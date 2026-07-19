import type { D1AuthUserRepository } from "../repositories/auth-users.ts";
import type { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import {
    D1IdentityBindingRepository,
    IdentityBindingMutationRejectedError,
    type FirstBindSubscriptionMutation
} from "../repositories/identity-bindings.ts";
import type { AuthIdentityRecord, AuthUserProfileResponse, AuthUserRecord } from "../types/auth.ts";
import type { VerificationEmailState } from "./email-task-producer.ts";
import { verificationStateKey } from "./email-task-producer.ts";
import type { PasswordHasher } from "./password.ts";
import { UserProfileService } from "./user-profile.ts";
import { sha256Hex } from "../utils/crypto.ts";

const PROVIDERS = ["linuxdo", "oidc", "wechat", "dingtalk"] as const;
type BindableProvider = typeof PROVIDERS[number];

const RESERVED_EMAIL_SUFFIXES = [
    "@linuxdo-connect.invalid",
    "@oidc-connect.invalid",
    "@wechat-connect.invalid",
    "@dingtalk-connect.invalid"
] as const;

export class IdentityBindingError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "IdentityBindingError";
        this.code = code;
        this.status = status;
    }
}

export class D1IdentityBindingService {
    readonly #users: D1AuthUserRepository;
    readonly #repository: D1IdentityBindingRepository;
    readonly #state: D1ExpiringStateRepository;
    readonly #passwords: PasswordHasher;
    readonly #clock: () => number;

    constructor(
        users: D1AuthUserRepository,
        repository: D1IdentityBindingRepository,
        state: D1ExpiringStateRepository,
        passwords: PasswordHasher,
        clock: () => number = Date.now
    ) {
        this.#users = users;
        this.#repository = repository;
        this.#state = state;
        this.#passwords = passwords;
        this.#clock = clock;
    }

    prepareBindingStart(providerValue: string, redirectValue = ""): {
        provider: BindableProvider;
        authorize_url: string;
        method: "GET";
        use_browser_redirect: true;
    } {
        const provider = normalizeProvider(providerValue);
        const redirect = normalizeRedirect(redirectValue);
        const query = new URLSearchParams({ redirect, intent: "bind_current_user" });
        return {
            provider,
            authorize_url: `/api/v1/auth/oauth/${provider}/bind/start?${query.toString()}`,
            method: "GET",
            use_browser_redirect: true
        };
    }

    async prepareEmailCode(
        currentUser: AuthUserRecord,
        emailValue: string,
        settings: Record<string, string>
    ): Promise<string> {
        const email = normalizeEmail(emailValue);
        assertEmailPolicy(email, settings.registration_email_suffix_whitelist);
        const owner = await this.#users.findByEmail(email);
        if (owner !== null && owner.id !== currentUser.id) {
            throw new IdentityBindingError("email_exists", 409, "Email is already in use");
        }
        return email;
    }

    async bindEmail(
        currentUser: AuthUserRecord,
        emailValue: string,
        verifyCodeValue: string,
        password: string,
        settings: Record<string, string>,
        runMode: "standard" | "simple" = "standard"
    ): Promise<AuthUserProfileResponse> {
        const email = normalizeEmail(emailValue);
        assertEmailPolicy(email, settings.registration_email_suffix_whitelist);
        const owner = await this.#users.findByEmail(email);
        if (owner !== null && owner.id !== currentUser.id) {
            throw new IdentityBindingError("email_exists", 409, "Email is already in use");
        }

        const verification = await this.#verifyCode(email, verifyCodeValue);
        const firstBind = isReservedEmail(currentUser.email);
        if (firstBind && password.length < 6) {
            throw new IdentityBindingError("password_too_short", 400, "password must be at least 6 characters");
        }
        if (!firstBind && !(await this.#passwords.verify(password, currentUser.passwordHash))) {
            throw new IdentityBindingError("password_incorrect", 400, "Password is incorrect");
        }

        const passwordHash = await this.#passwords.hash(password);
        const now = this.#clock();
        const updatedAt = nextIsoTimestamp(now, currentUser.updatedAt);
        try {
            await this.#repository.bindEmail({
                userId: currentUser.id,
                expectedUpdatedAt: currentUser.updatedAt,
                email,
                passwordHash,
                verificationKey: verification.key,
                verificationJson: verification.valueJson,
                now,
                updatedAt,
                ...(firstBind && settings.auth_source_default_email_grant_on_first_bind === "true"
                    ? { firstBindGrant: resolveFirstBindGrant(settings, updatedAt) }
                    : {})
            });
        } catch (error) {
            if (!(error instanceof IdentityBindingMutationRejectedError)) {
                throw error;
            }
            const conflicting = await this.#users.findByEmail(email);
            if (conflicting !== null && conflicting.id !== currentUser.id) {
                throw new IdentityBindingError("email_exists", 409, "Email is already in use");
            }
            throw new IdentityBindingError(
                "identity_binding_conflict",
                409,
                "Account identity changed concurrently; please retry"
            );
        }
        return this.#profile(currentUser.id, settings, runMode);
    }

    async unbindProvider(
        currentUser: AuthUserRecord,
        providerValue: string,
        settings: Record<string, string>,
        runMode: "standard" | "simple" = "standard"
    ): Promise<AuthUserProfileResponse> {
        const provider = normalizeProvider(providerValue);
        const identities = await this.#users.listIdentities(currentUser.id);
        if (!identities.some((identity) => identity.providerType.trim().toLowerCase() === provider)) {
            return new UserProfileService(this.#users).getProfile(currentUser, settings, runMode);
        }
        if (!canUnbindProvider(provider, currentUser, identities)) {
            throw new IdentityBindingError(
                "identity_unbind_last_method",
                409,
                "Bind another sign-in method before unbinding"
            );
        }
        const now = this.#clock();
        try {
            await this.#repository.unbindProvider(
                currentUser.id,
                provider,
                currentUser.updatedAt,
                nextIsoTimestamp(now, currentUser.updatedAt),
                now
            );
        } catch (error) {
            if (error instanceof IdentityBindingMutationRejectedError) {
                throw new IdentityBindingError(
                    "identity_binding_conflict",
                    409,
                    "Account identity changed concurrently; please retry"
                );
            }
            throw error;
        }
        return this.#profile(currentUser.id, settings, runMode);
    }

    async #verifyCode(email: string, verifyCodeValue: string): Promise<{
        key: string;
        valueJson: string;
    }> {
        const verifyCode = verifyCodeValue.trim();
        if (!/^\d{6}$/u.test(verifyCode)) {
            throw new IdentityBindingError("email_verify_required", 400, "Email verification code is required");
        }
        const key = await verificationStateKey(email);
        const stored = await this.#state.get<VerificationEmailState>(key);
        if (stored === null || stored.value.attempts >= 5) {
            throw verificationFailure(stored?.value.attempts === 5);
        }
        const submittedHash = await sha256Hex(verifyCode);
        if (!constantTimeHexEqual(stored.value.codeHash, submittedHash)) {
            const attempts = stored.value.attempts + 1;
            await this.#state.compareAndSwap(key, stored.value, { ...stored.value, attempts });
            throw verificationFailure(attempts >= 5);
        }
        return { key, valueJson: JSON.stringify(stored.value) };
    }

    async #profile(
        userId: number,
        settings: Record<string, string>,
        runMode: "standard" | "simple"
    ): Promise<AuthUserProfileResponse> {
        const user = await this.#users.findById(userId);
        if (user === null) {
            throw new IdentityBindingError("user_not_found", 404, "User not found");
        }
        return new UserProfileService(this.#users).getProfile(user, settings, runMode);
    }
}

function normalizeProvider(value: string): BindableProvider {
    const provider = value.trim().toLowerCase();
    if (!PROVIDERS.includes(provider as BindableProvider)) {
        throw new IdentityBindingError("identity_provider_invalid", 400, "Invalid identity provider");
    }
    return provider as BindableProvider;
}

function normalizeRedirect(value: string): string {
    const redirect = value.trim() || "/settings/profile";
    if (redirect.length > 2048 || !redirect.startsWith("/") || redirect.startsWith("//")) {
        throw new IdentityBindingError("identity_redirect_invalid", 400, "Invalid identity redirect");
    }
    return redirect;
}

function normalizeEmail(value: string): string {
    const email = value.trim().toLowerCase();
    if (email.length === 0 || email.length > 254 || !/^[^\s@]+@[^\s@]+$/u.test(email)) {
        throw new IdentityBindingError("invalid_email", 400, "invalid email");
    }
    return email;
}

function assertEmailPolicy(email: string, whitelistValue: string | undefined): void {
    if (isReservedEmail(email)) {
        throw new IdentityBindingError("email_reserved", 400, "This email address is reserved");
    }
    if (whitelistValue === undefined || whitelistValue.trim() === "") return;
    let parsed: unknown;
    try { parsed = JSON.parse(whitelistValue); } catch { return; }
    if (!Array.isArray(parsed) || parsed.length === 0) return;
    const domain = email.slice(email.lastIndexOf("@") + 1);
    if (!parsed.some((item) => typeof item === "string" && item.trim().toLowerCase() === domain)) {
        throw new IdentityBindingError(
            "registration_email_not_allowed",
            403,
            "Email domain is not allowed for registration"
        );
    }
}

function isReservedEmail(value: string): boolean {
    const email = value.trim().toLowerCase();
    return email === "" || RESERVED_EMAIL_SUFFIXES.some((suffix) => email.endsWith(suffix));
}

function verificationFailure(maxAttempts: boolean): IdentityBindingError {
    return new IdentityBindingError(
        maxAttempts ? "verify_code_max_attempts" : "invalid_verify_code",
        maxAttempts ? 429 : 400,
        maxAttempts
            ? "too many failed attempts, please request a new code"
            : "invalid or expired verification code"
    );
}

function constantTimeHexEqual(left: string, right: string): boolean {
    if (left.length !== right.length || !/^[a-f0-9]+$/iu.test(left + right)) return false;
    let difference = 0;
    for (let index = 0; index < left.length; index += 1) {
        difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
    }
    return difference === 0;
}

function canUnbindProvider(
    provider: BindableProvider,
    user: AuthUserRecord,
    identities: AuthIdentityRecord[]
): boolean {
    if (canUseEmail(user, identities)) return true;
    return PROVIDERS.some((candidate) => candidate !== provider && identities.some(
        (identity) => identity.providerType.trim().toLowerCase() === candidate
    ));
}

function canUseEmail(user: AuthUserRecord, identities: AuthIdentityRecord[]): boolean {
    if (isReservedEmail(user.email)) return false;
    const source = user.signupSource.trim().toLowerCase();
    if (source === "" || source === "email") return true;
    return identities.some((identity) => {
        if (identity.providerType.trim().toLowerCase() !== "email") return false;
        const identitySource = identity.metadata.source;
        return typeof identitySource === "string" && [
            "auth_service_email_bind",
            "auth_service_login_backfill",
            "auth_service_dual_write"
        ].includes(identitySource.trim());
    });
}

function resolveFirstBindGrant(settings: Record<string, string>, startsAt: string): {
    balance: number;
    concurrency: number;
    subscriptions: FirstBindSubscriptionMutation[];
} {
    return {
        balance: nonNegativeNumber(settings.auth_source_default_email_balance),
        concurrency: nonNegativeInteger(settings.auth_source_default_email_concurrency),
        subscriptions: parseSubscriptions(settings.auth_source_default_email_subscriptions, startsAt)
    };
}

function parseSubscriptions(raw: string | undefined, startsAt: string): FirstBindSubscriptionMutation[] {
    if (raw === undefined || raw.trim() === "") return [];
    let parsed: unknown;
    try { parsed = JSON.parse(raw); } catch { return []; }
    if (!Array.isArray(parsed)) return [];
    const output: FirstBindSubscriptionMutation[] = [];
    const seen = new Set<number>();
    for (const value of parsed) {
        if (value === null || typeof value !== "object" || Array.isArray(value)) continue;
        const item = value as Record<string, unknown>;
        const groupId = Number(item.group_id);
        const validityDays = Number(item.validity_days);
        if (
            !Number.isSafeInteger(groupId) || groupId <= 0 || seen.has(groupId)
            || !Number.isSafeInteger(validityDays) || validityDays <= 0 || validityDays > 3650
        ) continue;
        seen.add(groupId);
        output.push({
            groupId,
            validityDays,
            startsAt,
            expiresAt: new Date(Date.parse(startsAt) + validityDays * 86_400_000).toISOString(),
            windowStart: startOfUtcDay(startsAt)
        });
    }
    return output;
}

function nonNegativeNumber(raw: string | undefined): number {
    const value = Number(raw ?? 0);
    return Number.isFinite(value) && value >= 0 ? value : 0;
}

function nonNegativeInteger(raw: string | undefined): number {
    const value = Number(raw ?? 0);
    return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function nextIsoTimestamp(now: number, previous: string): string {
    const previousTime = Date.parse(previous);
    const next = Number.isFinite(previousTime) ? Math.max(now, previousTime + 1) : now;
    return new Date(next).toISOString();
}

function startOfUtcDay(value: string): string {
    const date = new Date(value);
    return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate())).toISOString();
}
