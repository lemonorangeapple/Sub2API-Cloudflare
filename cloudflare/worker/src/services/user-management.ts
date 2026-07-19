import type { D1AuthUserRepository } from "../repositories/auth-users.ts";
import {
    D1UserManagementRepository,
    type DefaultSubscriptionMutation,
    type PlatformQuotaMutation,
    UserMutationRejectedError
} from "../repositories/user-management.ts";
import type { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import type { AuthUserRecord, AuthUserResponse, PasswordLoginResponse } from "../types/auth.ts";
import { randomHex, sha256Hex } from "../utils/crypto.ts";
import type { AuthTokenService } from "./auth-tokens.ts";
import { mapAuthUser } from "./auth-user.ts";
import type { VerificationEmailState } from "./email-task-producer.ts";
import { verificationStateKey } from "./email-task-producer.ts";
import type { PasswordHasher } from "./password.ts";

const RESERVED_EMAIL_SUFFIXES = [
    "@linuxdo-connect.invalid",
    "@oidc-connect.invalid",
    "@wechat-connect.invalid",
    "@dingtalk-connect.invalid"
] as const;

const QUOTA_PLATFORMS = ["anthropic", "openai", "gemini", "antigravity", "grok"] as const;
const AFFILIATE_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export type UserManagementErrorCode =
    | "invalid_request"
    | "admin_required"
    | "user_not_found"
    | "email_exists"
    | "registration_disabled"
    | "registration_email_not_allowed"
    | "email_reserved"
    | "email_verify_required"
    | "invalid_verify_code"
    | "verify_code_max_attempts"
    | "invitation_code_required"
    | "invitation_code_invalid"
    | "backend_mode_admin_only"
    | "cannot_disable_admin"
    | "cannot_demote_self"
    | "cannot_demote_last_admin"
    | "user_state_changed"
    | "oauth_finalization_conflict"
    | "setup_not_allowed";

export class UserManagementError extends Error {
    readonly code: UserManagementErrorCode;
    readonly status: number;

    constructor(code: UserManagementErrorCode, status: number, message: string) {
        super(message);
        this.name = "UserManagementError";
        this.code = code;
        this.status = status;
    }
}

export interface AdminCreateUserInput {
    email: string;
    password: string;
    username?: string;
    notes?: string;
    role?: "admin" | "user";
    balance?: number;
    concurrency?: number;
    rpmLimit?: number;
    allowedGroups?: number[] | null;
}

export interface AdminUpdateUserInput {
    email?: string;
    password?: string;
    username?: string;
    notes?: string;
    role?: "admin" | "user";
    balance?: number;
    concurrency?: number;
    rpmLimit?: number;
    status?: "active" | "disabled";
    allowedGroups?: number[] | null;
    groupRates?: Record<string, number | null>;
}

export interface RegistrationInput {
    email: string;
    password: string;
    verifyCode?: string;
    promoCode?: string;
    invitationCode?: string;
    affiliateCode?: string;
}

export interface OAuthRegistrationInput {
    email: string;
    password?: string;
    verifyCode?: string;
    invitationCode?: string;
    affiliateCode?: string;
    promoCode?: string;
    requireEmailVerification: boolean;
    allowReservedEmail: boolean;
    allowRegistrationBypass?: boolean;
    initialUsername?: string;
    pendingSessionId: number;
    browserSessionKey: string;
    finalizationNonce: string;
    providerType: string;
    providerKey: string;
    providerSubject: string;
    issuer: string | null;
    metadata: Record<string, unknown>;
    adoptDisplayName: boolean;
    adoptAvatar: boolean;
    displayName: string;
    avatarUrl: string;
}

export interface ManagedAdminUserResponse extends AuthUserResponse {
    notes: string;
    group_rates: Record<string, number>;
}

export class D1UserManagementService {
    readonly #users: D1AuthUserRepository;
    readonly #repository: D1UserManagementRepository;
    readonly #passwords: PasswordHasher;
    readonly #state: D1ExpiringStateRepository;
    readonly #tokens: AuthTokenService;
    readonly #clock: () => number;

    constructor(
        users: D1AuthUserRepository,
        repository: D1UserManagementRepository,
        passwords: PasswordHasher,
        state: D1ExpiringStateRepository,
        tokens: AuthTokenService,
        clock: () => number = Date.now
    ) {
        this.#users = users;
        this.#repository = repository;
        this.#passwords = passwords;
        this.#state = state;
        this.#tokens = tokens;
        this.#clock = clock;
    }

    async createByAdmin(
        actor: AuthUserRecord,
        input: AdminCreateUserInput,
        settings: Record<string, string>
    ): Promise<ManagedAdminUserResponse> {
        requireAdmin(actor);
        const email = normalizeEmail(input.email);
        await this.#assertEmailAvailable(email);
        const password = validatePassword(input.password, 6);
        const role = normalizeRole(input.role ?? "user");
        const balance = input.balance === undefined
            ? nonNegativeNumberSetting(settings.default_balance, 0)
            : nonNegativeFinite(input.balance, "balance");
        const concurrency = nonNegativeInteger(input.concurrency ?? 0, "concurrency");
        const rpmLimit = nonNegativeInteger(input.rpmLimit ?? 0, "rpm_limit");
        const allowedGroups = normalizeIdList(input.allowedGroups ?? []);
        const createdAt = new Date(this.#clock()).toISOString();
        const passwordHash = await this.#passwords.hash(password);
        const userId = await this.#createUser({
            email,
            passwordHash,
            role,
            username: boundedText(input.username ?? "", "username", 256),
            notes: boundedText(input.notes ?? "", "notes", 4096),
            balance,
            concurrency,
            rpmLimit,
            status: "active",
            signupSource: "email",
            allowedGroups,
            groupRates: new Map(),
            defaultSubscriptions: parseDefaultSubscriptions(settings.default_subscriptions, createdAt),
            createdAt
        });
        return this.#requireAdminResponse(userId);
    }

    async updateByAdmin(
        actor: AuthUserRecord,
        targetUserId: number,
        input: AdminUpdateUserInput
    ): Promise<ManagedAdminUserResponse> {
        requireAdmin(actor);
        requirePositiveId(targetUserId);
        const target = await this.#users.findById(targetUserId);
        if (target === null) {
            throw new UserManagementError("user_not_found", 404, "User not found");
        }

        const email = input.email === undefined ? null : normalizeEmail(input.email);
        if (email !== null && email !== normalizeEmail(target.email)) {
            await this.#assertEmailAvailable(email, target.id);
        }
        const role = input.role === undefined ? null : normalizeRole(input.role);
        const status = input.status === undefined ? null : normalizeStatus(input.status);
        if (target.role === "admin" && status === "disabled") {
            throw new UserManagementError("cannot_disable_admin", 400, "cannot disable admin user");
        }
        if (target.id === actor.id && target.role === "admin" && role === "user") {
            throw new UserManagementError("cannot_demote_self", 400, "cannot demote yourself from admin");
        }
        if (target.role === "admin" && role === "user" && await this.#users.countActiveAdmins() <= 1) {
            throw new UserManagementError(
                "cannot_demote_last_admin",
                400,
                "cannot demote the last admin user"
            );
        }

        const passwordHash = input.password === undefined
            ? null
            : await this.#passwords.hash(validatePassword(input.password, 6));
        const username = input.username === undefined
            ? null
            : boundedText(input.username, "username", 256);
        const notes = input.notes === undefined
            ? null
            : boundedText(input.notes, "notes", 4096);
        const balance = input.balance === undefined
            ? null
            : nonNegativeFinite(input.balance, "balance");
        const concurrency = input.concurrency === undefined
            ? null
            : nonNegativeInteger(input.concurrency, "concurrency");
        const rpmLimit = input.rpmLimit === undefined
            ? null
            : nonNegativeInteger(input.rpmLimit, "rpm_limit");
        const replaceAllowedGroups = input.allowedGroups !== undefined;
        const allowedGroups = replaceAllowedGroups ? normalizeIdList(input.allowedGroups ?? []) : [];
        const groupRates = input.groupRates === undefined ? null : normalizeGroupRates(input.groupRates);
        const securityChanged =
            (email !== null && email !== normalizeEmail(target.email))
            || passwordHash !== null
            || (role !== null && role !== target.role)
            || (status !== null && status !== target.status);
        const now = this.#clock();
        const updatedAt = new Date(now).toISOString();
        const concurrencyDelta = concurrency === null ? 0 : concurrency - target.concurrency;
        let updated: boolean;
        try {
            updated = await this.#repository.updateUser({
            targetUserId: target.id,
            expectedUpdatedAt: target.updatedAt,
            email,
            passwordHash,
            username,
            notes,
            role,
            balance,
            concurrency,
            rpmLimit,
            status,
            replaceAllowedGroups,
            allowedGroups,
            groupRates,
            securityChanged,
            blockDisableAdmin: target.role === "admin" && status === "disabled",
            blockSelfDemotion: target.id === actor.id && target.role === "admin" && role === "user",
            requireOtherAdmin: target.role === "admin" && role === "user",
            updatedAt,
            revokedAt: now,
                ...(concurrencyDelta === 0 ? {} : {
                    concurrencyAdjustment: {
                        code: `adj_${randomHex(16)}`,
                        delta: concurrencyDelta,
                        actorAdminId: actor.id
                    }
                })
            });
        } catch (error) {
            const mapped = mapCreateError(error);
            if (mapped instanceof UserManagementError) {
                throw mapped;
            }
            throw error;
        }
        if (!updated) {
            throw new UserManagementError(
                "user_state_changed",
                409,
                "User state changed or a database safety guard rejected the update"
            );
        }
        return this.#requireAdminResponse(target.id);
    }

    async register(
        input: RegistrationInput,
        settings: Record<string, string>
    ): Promise<PasswordLoginResponse> {
        if (settings.registration_enabled !== "true") {
            throw new UserManagementError("registration_disabled", 403, "registration is disabled");
        }
        if (settings.backend_mode_enabled === "true") {
            throw new UserManagementError(
                "backend_mode_admin_only",
                403,
                "Backend mode is active. Only admin login is allowed."
            );
        }
        const email = normalizeEmail(input.email);
        if (RESERVED_EMAIL_SUFFIXES.some((suffix) => email.endsWith(suffix))) {
            throw new UserManagementError("email_reserved", 400, "This email address is reserved");
        }
        validateEmailWhitelist(email, settings.registration_email_suffix_whitelist);
        await this.#assertEmailAvailable(email);
        const passwordHash = await this.#passwords.hash(validatePassword(input.password, 6));

        const now = this.#clock();
        const createdAt = new Date(now).toISOString();
        const signupPlan = resolveSignupPlan(settings, "email", createdAt);
        const verificationState = settings.email_verify_enabled === "true"
            ? await this.#verifiedEmailState(email, input.verifyCode, now)
            : undefined;

        const invitationRequired = settings.invitation_code_enabled === "true";
        const invitationCode = (input.invitationCode ?? "").trim();
        if (invitationRequired && invitationCode === "") {
            throw new UserManagementError(
                "invitation_code_required",
                400,
                "Invitation code is required"
            );
        }

        const promotionCode = settings.promo_code_enabled === "true"
            ? (input.promoCode ?? "").trim()
            : "";
        const inviterCode = (input.affiliateCode ?? "").trim().toUpperCase();
        let userId = 0;
        for (let attempt = 0; attempt < 5; attempt += 1) {
            try {
                userId = await this.#repository.createUser({
                    email,
                    passwordHash,
                    role: "user",
                    username: "",
                    notes: "",
                    balance: signupPlan.balance,
                    concurrency: signupPlan.concurrency,
                    rpmLimit: nonNegativeIntegerSetting(settings.default_user_rpm_limit, 0),
                    status: "active",
                    signupSource: "email",
                    allowedGroups: [],
                    groupRates: new Map(),
                    defaultSubscriptions: signupPlan.subscriptions,
                    createdAt,
                    touchLoginAt: createdAt,
                    platformQuotas: signupPlan.platformQuotas,
                    affiliate: {
                        profileCode: randomAffiliateCode(),
                        ...(inviterCode === "" ? {} : { inviterCode })
                    },
                    ...(promotionCode === "" ? {} : {
                        promotion: { code: promotionCode, nowIso: createdAt }
                    }),
                    ...(verificationState === undefined ? {} : { verificationState }),
                    ...(invitationCode === "" ? {} : {
                        invitation: { code: invitationCode, nowIso: createdAt }
                    })
                });
                break;
            } catch (error) {
                if (isAffiliateCodeConflict(error) && attempt < 4) {
                    continue;
                }
                if (error instanceof UserMutationRejectedError && invitationCode !== "") {
                    throw new UserManagementError(
                        "invitation_code_invalid",
                        400,
                        "Invitation code is invalid or already used"
                    );
                }
                throw mapCreateError(error);
            }
        }
        if (userId <= 0) {
            throw new Error("affiliate code allocation exhausted");
        }

        const user = await this.#users.findById(userId);
        if (user === null) {
            throw new UserManagementError("user_not_found", 500, "Created user could not be loaded");
        }
        const tokenPair = await this.#tokens.issue(user);
        return {
            access_token: tokenPair.accessToken,
            refresh_token: tokenPair.refreshToken,
            expires_in: tokenPair.expiresIn,
            token_type: "Bearer",
            user: mapAuthUser(user)
        };
    }

    async registerOAuth(
        input: OAuthRegistrationInput,
        settings: Record<string, string>
    ): Promise<PasswordLoginResponse> {
        if (settings.registration_enabled !== "true" && input.allowRegistrationBypass !== true) {
            throw new UserManagementError("registration_disabled", 403, "registration is disabled");
        }
        if (settings.backend_mode_enabled === "true") {
            throw new UserManagementError(
                "backend_mode_admin_only",
                403,
                "Backend mode is active. Only admin login is allowed."
            );
        }
        const email = normalizeEmail(input.email);
        if (!input.allowReservedEmail && RESERVED_EMAIL_SUFFIXES.some((suffix) => email.endsWith(suffix))) {
            throw new UserManagementError("email_reserved", 400, "This email address is reserved");
        }
        if (!input.allowReservedEmail) {
            validateEmailWhitelist(email, settings.registration_email_suffix_whitelist);
        }
        await this.#assertEmailAvailable(email);

        const provider = normalizeSignupSource(input.providerType);
        const now = this.#clock();
        const createdAt = new Date(now).toISOString();
        const signupPlan = resolveSignupPlan(settings, provider, createdAt);
        const password = input.password === undefined
            ? randomHex(32)
            : validatePassword(input.password, 6);
        const passwordHash = await this.#passwords.hash(password);
        const verificationState = input.requireEmailVerification
            ? await this.#verifiedEmailState(email, input.verifyCode, now)
            : undefined;
        const invitationCode = (input.invitationCode ?? "").trim();
        if (settings.invitation_code_enabled === "true" && invitationCode === "") {
            throw new UserManagementError(
                "invitation_code_required",
                400,
                "Invitation code is required"
            );
        }
        const inviterCode = (input.affiliateCode ?? "").trim().toUpperCase();
        const promotionCode = settings.promo_code_enabled === "true"
            ? (input.promoCode ?? "").trim()
            : "";
        const username = input.adoptDisplayName && input.displayName !== ""
            ? input.displayName
            : input.initialUsername ?? "";

        let userId = 0;
        for (let attempt = 0; attempt < 5; attempt += 1) {
            try {
                userId = await this.#repository.createUser({
                    email,
                    passwordHash,
                    role: "user",
                    username: boundedText(username, "username", 256),
                    notes: "",
                    balance: signupPlan.balance,
                    concurrency: signupPlan.concurrency,
                    rpmLimit: nonNegativeIntegerSetting(settings.default_user_rpm_limit, 0),
                    status: "active",
                    signupSource: provider,
                    allowedGroups: [],
                    groupRates: new Map(),
                    defaultSubscriptions: signupPlan.subscriptions,
                    createdAt,
                    touchLoginAt: createdAt,
                    platformQuotas: signupPlan.platformQuotas,
                    affiliate: {
                        profileCode: randomAffiliateCode(),
                        ...(inviterCode === "" ? {} : { inviterCode })
                    },
                    ...(promotionCode === "" ? {} : {
                        promotion: { code: promotionCode, nowIso: createdAt }
                    }),
                    ...(verificationState === undefined ? {} : { verificationState }),
                    ...(invitationCode === "" ? {} : {
                        invitation: { code: invitationCode, nowIso: createdAt }
                    }),
                    oauthFinalization: {
                        pendingSessionId: input.pendingSessionId,
                        browserSessionKey: input.browserSessionKey,
                        finalizationNonce: input.finalizationNonce,
                        identity: {
                            providerType: provider,
                            providerKey: input.providerKey,
                            providerSubject: input.providerSubject,
                            issuer: input.issuer,
                            metadata: input.metadata
                        },
                        adoption: {
                            adoptDisplayName: input.adoptDisplayName,
                            adoptAvatar: input.adoptAvatar,
                            displayName: input.displayName,
                            avatarUrl: input.avatarUrl
                        },
                        grantOnSignup: signupPlan.sourceGrantEnabled
                    }
                });
                break;
            } catch (error) {
                if (isAffiliateCodeConflict(error) && attempt < 4) continue;
                if (error instanceof UserMutationRejectedError) {
                    if (await this.#users.findByEmail(email) !== null) {
                        throw new UserManagementError("email_exists", 409, "Email is already in use");
                    }
                    if (invitationCode !== "") {
                        throw new UserManagementError(
                            "invitation_code_invalid",
                            400,
                            "Invitation code is invalid or already used"
                        );
                    }
                    throw new UserManagementError(
                        "oauth_finalization_conflict",
                        409,
                        "Pending oauth session changed or identity is already owned"
                    );
                }
                throw mapCreateError(error);
            }
        }
        if (userId <= 0) throw new Error("affiliate code allocation exhausted");
        const user = await this.#users.findById(userId);
        if (user === null) {
            throw new UserManagementError("user_not_found", 500, "Created user could not be loaded");
        }
        const tokenPair = await this.#tokens.issue(user);
        return {
            access_token: tokenPair.accessToken,
            refresh_token: tokenPair.refreshToken,
            expires_in: tokenPair.expiresIn,
            token_type: "Bearer",
            user: mapAuthUser(user)
        };
    }

    async createInitialAdmin(emailValue: string, passwordValue: string): Promise<ManagedAdminUserResponse> {
        const email = normalizeEmail(emailValue);
        const passwordHash = await this.#passwords.hash(validatePassword(passwordValue, 8));
        const createdAt = new Date(this.#clock()).toISOString();
        let userId: number;
        try {
            userId = await this.#repository.createUser({
                email,
                passwordHash,
                role: "admin",
                username: "",
                notes: "",
                balance: 0,
                concurrency: 5,
                rpmLimit: 0,
                status: "active",
                signupSource: "email",
                allowedGroups: [],
                groupRates: new Map(),
                defaultSubscriptions: [],
                createdAt,
                requireEmptyDatabase: true
            });
        } catch (error) {
            if (error instanceof UserMutationRejectedError) {
                throw new UserManagementError(
                    "setup_not_allowed",
                    403,
                    "Setup is not allowed: system is already installed or contains users"
                );
            }
            throw mapCreateError(error);
        }
        return this.#requireAdminResponse(userId);
    }

    async #createUser(input: Parameters<D1UserManagementRepository["createUser"]>[0]): Promise<number> {
        try {
            return await this.#repository.createUser(input);
        } catch (error) {
            throw mapCreateError(error);
        }
    }

    async #assertEmailAvailable(email: string, currentUserId?: number): Promise<void> {
        const owner = await this.#users.findByEmail(email);
        if (owner !== null && owner.id !== currentUserId) {
            throw new UserManagementError("email_exists", 409, "Email is already in use");
        }
    }

    async #verifiedEmailState(
        email: string,
        verifyCodeValue: string | undefined,
        now: number
    ): Promise<{ key: string; expectedJson: string; now: number }> {
        const verifyCode = (verifyCodeValue ?? "").trim();
        if (!/^\d{6}$/u.test(verifyCode)) {
            throw new UserManagementError(
                "email_verify_required",
                400,
                "Email verification code is required"
            );
        }
        const key = await verificationStateKey(email);
        const stored = await this.#state.get<VerificationEmailState>(key);
        if (stored === null || stored.value.attempts >= 5) {
            throw new UserManagementError(
                stored?.value.attempts === 5 ? "verify_code_max_attempts" : "invalid_verify_code",
                stored?.value.attempts === 5 ? 429 : 400,
                stored?.value.attempts === 5
                    ? "too many failed attempts, please request a new code"
                    : "invalid or expired verification code"
            );
        }
        const submittedHash = await sha256Hex(verifyCode);
        if (!constantTimeHexEqual(stored.value.codeHash, submittedHash)) {
            const attempts = stored.value.attempts + 1;
            await this.#state.compareAndSwap(key, stored.value, { ...stored.value, attempts });
            throw new UserManagementError(
                attempts >= 5 ? "verify_code_max_attempts" : "invalid_verify_code",
                attempts >= 5 ? 429 : 400,
                attempts >= 5
                    ? "too many failed attempts, please request a new code"
                    : "invalid or expired verification code"
            );
        }
        return { key, expectedJson: JSON.stringify(stored.value), now };
    }

    async #requireAdminResponse(userId: number): Promise<ManagedAdminUserResponse> {
        const user = await this.#users.findById(userId);
        if (user === null) {
            throw new UserManagementError("user_not_found", 404, "User not found");
        }
        return {
            ...mapAuthUser(user),
            notes: user.notes,
            group_rates: user.groupRates
        };
    }
}

function parseDefaultSubscriptions(raw: string | undefined, startsAt: string): DefaultSubscriptionMutation[] {
    if (raw === undefined || raw.trim() === "") {
        return [];
    }
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw);
    } catch {
        return [];
    }
    if (!Array.isArray(parsed)) {
        return [];
    }
    const output: DefaultSubscriptionMutation[] = [];
    const seen = new Set<number>();
    for (const item of parsed) {
        if (item === null || typeof item !== "object" || Array.isArray(item)) {
            continue;
        }
        const record = item as Record<string, unknown>;
        const groupId = Number(record.group_id);
        const validityDays = Number(record.validity_days);
        if (
            !Number.isSafeInteger(groupId)
            || groupId <= 0
            || !Number.isSafeInteger(validityDays)
            || validityDays <= 0
            || validityDays > 3650
            || seen.has(groupId)
        ) {
            continue;
        }
        seen.add(groupId);
        output.push({
            groupId,
            startsAt,
            expiresAt: new Date(Date.parse(startsAt) + validityDays * 86_400_000).toISOString(),
            notes: "auto assigned by default user subscriptions setting"
        });
    }
    return output;
}

interface SignupPlan {
    balance: number;
    concurrency: number;
    subscriptions: DefaultSubscriptionMutation[];
    platformQuotas: PlatformQuotaMutation[];
    sourceGrantEnabled: boolean;
}

interface QuotaPatch {
    dailyLimitUsd?: number;
    weeklyLimitUsd?: number;
    monthlyLimitUsd?: number;
}

function resolveSignupPlan(
    settings: Record<string, string>,
    source: string,
    startsAt: string
): SignupPlan {
    let balance = nonNegativeNumberSetting(settings.default_balance, 0);
    let concurrency = nonNegativeIntegerSetting(settings.default_concurrency, 5);
    let subscriptions = parseDefaultSubscriptions(settings.default_subscriptions, startsAt);
    const prefix = `auth_source_default_${source}`;
    const sourceGrantEnabled = settings[`${prefix}_grant_on_signup`] === "true";
    if (sourceGrantEnabled) {
        balance = nonNegativeNumberSetting(settings[`${prefix}_balance`], 0);
        const sourceConcurrency = nonNegativeIntegerSetting(
            settings[`${prefix}_concurrency`],
            5
        );
        if (sourceConcurrency > 0) {
            concurrency = sourceConcurrency;
        }
        const sourceSubscriptions = parseDefaultSubscriptions(
            settings[`${prefix}_subscriptions`],
            startsAt
        );
        if (sourceSubscriptions.length > 0) {
            subscriptions = sourceSubscriptions;
        }
    }

    const globalQuotas = parseQuotaPatches(settings.default_platform_quotas);
    const sourceQuotas = sourceGrantEnabled
        ? parseQuotaPatches(settings[`${prefix}_platform_quotas`])
        : new Map<string, QuotaPatch>();
    const platformQuotas = QUOTA_PLATFORMS.map((platform) => {
        const global = globalQuotas.get(platform) ?? {};
        const source = sourceQuotas.get(platform) ?? {};
        return {
            platform,
            dailyLimitUsd: source.dailyLimitUsd ?? global.dailyLimitUsd ?? null,
            weeklyLimitUsd: source.weeklyLimitUsd ?? global.weeklyLimitUsd ?? null,
            monthlyLimitUsd: source.monthlyLimitUsd ?? global.monthlyLimitUsd ?? null
        };
    });
    return { balance, concurrency, subscriptions, platformQuotas, sourceGrantEnabled };
}

function normalizeSignupSource(value: string): string {
    const source = value.trim().toLowerCase();
    return ["email", "linuxdo", "wechat", "oidc", "github", "google", "dingtalk"].includes(source)
        ? source
        : "email";
}

function parseQuotaPatches(raw: string | undefined): Map<string, QuotaPatch> {
    const output = new Map<string, QuotaPatch>();
    if (raw === undefined || raw.trim() === "") {
        return output;
    }
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw);
    } catch {
        return output;
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        return output;
    }
    for (const platform of QUOTA_PLATFORMS) {
        const value = (parsed as Record<string, unknown>)[platform];
        if (value === null || typeof value !== "object" || Array.isArray(value)) {
            continue;
        }
        const record = value as Record<string, unknown>;
        const patch: QuotaPatch = {};
        const daily = quotaValue(record.daily);
        const weekly = quotaValue(record.weekly);
        const monthly = quotaValue(record.monthly);
        if (daily !== null) patch.dailyLimitUsd = daily;
        if (weekly !== null) patch.weeklyLimitUsd = weekly;
        if (monthly !== null) patch.monthlyLimitUsd = monthly;
        output.set(platform, patch);
    }
    return output;
}

function quotaValue(value: unknown): number | null {
    return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

function randomAffiliateCode(): string {
    const bytes = new Uint8Array(12);
    crypto.getRandomValues(bytes);
    let code = "";
    for (const value of bytes) {
        code += AFFILIATE_CODE_ALPHABET[value & 31];
    }
    return code;
}

function isAffiliateCodeConflict(error: unknown): boolean {
    const message = error instanceof Error ? error.message : String(error);
    return /user_affiliates(?:\.|.*)aff_code.*unique|unique.*user_affiliates(?:\.|.*)aff_code/iu.test(message);
}

function normalizeGroupRates(input: Record<string, number | null>): Map<number, number | null> {
    const output = new Map<number, number | null>();
    for (const [key, value] of Object.entries(input)) {
        const groupId = Number(key);
        if (!Number.isSafeInteger(groupId) || groupId <= 0) {
            throw new UserManagementError("invalid_request", 400, `Invalid group rate ID: ${key}`);
        }
        if (value !== null && (!Number.isFinite(value) || value <= 0)) {
            throw new UserManagementError(
                "invalid_request",
                400,
                `rate_multiplier must be greater than zero for group ${key}`
            );
        }
        output.set(groupId, value);
    }
    return output;
}

function validateEmailWhitelist(email: string, raw: string | undefined): void {
    if (raw === undefined || raw.trim() === "") {
        return;
    }
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw);
    } catch {
        return;
    }
    if (!Array.isArray(parsed) || parsed.length === 0) {
        return;
    }
    const domain = email.slice(email.lastIndexOf("@") + 1);
    const allowed = parsed.some((item) => typeof item === "string" && domain === item.trim().toLowerCase());
    if (!allowed) {
        throw new UserManagementError(
            "registration_email_not_allowed",
            403,
            "Email domain is not allowed for registration"
        );
    }
}

function normalizeEmail(value: string): string {
    const email = value.trim().toLowerCase();
    if (email.length === 0 || email.length > 254 || !/^[^\s@]+@[^\s@]+$/u.test(email)) {
        throw new UserManagementError("invalid_request", 400, "A valid email is required");
    }
    return email;
}

function validatePassword(value: string, minimumLength: number): string {
    const byteLength = new TextEncoder().encode(value).byteLength;
    if (value.length < minimumLength || byteLength > 72) {
        throw new UserManagementError(
            "invalid_request",
            400,
            `Password must be at least ${minimumLength} characters and at most 72 UTF-8 bytes`
        );
    }
    return value;
}

function normalizeRole(value: string): "admin" | "user" {
    if (value !== "admin" && value !== "user") {
        throw new UserManagementError("invalid_request", 400, "role must be admin or user");
    }
    return value;
}

function normalizeStatus(value: string): "active" | "disabled" {
    if (value !== "active" && value !== "disabled") {
        throw new UserManagementError("invalid_request", 400, "status must be active or disabled");
    }
    return value;
}

function normalizeIdList(values: readonly number[]): number[] {
    const output = [...new Set(values)];
    if (output.some((value) => !Number.isSafeInteger(value) || value <= 0)) {
        throw new UserManagementError("invalid_request", 400, "allowed_groups contains an invalid ID");
    }
    return output;
}

function nonNegativeFinite(value: number, field: string): number {
    if (!Number.isFinite(value) || value < 0) {
        throw new UserManagementError("invalid_request", 400, `${field} must be non-negative`);
    }
    return value;
}

function nonNegativeInteger(value: number, field: string): number {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new UserManagementError("invalid_request", 400, `${field} must be a non-negative integer`);
    }
    return value;
}

function nonNegativeNumberSetting(raw: string | undefined, fallback: number): number {
    if (raw === undefined || raw.trim() === "") {
        return fallback;
    }
    const value = Number(raw);
    return Number.isFinite(value) && value >= 0 ? value : fallback;
}

function nonNegativeIntegerSetting(raw: string | undefined, fallback: number): number {
    const value = nonNegativeNumberSetting(raw, fallback);
    return Number.isSafeInteger(value) ? value : fallback;
}

function boundedText(value: string, field: string, maxBytes: number): string {
    if (new TextEncoder().encode(value).byteLength > maxBytes) {
        throw new UserManagementError("invalid_request", 400, `${field} is too long`);
    }
    return value;
}

function requireAdmin(user: AuthUserRecord): void {
    if (user.role !== "admin" || user.status !== "active") {
        throw new UserManagementError("admin_required", 403, "Administrator access is required");
    }
}

function requirePositiveId(value: number): void {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new UserManagementError("invalid_request", 400, "Invalid user ID");
    }
}

function constantTimeHexEqual(left: string, right: string): boolean {
    if (left.length !== right.length) {
        return false;
    }
    let difference = 0;
    for (let index = 0; index < left.length; index += 1) {
        difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
    }
    return difference === 0;
}

function mapCreateError(error: unknown): UserManagementError | Error {
    if (error instanceof UserManagementError) {
        return error;
    }
    const message = error instanceof Error ? error.message : String(error);
    if (/unique|users_active_email_normalized_unique|email/i.test(message)) {
        return new UserManagementError("email_exists", 409, "Email is already in use");
    }
    if (error instanceof UserMutationRejectedError) {
        return error;
    }
    return error instanceof Error ? error : new Error(message);
}
