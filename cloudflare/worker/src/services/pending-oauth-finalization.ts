import type { D1AuthUserRepository } from "../repositories/auth-users.ts";
import type { D1DingTalkAttributeRepository } from "../repositories/dingtalk-attributes.ts";
import {
    D1OAuthFinalizationRepository,
    OAuthFinalizationRejectedError,
    type OAuthFirstBindGrantMutation
} from "../repositories/oauth-finalization.ts";
import type { PendingAuthSessionRecord } from "../repositories/pending-auth.ts";
import { randomHex } from "../utils/crypto.ts";
import type { AuthTokenPair, AuthUserRecord } from "../types/auth.ts";
import type { AuthTokenService } from "./auth-tokens.ts";
import type { PasswordVerifier } from "./password.ts";
import type { D1PendingAuthService } from "./pending-auth.ts";
import type { D1UserManagementService } from "./user-management.ts";
import type { PendingOAuthTotpContext, TotpLoginService } from "./totp.ts";

const DUMMY_BCRYPT_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";
const CHOICE_STEPS = new Set([
    "choose_account_action_required",
    "create_account_required",
    "email_completion",
    "bind_login_required"
]);

export interface OAuthAdoptionDecisionInput {
    adoptDisplayName?: boolean;
    adoptAvatar?: boolean;
}

export interface PendingOAuthFinalizationOptions {
    clock?: () => number;
    nonceFactory?: () => string;
    registrations?: D1UserManagementService;
    totpLogin?: TotpLoginService;
    dingtalkAttributes?: D1DingTalkAttributeRepository;
}

export interface PendingOAuthExchangeResult {
    payload: Record<string, unknown>;
    finalized: boolean;
}

export type PendingOAuthRegistrationMode =
    | "local_email"
    | "provider_identity"
    | "verified_provider_email"
    | "verified_provider_email_with_password";

export class PendingOAuthFinalizationError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "PendingOAuthFinalizationError";
        this.code = code;
        this.status = status;
    }
}

export class D1PendingOAuthFinalizationService {
    readonly #users: D1AuthUserRepository;
    readonly #pending: D1PendingAuthService;
    readonly #repository: D1OAuthFinalizationRepository;
    readonly #passwords: PasswordVerifier;
    readonly #tokens: AuthTokenService;
    readonly #clock: () => number;
    readonly #nonceFactory: () => string;
    readonly #registrations: D1UserManagementService | null;
    readonly #totpLogin: TotpLoginService | null;
    readonly #dingtalkAttributes: D1DingTalkAttributeRepository | null;

    constructor(
        users: D1AuthUserRepository,
        pending: D1PendingAuthService,
        repository: D1OAuthFinalizationRepository,
        passwords: PasswordVerifier,
        tokens: AuthTokenService,
        options: PendingOAuthFinalizationOptions = {}
    ) {
        this.#users = users;
        this.#pending = pending;
        this.#repository = repository;
        this.#passwords = passwords;
        this.#tokens = tokens;
        this.#clock = options.clock ?? Date.now;
        this.#nonceFactory = options.nonceFactory ?? (() => randomHex(16));
        this.#registrations = options.registrations ?? null;
        this.#totpLogin = options.totpLogin ?? null;
        this.#dingtalkAttributes = options.dingtalkAttributes ?? null;
    }

    async exchange(
        sessionToken: string,
        browserSessionKey: string,
        decision: OAuthAdoptionDecisionInput,
        settings: Record<string, string>
    ): Promise<PendingOAuthExchangeResult> {
        const session = await this.#pending.getBrowserSession(sessionToken, browserSessionKey);
        const payload = completionPayload(session);
        const target = session.targetUserId === null ? null : await this.#users.findById(session.targetUserId);
        const canIssueToken = canIssueTokenPair(session, payload);
        if (canIssueToken) {
            assertActiveUser(target);
            assertBackendMode(target, settings);
        }

        if (target !== null && await identityAlreadyBound(this.#users, target.id, session)) {
            delete payload.adoption_required;
        }
        if (requiresUserChoice(payload)) return { payload, finalized: false };
        if (payload.adoption_required === true && !hasDecision(decision)) {
            return { payload, finalized: false };
        }
        if (target === null) {
            throw new PendingOAuthFinalizationError(
                "pending_auth_target_user_missing",
                400,
                "pending auth target user is missing"
            );
        }

        await this.#complete(session, target, browserSessionKey, decision, settings, canIssueToken);
        if (canIssueToken) {
            Object.assign(payload, tokenPayload(await this.#tokens.issue(await requireUser(this.#users, target.id))));
        }
        return { payload, finalized: true };
    }

    async bindLogin(
        sessionToken: string,
        browserSessionKey: string,
        emailValue: string,
        password: string,
        decision: OAuthAdoptionDecisionInput,
        settings: Record<string, string>,
        provider = ""
    ): Promise<Record<string, unknown>> {
        const session = await this.#pending.getBrowserSession(sessionToken, browserSessionKey);
        if (provider.trim() !== "" && session.providerType !== provider.trim().toLowerCase()) {
            throw new PendingOAuthFinalizationError("pending_auth_provider_mismatch", 400, "pending oauth provider mismatch");
        }
        const user = await this.#verifyCredentials(emailValue, password);
        if (session.targetUserId !== null && session.targetUserId !== user.id) {
            throw new PendingOAuthFinalizationError(
                "pending_auth_target_user_mismatch",
                409,
                "pending oauth session must be completed by the targeted user"
            );
        }
        assertBackendMode(user, settings);
        if (settings.totp_enabled === "true" && user.totpEnabled) {
            if (this.#totpLogin === null) {
                throw new PendingOAuthFinalizationError(
                    "pending_auth_totp_not_configured",
                    503,
                    "Pending OAuth TOTP completion is not configured"
                );
            }
            return { ...await this.#totpLogin.createPendingOAuth(user, {
                pendingSessionToken: sessionToken,
                browserSessionKey,
                adoptDisplayName: decision.adoptDisplayName === true,
                adoptAvatar: decision.adoptAvatar === true
            }) };
        }
        await this.#complete(session, user, browserSessionKey, decision, settings, true, true);
        return tokenPayload(await this.#tokens.issue(await requireUser(this.#users, user.id)));
    }

    async createAccount(
        sessionToken: string,
        browserSessionKey: string,
        input: {
            email?: string;
            password?: string;
            verifyCode?: string;
            invitationCode?: string;
            affiliateCode?: string;
            adoption: OAuthAdoptionDecisionInput;
        },
        settings: Record<string, string>,
        provider = "",
        registrationMode: PendingOAuthRegistrationMode = "local_email"
    ): Promise<Record<string, unknown>> {
        if (this.#registrations === null) {
            throw new PendingOAuthFinalizationError(
                "pending_auth_not_ready",
                503,
                "pending oauth registration is not configured"
            );
        }
        const session = await this.#pending.getBrowserSession(sessionToken, browserSessionKey);
        const expectedProvider = provider.trim().toLowerCase();
        if (expectedProvider !== "" && session.providerType !== expectedProvider) {
            throw new PendingOAuthFinalizationError(
                "pending_auth_provider_mismatch",
                400,
                "pending oauth provider mismatch"
            );
        }
        if (session.intent !== "login" || session.targetUserId !== null) {
            throw new PendingOAuthFinalizationError(
                "pending_auth_session_invalid",
                400,
                "pending auth session cannot create an account"
            );
        }
        const adoption = resolveAdoption(session, input.adoption);
        const passwordless = registrationMode === "provider_identity"
            || registrationMode === "verified_provider_email";
        const email = registrationMode === "provider_identity"
            || registrationMode === "verified_provider_email_with_password"
            ? session.resolvedEmail
            : input.email ?? "";
        const initialUsername = registrationMode !== "local_email"
            ? stringValue(session.upstreamIdentityClaims.username)
            : "";
        const identityMetadata = registrationMode === "verified_provider_email"
            ? {
                ...session.upstreamIdentityClaims,
                synthetic_email: stringValue(session.upstreamIdentityClaims.email),
                email: email.trim().toLowerCase()
            }
            : session.upstreamIdentityClaims;
        try {
            const response = await this.#registrations.registerOAuth({
                email,
                ...(passwordless ? {} : { password: input.password ?? "" }),
                ...(input.verifyCode === undefined ? {} : { verifyCode: input.verifyCode }),
                ...(input.invitationCode === undefined ? {} : { invitationCode: input.invitationCode }),
                affiliateCode: firstNonEmpty(
                    input.affiliateCode,
                    stringValue(session.localFlowState.affiliate_code),
                    stringValue(session.upstreamIdentityClaims.aff_code)
                ),
                promoCode: stringValue(session.localFlowState.promo_code),
                requireEmailVerification: registrationMode === "local_email",
                allowReservedEmail: registrationMode === "provider_identity",
                allowRegistrationBypass: session.providerType === "dingtalk"
                    && session.localFlowState.registration_bypass_allowed === true,
                initialUsername,
                pendingSessionId: session.id,
                browserSessionKey,
                finalizationNonce: this.#nonceFactory(),
                providerType: session.providerType,
                providerKey: session.providerKey,
                providerSubject: session.providerSubject,
                issuer: identityIssuer(session),
                metadata: {
                    ...identityMetadata,
                    ...(adoption.adoptDisplayName && adoption.displayName !== ""
                        ? { display_name: adoption.displayName }
                        : {}),
                    ...(adoption.adoptAvatar && adoption.avatarUrl !== ""
                        ? { avatar_url: adoption.avatarUrl }
                        : {})
                },
                ...adoption
            }, settings);
            await this.#syncDingTalkAttributes(response.user.id, session, true);
            const { user: _user, ...payload } = response;
            return payload;
        } catch (error) {
            if (isUserManagementError(error)) {
                throw new PendingOAuthFinalizationError(error.code, error.status, error.message);
            }
            throw error;
        }
    }

    async prepareVerification(
        sessionToken: string,
        browserSessionKey: string,
        emailValue: string
    ): Promise<{ email: string; existingAccountPayload: Record<string, unknown> | null }> {
        const email = normalizeRegistrationEmail(emailValue);
        const session = await this.#pending.getBrowserSession(sessionToken, browserSessionKey);
        if (session.intent !== "login" || session.targetUserId !== null) {
            throw new PendingOAuthFinalizationError(
                "pending_auth_session_invalid",
                400,
                "pending auth session cannot create an account"
            );
        }
        const existing = await this.#users.findByEmail(email);
        if (existing === null) return { email, existingAccountPayload: null };
        const updated = await this.#pending.transitionAccountChoice(
            sessionToken,
            browserSessionKey,
            email,
            existing.id
        );
        return { email, existingAccountPayload: pendingSessionStatus(updated) };
    }

    async completeAfterTotp(
        user: AuthUserRecord,
        context: PendingOAuthTotpContext,
        settings: Record<string, string>
    ): Promise<void> {
        const session = await this.#pending.getBrowserSession(
            context.pendingSessionToken,
            context.browserSessionKey
        );
        if (session.targetUserId !== null && session.targetUserId !== user.id) {
            throw new PendingOAuthFinalizationError(
                "pending_auth_target_user_mismatch",
                409,
                "pending oauth session must be completed by the targeted user"
            );
        }
        assertActiveUser(user);
        assertBackendMode(user, settings);
        await this.#complete(session, user, context.browserSessionKey, {
            adoptDisplayName: context.adoptDisplayName,
            adoptAvatar: context.adoptAvatar
        }, settings, true, true);
    }

    async #complete(
        session: PendingAuthSessionRecord,
        user: AuthUserRecord,
        browserSessionKey: string,
        decision: OAuthAdoptionDecisionInput,
        settings: Record<string, string>,
        recordLogin: boolean,
        forceFirstBind = false
    ): Promise<void> {
        const now = this.#clock();
        const completedAt = new Date(now).toISOString();
        const adoption = resolveAdoption(session, decision);
        const firstBind = forceFirstBind || session.intent === "bind_current_user";
        try {
            await this.#repository.completeBinding({
                pendingSessionId: session.id,
                browserSessionKey,
                finalizationNonce: this.#nonceFactory(),
                userId: user.id,
                identity: {
                    providerType: session.providerType,
                    providerKey: session.providerKey,
                    providerSubject: session.providerSubject,
                    issuer: identityIssuer(session),
                    metadata: {
                        ...session.upstreamIdentityClaims,
                        ...(adoption.adoptDisplayName && adoption.displayName !== ""
                            ? { display_name: adoption.displayName }
                            : {}),
                        ...(adoption.adoptAvatar && adoption.avatarUrl !== ""
                            ? { avatar_url: adoption.avatarUrl }
                            : {})
                    }
                },
                adoption,
                completedAt,
                completedAtMs: now,
                recordLogin,
                ...(firstBind && providerFirstBindEnabled(settings, session.providerType)
                    ? { firstBindGrant: resolveFirstBindGrant(settings, session.providerType, completedAt) }
                    : {})
            });
            await this.#syncDingTalkAttributes(user.id, session, false);
        } catch (error) {
            if (error instanceof OAuthFinalizationRejectedError) {
                throw new PendingOAuthFinalizationError(
                    "pending_auth_finalization_conflict",
                    409,
                    "pending oauth session changed or identity is already owned"
                );
            }
            throw error;
        }
    }

    async #syncDingTalkAttributes(
        userId: number,
        session: PendingAuthSessionRecord,
        registration: boolean
    ): Promise<void> {
        if (session.providerType !== "dingtalk" || this.#dingtalkAttributes === null) return;
        const sync = dingTalkAttributeSync(session.localFlowState.dingtalk_attribute_sync);
        if (sync === null) return;
        try {
            await this.#dingtalkAttributes.sync(userId, sync, registration, new Date(this.#clock()).toISOString());
        } catch {
            // DingTalk enterprise attributes are best-effort and must not invalidate a completed login.
        }
    }

    async #verifyCredentials(emailValue: string, password: string): Promise<AuthUserRecord> {
        const email = normalizeEmail(emailValue);
        if (password.length === 0 || new TextEncoder().encode(password).byteLength > 72) {
            throw invalidCredentials();
        }
        const user = await this.#users.findByEmail(email);
        const matches = await this.#passwords.verify(password, user?.passwordHash ?? DUMMY_BCRYPT_HASH);
        if (user === null || !matches) throw invalidCredentials();
        assertActiveUser(user);
        return user;
    }
}

function dingTalkAttributeSync(value: unknown): {
    usernameOnRegistration: boolean;
    username: string;
    attributes: { key: string; value: string }[];
} | null {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
    const stored = value as Record<string, unknown>;
    const attributes = Array.isArray(stored.attributes) ? stored.attributes.flatMap((entry) => {
        if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return [];
        const field = entry as Record<string, unknown>;
        return typeof field.key === "string" && typeof field.value === "string"
            ? [{ key: field.key, value: field.value }]
            : [];
    }) : [];
    return {
        usernameOnRegistration: stored.username_on_registration === true,
        username: stringValue(stored.username),
        attributes
    };
}

function completionPayload(session: PendingAuthSessionRecord): Record<string, unknown> {
    const stored = session.localFlowState.completion_response;
    if (stored === null || typeof stored !== "object" || Array.isArray(stored)) {
        throw new PendingOAuthFinalizationError(
            "pending_auth_completion_invalid",
            500,
            "pending auth completion payload is invalid"
        );
    }
    const payload = { ...(stored as Record<string, unknown>) };
    for (const key of ["access_token", "refresh_token", "expires_in", "token_type"]) delete payload[key];
    const step = stringValue(payload.step).toLowerCase();
    if (["choice", "choose_account_action", "choose_account", "choose", "email_required"].includes(step)) {
        payload.step = "choose_account_action_required";
    }
    if (payload.step === "choose_account_action_required" || "email_binding_required" in payload) {
        payload.adoption_required = true;
    }
    if (session.redirectTo !== "" && !("redirect" in payload)) payload.redirect = session.redirectTo;
    const displayName = stringValue(session.upstreamIdentityClaims.suggested_display_name);
    const avatarUrl = stringValue(session.upstreamIdentityClaims.suggested_avatar_url);
    if (displayName !== "" && !("suggested_display_name" in payload)) payload.suggested_display_name = displayName;
    if (avatarUrl !== "" && !("suggested_avatar_url" in payload)) payload.suggested_avatar_url = avatarUrl;
    if (displayName !== "" || avatarUrl !== "") payload.adoption_required ??= true;
    return payload;
}

function pendingSessionStatus(session: PendingAuthSessionRecord): Record<string, unknown> {
    return {
        auth_result: "pending_session",
        provider: session.providerType,
        intent: session.intent,
        ...completionPayload(session),
        ...(session.resolvedEmail === "" ? {} : { email: session.resolvedEmail })
    };
}

function canIssueTokenPair(session: PendingAuthSessionRecord, payload: Record<string, unknown>): boolean {
    return session.intent === "login"
        && session.targetUserId !== null
        && stringValue(payload.error).toLowerCase() !== "invitation_required"
        && stringValue(payload.step) === "";
}

function requiresUserChoice(payload: Record<string, unknown>): boolean {
    return stringValue(payload.error).toLowerCase() === "invitation_required"
        || CHOICE_STEPS.has(stringValue(payload.step).toLowerCase());
}

async function identityAlreadyBound(
    users: D1AuthUserRepository,
    userId: number,
    session: PendingAuthSessionRecord
): Promise<boolean> {
    const identities = await users.listIdentities(userId);
    return identities.some((identity) => identity.providerType === session.providerType
        && identity.providerKey === session.providerKey
        && identity.providerSubject === session.providerSubject);
}

function resolveAdoption(
    session: PendingAuthSessionRecord,
    input: OAuthAdoptionDecisionInput
): {
    adoptDisplayName: boolean;
    adoptAvatar: boolean;
    displayName: string;
    avatarUrl: string;
} {
    const displayName = [...stringValue(session.upstreamIdentityClaims.suggested_display_name)]
        .slice(0, 100).join("");
    const avatarCandidate = stringValue(session.upstreamIdentityClaims.suggested_avatar_url);
    return {
        adoptDisplayName: input.adoptDisplayName === true && displayName !== "",
        adoptAvatar: input.adoptAvatar === true && validAvatarUrl(avatarCandidate),
        displayName,
        avatarUrl: validAvatarUrl(avatarCandidate) ? avatarCandidate : ""
    };
}

function resolveFirstBindGrant(
    settings: Record<string, string>,
    provider: string,
    startsAt: string
): OAuthFirstBindGrantMutation {
    const prefix = `auth_source_default_${provider}`;
    return {
        balance: nonNegativeNumber(settings[`${prefix}_balance`]),
        concurrency: nonNegativeInteger(settings[`${prefix}_concurrency`]),
        subscriptions: parseSubscriptions(settings[`${prefix}_subscriptions`], startsAt)
    };
}

function parseSubscriptions(raw: string | undefined, startsAt: string) {
    let parsed: unknown;
    try { parsed = JSON.parse(raw ?? "[]"); } catch { return []; }
    if (!Array.isArray(parsed)) return [];
    const output = [];
    const seen = new Set<number>();
    for (const value of parsed) {
        if (value === null || typeof value !== "object" || Array.isArray(value)) continue;
        const record = value as Record<string, unknown>;
        const groupId = Number(record.group_id);
        const validityDays = Number(record.validity_days);
        if (!Number.isSafeInteger(groupId) || groupId <= 0 || seen.has(groupId)
            || !Number.isSafeInteger(validityDays) || validityDays <= 0 || validityDays > 3650) continue;
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

function tokenPayload(pair: AuthTokenPair): Record<string, unknown> {
    return {
        access_token: pair.accessToken,
        refresh_token: pair.refreshToken,
        expires_in: pair.expiresIn,
        token_type: "Bearer"
    };
}

function assertActiveUser(user: AuthUserRecord | null): asserts user is AuthUserRecord {
    if (user === null || user.status !== "active") {
        throw new PendingOAuthFinalizationError("user_not_active", 401, "user account is not active");
    }
}

function assertBackendMode(user: AuthUserRecord, settings: Record<string, string>): void {
    if (settings.backend_mode_enabled === "true" && user.role !== "admin") {
        throw new PendingOAuthFinalizationError(
            "backend_mode_admin_only",
            403,
            "Backend mode is active. Only admin login is allowed."
        );
    }
}

async function requireUser(users: D1AuthUserRepository, id: number): Promise<AuthUserRecord> {
    const user = await users.findById(id);
    assertActiveUser(user);
    return user;
}

function providerFirstBindEnabled(settings: Record<string, string>, provider: string): boolean {
    return settings[`auth_source_default_${provider}_grant_on_first_bind`] === "true";
}

function identityIssuer(session: PendingAuthSessionRecord): string | null {
    const claim = stringValue(session.upstreamIdentityClaims.issuer);
    if (session.providerType === "oidc") return session.providerKey || claim || null;
    return claim || null;
}

function validAvatarUrl(value: string): boolean {
    if (value === "" || value.length > 2048) return false;
    try {
        const url = new URL(value);
        return url.protocol === "https:" || url.protocol === "http:";
    } catch {
        return false;
    }
}

function normalizeEmail(value: string): string {
    const email = value.trim().toLowerCase();
    if (email.length === 0 || email.length > 254 || !/^[^\s@]+@[^\s@]+$/u.test(email)) {
        throw invalidCredentials();
    }
    return email;
}

function normalizeRegistrationEmail(value: string): string {
    const email = value.trim().toLowerCase();
    if (email.length === 0 || email.length > 254 || !/^[^\s@]+@[^\s@]+$/u.test(email)) {
        throw new PendingOAuthFinalizationError("invalid_request", 400, "A valid email is required");
    }
    if ([
        "@linuxdo-connect.invalid",
        "@oidc-connect.invalid",
        "@wechat-connect.invalid",
        "@dingtalk-connect.invalid"
    ].some((suffix) => email.endsWith(suffix))) {
        throw new PendingOAuthFinalizationError("email_reserved", 400, "This email address is reserved");
    }
    return email;
}

function invalidCredentials(): PendingOAuthFinalizationError {
    return new PendingOAuthFinalizationError("invalid_credentials", 401, "Invalid email or password");
}

function hasDecision(value: OAuthAdoptionDecisionInput): boolean {
    return typeof value.adoptDisplayName === "boolean" || typeof value.adoptAvatar === "boolean";
}

function stringValue(value: unknown): string {
    return typeof value === "string" ? value.trim() : "";
}

function firstNonEmpty(...values: Array<string | undefined>): string {
    return values.map((value) => value?.trim() ?? "").find(Boolean) ?? "";
}

function isUserManagementError(error: unknown): error is Error & { code: string; status: number } {
    if (!(error instanceof Error)) return false;
    const record = error as Error & { code?: unknown; status?: unknown };
    return typeof record.code === "string" && typeof record.status === "number";
}

function nonNegativeNumber(raw: string | undefined): number {
    const value = Number(raw ?? 0);
    return Number.isFinite(value) && value >= 0 ? value : 0;
}

function nonNegativeInteger(raw: string | undefined): number {
    const value = Number(raw ?? 0);
    return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function startOfUtcDay(value: string): string {
    const date = new Date(value);
    return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate())).toISOString();
}
