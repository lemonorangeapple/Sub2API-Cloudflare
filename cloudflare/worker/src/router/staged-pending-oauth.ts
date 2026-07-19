import { D1AuthEmailRepository, EmailCooldownError } from "../repositories/auth-email.ts";
import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import { D1OAuthFinalizationRepository } from "../repositories/oauth-finalization.ts";
import { D1PendingAuthRepository } from "../repositories/pending-auth.ts";
import { D1CoordinationRepository } from "../repositories/runtime-coordination.ts";
import { D1DingTalkAttributeRepository } from "../repositories/dingtalk-attributes.ts";
import { D1SettingsRepository } from "../repositories/settings.ts";
import { D1UserManagementRepository } from "../repositories/user-management.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import {
    AesGcmEmailSecretCipher,
    AuthenticationEmailTaskProducer,
    type EmailSecretCipher
} from "../services/email-task-producer.ts";
import { Hs256JwtSigner } from "../services/jwt.ts";
import {
    D1PendingOAuthFinalizationService,
    PendingOAuthFinalizationError,
    type OAuthAdoptionDecisionInput
} from "../services/pending-oauth-finalization.ts";
import { D1PendingAuthService, PendingAuthError } from "../services/pending-auth.ts";
import { BcryptPasswordService, type PasswordHasher, type PasswordVerifier } from "../services/password.ts";
import { TurnstileVerificationError, TurnstileVerifier } from "../services/turnstile.ts";
import {
    AesGcmTotpSecretDecryptor,
    TotpLoginService,
    type TotpSecretDecryptor
} from "../services/totp.ts";
import { D1UserManagementService } from "../services/user-management.ts";
import type { D1Database } from "../types/d1.ts";
import { legacyError, legacyInternalError, legacySuccess, routerError } from "./responses.ts";

export const STAGED_PENDING_OAUTH_PATHS = {
    exchange: "/api/v1/auth/oauth/pending/exchange",
    bindLogin: "/api/v1/auth/oauth/pending/bind-login",
    createAccount: "/api/v1/auth/oauth/pending/create-account",
    sendVerifyCode: "/api/v1/auth/oauth/pending/send-verify-code",
    linuxdoBindLogin: "/api/v1/auth/oauth/linuxdo/bind-login",
    linuxdoCompleteRegistration: "/api/v1/auth/oauth/linuxdo/complete-registration",
    linuxdoCreateAccount: "/api/v1/auth/oauth/linuxdo/create-account",
    oidcBindLogin: "/api/v1/auth/oauth/oidc/bind-login",
    oidcCompleteRegistration: "/api/v1/auth/oauth/oidc/complete-registration",
    oidcCreateAccount: "/api/v1/auth/oauth/oidc/create-account",
    wechatBindLogin: "/api/v1/auth/oauth/wechat/bind-login",
    wechatCompleteRegistration: "/api/v1/auth/oauth/wechat/complete-registration",
    wechatCreateAccount: "/api/v1/auth/oauth/wechat/create-account",
    dingtalkBindLogin: "/api/v1/auth/oauth/dingtalk/bind-login",
    dingtalkCompleteRegistration: "/api/v1/auth/oauth/dingtalk/complete-registration",
    dingtalkCreateAccount: "/api/v1/auth/oauth/dingtalk/create-account",
    githubCompleteRegistration: "/api/v1/auth/oauth/github/complete-registration",
    googleCompleteRegistration: "/api/v1/auth/oauth/google/complete-registration"
} as const;

export const STAGED_PENDING_OAUTH_SETTING_KEYS = [
    "backend_mode_enabled",
    "totp_enabled",
    "registration_enabled",
    "registration_email_suffix_whitelist",
    "invitation_code_enabled",
    "promo_code_enabled",
    "default_balance",
    "default_concurrency",
    "default_user_rpm_limit",
    "default_subscriptions",
    "default_platform_quotas",
    "site_name",
    "turnstile_enabled",
    "turnstile_secret_key",
    "auth_source_default_linuxdo_balance",
    "auth_source_default_linuxdo_concurrency",
    "auth_source_default_linuxdo_subscriptions",
    "auth_source_default_linuxdo_platform_quotas",
    "auth_source_default_linuxdo_grant_on_signup",
    "auth_source_default_linuxdo_grant_on_first_bind",
    "auth_source_default_oidc_balance",
    "auth_source_default_oidc_concurrency",
    "auth_source_default_oidc_subscriptions",
    "auth_source_default_oidc_platform_quotas",
    "auth_source_default_oidc_grant_on_signup",
    "auth_source_default_oidc_grant_on_first_bind",
    "auth_source_default_wechat_balance",
    "auth_source_default_wechat_concurrency",
    "auth_source_default_wechat_subscriptions",
    "auth_source_default_wechat_platform_quotas",
    "auth_source_default_wechat_grant_on_signup",
    "auth_source_default_wechat_grant_on_first_bind",
    "auth_source_default_github_balance",
    "auth_source_default_github_concurrency",
    "auth_source_default_github_subscriptions",
    "auth_source_default_github_platform_quotas",
    "auth_source_default_github_grant_on_signup",
    "auth_source_default_github_grant_on_first_bind",
    "auth_source_default_google_balance",
    "auth_source_default_google_concurrency",
    "auth_source_default_google_subscriptions",
    "auth_source_default_google_platform_quotas",
    "auth_source_default_google_grant_on_signup",
    "auth_source_default_google_grant_on_first_bind",
    "auth_source_default_dingtalk_balance",
    "auth_source_default_dingtalk_concurrency",
    "auth_source_default_dingtalk_subscriptions",
    "auth_source_default_dingtalk_platform_quotas",
    "auth_source_default_dingtalk_grant_on_signup",
    "auth_source_default_dingtalk_grant_on_first_bind"
] as const;

const OAUTH_COOKIE_PATH = "/api/v1/auth/oauth";

export interface StagedPendingOAuthEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
    EMAIL_TASK_ENCRYPTION_KEY?: string;
    TOTP_ENCRYPTION_KEY?: string;
}

export interface StagedPendingOAuthDependencies {
    clock?: () => number;
    passwordVerifier?: PasswordVerifier;
    passwordHasher?: PasswordHasher;
    nonceFactory?: () => string;
    emailCipher?: EmailSecretCipher;
    verificationCodeFactory?: () => string;
    fetchImplementation?: typeof fetch;
}

export async function routeStagedPendingOAuth(
    request: Request,
    env: StagedPendingOAuthEnv,
    dependencies: StagedPendingOAuthDependencies = {}
): Promise<Response | null> {
    const path = new URL(request.url).pathname;
    if (!Object.values(STAGED_PENDING_OAUTH_PATHS).includes(
        path as typeof STAGED_PENDING_OAUTH_PATHS[keyof typeof STAGED_PENDING_OAUTH_PATHS]
    )) return null;
    if (request.method !== "POST") {
        return routerError(405, "method_not_allowed", `${path} requires POST`, { allow: "POST" });
    }
    if (env.DB === undefined) {
        return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");
    }

    try {
        const clock = dependencies.clock ?? Date.now;
        const settings = await new D1SettingsRepository(env.DB).getMany(STAGED_PENDING_OAUTH_SETTING_KEYS);
        const service = createPendingOAuthFinalizationService(env.DB, env, dependencies, clock);
        const sessionToken = requiredCookie(request, "oauth_pending_session");
        const browserSessionKey = requiredCookie(request, "oauth_pending_browser_session");
        const body = await optionalJsonBody(request);
        const decision = adoptionDecision(body);

        if (path === STAGED_PENDING_OAUTH_PATHS.exchange) {
            const result = await service.exchange(sessionToken, browserSessionKey, decision, settings);
            const response = legacySuccess(result.payload);
            return result.finalized ? clearPendingCookies(response, request) : response;
        }

        if (path === STAGED_PENDING_OAUTH_PATHS.sendVerifyCode) {
            const limited = await consumeRateLimit(env.DB, request, clock);
            if (limited !== null) return limited;
            await verifyTurnstileIfEnabled(body, request, settings, dependencies.fetchImplementation);
            const prepared = await service.prepareVerification(
                sessionToken,
                browserSessionKey,
                stringField(body, "email")
            );
            if (prepared.existingAccountPayload !== null) {
                return legacySuccess(prepared.existingAccountPayload);
            }
            const result = await createEmailProducer(env.DB, env, dependencies, clock)
                .enqueueVerification(
                    prepared.email,
                    settings.site_name || "Sub2API",
                    request.headers.get("accept-language") ?? ""
                );
            return legacySuccess({ success: true, countdown: result.countdown });
        }

        if (
            path === STAGED_PENDING_OAUTH_PATHS.createAccount
            || path === STAGED_PENDING_OAUTH_PATHS.linuxdoCreateAccount
            || path === STAGED_PENDING_OAUTH_PATHS.linuxdoCompleteRegistration
            || path === STAGED_PENDING_OAUTH_PATHS.oidcCreateAccount
            || path === STAGED_PENDING_OAUTH_PATHS.oidcCompleteRegistration
            || path === STAGED_PENDING_OAUTH_PATHS.wechatCreateAccount
            || path === STAGED_PENDING_OAUTH_PATHS.wechatCompleteRegistration
            || path === STAGED_PENDING_OAUTH_PATHS.dingtalkCreateAccount
            || path === STAGED_PENDING_OAUTH_PATHS.dingtalkCompleteRegistration
            || path === STAGED_PENDING_OAUTH_PATHS.githubCompleteRegistration
            || path === STAGED_PENDING_OAUTH_PATHS.googleCompleteRegistration
        ) {
            const providerIdentityRegistration = path === STAGED_PENDING_OAUTH_PATHS.linuxdoCompleteRegistration
                || path === STAGED_PENDING_OAUTH_PATHS.oidcCompleteRegistration
                || path === STAGED_PENDING_OAUTH_PATHS.wechatCompleteRegistration
                || path === STAGED_PENDING_OAUTH_PATHS.dingtalkCompleteRegistration;
            const verifiedEmailRegistration = path === STAGED_PENDING_OAUTH_PATHS.githubCompleteRegistration
                || path === STAGED_PENDING_OAUTH_PATHS.googleCompleteRegistration;
            const expectedProvider = path.startsWith("/api/v1/auth/oauth/oidc/") ? "oidc"
                : path.startsWith("/api/v1/auth/oauth/linuxdo/") ? "linuxdo"
                    : path.startsWith("/api/v1/auth/oauth/wechat/") ? "wechat" : "";
            const compatibilityProvider = expectedProvider !== "" ? expectedProvider
                : path.startsWith("/api/v1/auth/oauth/dingtalk/") ? "dingtalk" : "";
            const provider = path === STAGED_PENDING_OAUTH_PATHS.githubCompleteRegistration ? "github"
                : path === STAGED_PENDING_OAUTH_PATHS.googleCompleteRegistration ? "google" : compatibilityProvider;
            const payload = await service.createAccount(
                sessionToken,
                browserSessionKey,
                {
                    ...(providerIdentityRegistration ? {} : {
                        ...(verifiedEmailRegistration ? {} : { email: stringField(body, "email") }),
                        password: stringField(body, "password"),
                        ...(verifiedEmailRegistration ? {} : { verifyCode: stringField(body, "verify_code") })
                    }),
                    invitationCode: optionalStringField(body, "invitation_code"),
                    affiliateCode: optionalStringField(body, "aff_code"),
                    adoption: decision
                },
                settings,
                provider,
                providerIdentityRegistration ? "provider_identity"
                    : verifiedEmailRegistration ? "verified_provider_email_with_password" : "local_email"
            );
            return clearPendingCookies(legacySuccess(payload), request);
        }

        const payload = await service.bindLogin(
            sessionToken,
            browserSessionKey,
            stringField(body, "email"),
            stringField(body, "password"),
            decision,
            settings,
            path === STAGED_PENDING_OAUTH_PATHS.linuxdoBindLogin ? "linuxdo"
                : path === STAGED_PENDING_OAUTH_PATHS.oidcBindLogin ? "oidc"
                    : path === STAGED_PENDING_OAUTH_PATHS.wechatBindLogin ? "wechat"
                        : path === STAGED_PENDING_OAUTH_PATHS.dingtalkBindLogin ? "dingtalk" : ""
        );
        return clearPendingCookies(legacySuccess(payload), request);
    } catch (error) {
        return pendingOAuthFailure(error);
    }
}

export function createPendingOAuthFinalizationService(
    db: D1Database,
    env: StagedPendingOAuthEnv,
    dependencies: StagedPendingOAuthDependencies,
    clock: () => number
): D1PendingOAuthFinalizationService {
    const secret = env.JWT_SECRET?.trim() ?? "";
    if (secret === "") {
        throw new PendingOAuthConfigurationError("JWT secret is not configured");
    }
    const users = new D1AuthUserRepository(db);
    const sessions = new D1AuthSessionRepository(db);
    const state = new D1ExpiringStateRepository(db, { clock });
    const coordination = new D1CoordinationRepository(db, { clock });
    const tokens = new AuthTokenService(
        sessions,
        new Hs256JwtSigner(
            secret,
            boundedInteger(env.JWT_ACCESS_TOKEN_EXPIRES_SECONDS, 86400, 1, 604800),
            clock
        ),
        boundedInteger(env.JWT_REFRESH_TOKEN_EXPIRE_DAYS, 30, 1, 365),
        clock
    );
    const passwords = dependencies.passwordVerifier ?? dependencies.passwordHasher ?? new BcryptPasswordService();
    const registrations = new D1UserManagementService(
        users,
        new D1UserManagementRepository(db),
        dependencies.passwordHasher ?? passwordHasher(passwords),
        state,
        tokens,
        clock
    );
    const totpLogin = new TotpLoginService(
        users,
        state,
        coordination,
        tokens,
        totpDecryptor(env),
        clock
    );
    return new D1PendingOAuthFinalizationService(
        users,
        new D1PendingAuthService(new D1PendingAuthRepository(db), { clock }),
        new D1OAuthFinalizationRepository(db),
        passwords,
        tokens,
        {
            clock,
            nonceFactory: dependencies.nonceFactory,
            registrations,
            totpLogin,
            dingtalkAttributes: new D1DingTalkAttributeRepository(db)
        }
    );
}

function totpDecryptor(env: StagedPendingOAuthEnv): TotpSecretDecryptor {
    const key = env.TOTP_ENCRYPTION_KEY?.trim() ?? "";
    if (key === "") {
        return { async decrypt() { throw new Error("TOTP encryption key is not configured"); } };
    }
    try {
        return new AesGcmTotpSecretDecryptor(key);
    } catch {
        return { async decrypt() { throw new Error("TOTP encryption key is invalid"); } };
    }
}

function adoptionDecision(body: Record<string, unknown>): OAuthAdoptionDecisionInput {
    return {
        ...(typeof body.adopt_display_name === "boolean"
            ? { adoptDisplayName: body.adopt_display_name }
            : {}),
        ...(typeof body.adopt_avatar === "boolean" ? { adoptAvatar: body.adopt_avatar } : {})
    };
}

async function optionalJsonBody(request: Request): Promise<Record<string, unknown>> {
    const text = await request.text();
    if (text.trim() === "") return {};
    if (new TextEncoder().encode(text).byteLength > 16 * 1024) {
        throw new PendingOAuthRequestError("request body is too large");
    }
    try {
        const value: unknown = JSON.parse(text);
        if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError();
        return value as Record<string, unknown>;
    } catch {
        throw new PendingOAuthRequestError("invalid request body");
    }
}

function stringField(body: Record<string, unknown>, key: string): string {
    const value = body[key];
    if (typeof value !== "string") throw new PendingOAuthRequestError(`${key} is required`);
    return value;
}

function optionalStringField(body: Record<string, unknown>, key: string): string | undefined {
    const value = body[key];
    if (value === undefined || value === null) return undefined;
    if (typeof value !== "string") throw new PendingOAuthRequestError(`${key} must be a string`);
    return value;
}

function passwordHasher(passwords: PasswordVerifier): BcryptPasswordService {
    if ("hash" in passwords && typeof passwords.hash === "function") {
        return passwords as BcryptPasswordService;
    }
    return new BcryptPasswordService();
}

function createEmailProducer(
    db: D1Database,
    env: StagedPendingOAuthEnv,
    dependencies: StagedPendingOAuthDependencies,
    clock: () => number
): AuthenticationEmailTaskProducer {
    let cipher = dependencies.emailCipher;
    if (cipher === undefined) {
        const key = env.EMAIL_TASK_ENCRYPTION_KEY?.trim() ?? "";
        if (key === "") throw new PendingOAuthConfigurationError("Email task encryption key is not configured");
        cipher = new AesGcmEmailSecretCipher(key);
    }
    return new AuthenticationEmailTaskProducer(new D1AuthEmailRepository(db), cipher, {
        clock,
        verificationCodeFactory: dependencies.verificationCodeFactory
    });
}

async function verifyTurnstileIfEnabled(
    body: Record<string, unknown>,
    request: Request,
    settings: Record<string, string>,
    fetchImplementation?: typeof fetch
): Promise<void> {
    if (settings.turnstile_enabled !== "true") return;
    const secret = settings.turnstile_secret_key?.trim() ?? "";
    if (secret === "") throw new PendingOAuthConfigurationError("Turnstile verification is not configured");
    await new TurnstileVerifier(secret, fetchImplementation ?? fetch).verify(
        stringField(body, "turnstile_token"),
        clientIp(request)
    );
}

async function consumeRateLimit(
    db: D1Database,
    request: Request,
    clock: () => number
): Promise<Response | null> {
    const result = await new D1CoordinationRepository(db, { clock }).consumeFixedWindow({
        key: `oauth-pending-send-verify-code:${clientIp(request)}`,
        limit: 5,
        windowMs: 60_000
    });
    return result.allowed ? null : legacyError(
        429,
        "Too many requests, please try again later",
        "RATE_LIMIT_EXCEEDED",
        { reset_at: String(result.resetAt) }
    );
}

function clientIp(request: Request): string {
    return request.headers.get("cf-connecting-ip")?.trim()
        || request.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
        || "unknown";
}

function requiredCookie(request: Request, name: string): string {
    const raw = request.headers.get("cookie") ?? "";
    for (const entry of raw.split(";")) {
        const separator = entry.indexOf("=");
        if (separator < 0 || entry.slice(0, separator).trim() !== name) continue;
        try {
            const value = decodeURIComponent(entry.slice(separator + 1).trim());
            if (value !== "") return value;
        } catch {
            break;
        }
    }
    throw new PendingAuthError(
        name === "oauth_pending_session"
            ? "pending_auth_session_not_found"
            : "pending_auth_browser_mismatch",
        name === "oauth_pending_session" ? 404 : 401,
        name === "oauth_pending_session"
            ? "pending auth session not found"
            : "pending auth session does not match this browser"
    );
}

function clearPendingCookies(response: Response, request: Request): Response {
    const secure = new URL(request.url).protocol === "https:";
    for (const name of ["oauth_pending_session", "oauth_pending_browser_session", "oauth_promo_code"]) {
        response.headers.append("set-cookie", [
            `${name}=`, `Path=${OAUTH_COOKIE_PATH}`, "Max-Age=0", "HttpOnly", "SameSite=Lax",
            ...(secure ? ["Secure"] : [])
        ].join("; "));
    }
    return response;
}

function boundedInteger(raw: string | undefined, fallback: number, minimum: number, maximum: number): number {
    if (raw === undefined || raw.trim() === "") return fallback;
    const value = Number(raw);
    if (!Number.isInteger(value) || value < minimum || value > maximum) {
        throw new PendingOAuthConfigurationError("authentication duration is invalid");
    }
    return value;
}

function pendingOAuthFailure(error: unknown): Response {
    if (error instanceof PendingOAuthFinalizationError || error instanceof PendingAuthError) {
        return legacyError(error.status, error.message, error.code.toUpperCase());
    }
    if (error instanceof PendingOAuthRequestError) {
        return legacyError(400, error.message, "INVALID_REQUEST");
    }
    if (error instanceof EmailCooldownError) {
        return legacyError(429, "please wait before requesting a new code", "VERIFY_CODE_TOO_FREQUENT");
    }
    if (error instanceof TurnstileVerificationError) {
        return legacyError(400, error.message, "TURNSTILE_VERIFICATION_FAILED");
    }
    if (error instanceof PendingOAuthConfigurationError || error instanceof RangeError) {
        return legacyError(503, error instanceof Error ? error.message : "oauth finalization is not configured");
    }
    return legacyInternalError();
}

class PendingOAuthRequestError extends Error {}
class PendingOAuthConfigurationError extends Error {}
