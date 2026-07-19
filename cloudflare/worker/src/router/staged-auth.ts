import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { D1CoordinationRepository } from "../repositories/runtime-coordination.ts";
import { D1DingTalkAttributeRepository } from "../repositories/dingtalk-attributes.ts";
import { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import { D1OAuthFinalizationRepository } from "../repositories/oauth-finalization.ts";
import { D1PendingAuthRepository } from "../repositories/pending-auth.ts";
import { D1SettingsRepository } from "../repositories/settings.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AuthRefreshError, AuthRefreshService } from "../services/auth-refresh.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import { PasswordAuthError, PasswordAuthService } from "../services/password-auth.ts";
import {
    D1PendingOAuthFinalizationService,
    PendingOAuthFinalizationError
} from "../services/pending-oauth-finalization.ts";
import { D1PendingAuthService } from "../services/pending-auth.ts";
import { BcryptPasswordService, type PasswordVerifier } from "../services/password.ts";
import {
    AesGcmTotpSecretDecryptor,
    TotpAuthError,
    TotpLoginService,
    type TotpSecretDecryptor
} from "../services/totp.ts";
import { TurnstileVerificationError, TurnstileVerifier } from "../services/turnstile.ts";
import { UserProfileService } from "../services/user-profile.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
    routerError
} from "./responses.ts";

export const STAGED_AUTH_PATHS = {
    login: "/api/v1/auth/login",
    login2fa: "/api/v1/auth/login/2fa",
    refresh: "/api/v1/auth/refresh",
    logout: "/api/v1/auth/logout",
    me: "/api/v1/auth/me",
    revokeAll: "/api/v1/auth/revoke-all-sessions",
    bindToken: "/api/v1/auth/oauth/bind-token"
} as const;

const AUTH_SETTING_KEYS = [
    "backend_mode_enabled",
    "totp_enabled",
    "turnstile_enabled",
    "turnstile_secret_key",
    "linuxdo_connect_enabled",
    "oidc_connect_enabled",
    "wechat_connect_enabled",
    "wechat_connect_open_enabled",
    "wechat_connect_mp_enabled",
    "wechat_connect_mobile_enabled",
    "dingtalk_connect_enabled",
    "auth_source_default_linuxdo_balance",
    "auth_source_default_linuxdo_concurrency",
    "auth_source_default_linuxdo_subscriptions",
    "auth_source_default_linuxdo_grant_on_first_bind",
    "auth_source_default_oidc_balance",
    "auth_source_default_oidc_concurrency",
    "auth_source_default_oidc_subscriptions",
    "auth_source_default_oidc_grant_on_first_bind",
    "auth_source_default_wechat_balance",
    "auth_source_default_wechat_concurrency",
    "auth_source_default_wechat_subscriptions",
    "auth_source_default_wechat_grant_on_first_bind"
] as const;

const OAUTH_COOKIES = [
    ["oauth_pending_browser_session", "/api/v1/auth/oauth"],
    ["oauth_pending_session", "/api/v1/auth/oauth"],
    ["oauth_promo_code", "/api/v1/auth/oauth"],
    ["oauth_bind_access_token", "/api/v1/auth/oauth"],
    ["email_oauth_state", "/api/v1/auth/oauth"],
    ["linuxdo_oauth_state", "/api/v1/auth/oauth/linuxdo"],
    ["linuxdo_oauth_intent", "/api/v1/auth/oauth/linuxdo"],
    ["linuxdo_oauth_bind_user", "/api/v1/auth/oauth/linuxdo"],
    ["oidc_oauth_state", "/api/v1/auth/oauth/oidc"],
    ["oidc_oauth_intent", "/api/v1/auth/oauth/oidc"],
    ["oidc_oauth_bind_user", "/api/v1/auth/oauth/oidc"],
    ["wechat_oauth_state", "/api/v1/auth/oauth/wechat"],
    ["wechat_oauth_redirect", "/api/v1/auth/oauth/wechat"],
    ["wechat_oauth_intent", "/api/v1/auth/oauth/wechat"],
    ["wechat_oauth_mode", "/api/v1/auth/oauth/wechat"],
    ["wechat_oauth_bind_user", "/api/v1/auth/oauth/wechat"],
    ["dingtalk_oauth_state", "/api/v1/auth/oauth/dingtalk"],
    ["dingtalk_oauth_intent", "/api/v1/auth/oauth/dingtalk"],
    ["dingtalk_oauth_bind_user", "/api/v1/auth/oauth/dingtalk"]
] as const;

export interface StagedAuthEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
    TOTP_ENCRYPTION_KEY?: string;
    RUN_MODE?: string;
}

export interface StagedAuthDependencies {
    clock?: () => number;
    passwordVerifier?: PasswordVerifier;
    fetchImplementation?: typeof fetch;
}

export async function routeStagedAuth(
    request: Request,
    env: StagedAuthEnv,
    dependencies: StagedAuthDependencies = {}
): Promise<Response | null> {
    const path = new URL(request.url).pathname;
    if (!Object.values(STAGED_AUTH_PATHS).includes(path as typeof STAGED_AUTH_PATHS[keyof typeof STAGED_AUTH_PATHS])) {
        return null;
    }
    if (env.DB === undefined) {
        return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");
    }

    const expectedMethod = path === STAGED_AUTH_PATHS.me ? "GET" : "POST";
    if (request.method !== expectedMethod) {
        return routerError(
            405,
            "method_not_allowed",
            `${path} requires ${expectedMethod}`,
            { allow: expectedMethod }
        );
    }

    const clock = dependencies.clock ?? Date.now;
    const settingsRepository = new D1SettingsRepository(env.DB);
    const settings = await settingsRepository.getMany(AUTH_SETTING_KEYS);
    const users = new D1AuthUserRepository(env.DB);
    const sessions = new D1AuthSessionRepository(env.DB);
    const coordination = new D1CoordinationRepository(env.DB, { clock });
    const state = new D1ExpiringStateRepository(env.DB, { clock });

    try {
        if (path === STAGED_AUTH_PATHS.logout) {
            const body = await optionalJsonBody(request);
            const rawToken = typeof body.refresh_token === "string" ? body.refresh_token : undefined;
            if (env.JWT_SECRET?.trim()) {
                const services = createTokenServices(env, users, sessions, clock);
                await new AuthRefreshService(users, sessions, services.tokens, clock).logout(rawToken);
            } else if (rawToken) {
                await sessions.revokeToken(await cryptoHash(rawToken), clock());
            }
            return clearOAuthCookies(legacySuccess({ message: "Logged out successfully" }), request);
        }

        const services = createTokenServices(env, users, sessions, clock);
        const backendModeEnabled = settings.backend_mode_enabled === "true";

        if (path === STAGED_AUTH_PATHS.login) {
            const limit = await consumeRateLimit(coordination, request, "auth-login", 20);
            if (limit !== null) {
                return limit;
            }
            const body = await requiredJsonBody(request);
            if (settings.turnstile_enabled === "true") {
                const secret = settings.turnstile_secret_key?.trim();
                if (!secret) {
                    return legacyError(503, "Turnstile verification is not configured", "TURNSTILE_NOT_CONFIGURED");
                }
                await new TurnstileVerifier(
                    secret,
                    dependencies.fetchImplementation ?? fetch
                ).verify(stringField(body, "turnstile_token"), clientIp(request));
            }
            const totp = createTotpService(env, users, state, coordination, services.tokens, clock);
            const passwordAuth = new PasswordAuthService(
                users,
                dependencies.passwordVerifier ?? new BcryptPasswordService(),
                services.tokens,
                clock,
                totp
            );
            return legacySuccess(await passwordAuth.login(
                stringField(body, "email"),
                stringField(body, "password"),
                {
                    backendModeEnabled,
                    totpFeatureEnabled: settings.totp_enabled === "true"
                }
            ));
        }

        if (path === STAGED_AUTH_PATHS.login2fa) {
            const limit = await consumeRateLimit(coordination, request, "auth-login-2fa", 20);
            if (limit !== null) {
                return limit;
            }
            const body = await requiredJsonBody(request);
            const totp = createTotpService(env, users, state, coordination, services.tokens, clock);
            let completedPendingOAuth = false;
            const finalizer = new D1PendingOAuthFinalizationService(
                users,
                new D1PendingAuthService(new D1PendingAuthRepository(env.DB), { clock }),
                new D1OAuthFinalizationRepository(env.DB),
                dependencies.passwordVerifier ?? new BcryptPasswordService(),
                services.tokens,
                { clock, dingtalkAttributes: new D1DingTalkAttributeRepository(env.DB) }
            );
            const response = legacySuccess(await totp.complete(
                stringField(body, "temp_token"),
                stringField(body, "totp_code"),
                backendModeEnabled,
                async (user, context) => {
                    await finalizer.completeAfterTotp(user, context, settings);
                    completedPendingOAuth = true;
                }
            ));
            return completedPendingOAuth ? clearOAuthCookies(response, request) : response;
        }

        if (path === STAGED_AUTH_PATHS.refresh) {
            const limit = await consumeRateLimit(coordination, request, "refresh-token", 30);
            if (limit !== null) {
                return limit;
            }
            const body = await requiredJsonBody(request);
            const refresh = new AuthRefreshService(users, sessions, services.tokens, clock);
            return legacySuccess(await refresh.refresh(
                stringField(body, "refresh_token"),
                backendModeEnabled
            ));
        }

        const access = new AccessAuthService(users, services.verifier, services.tokens, clock);
        const authenticated = await access.authenticateAuthorization(request.headers.get("authorization"));

        if (path === STAGED_AUTH_PATHS.me) {
            const runMode = env.RUN_MODE === "simple" ? "simple" : "standard";
            return legacySuccess(await new UserProfileService(users).getProfile(
                authenticated.user,
                settings,
                runMode
            ));
        }

        if (path === STAGED_AUTH_PATHS.bindToken) {
            const response = new Response(null, { status: 204 });
            response.headers.append("set-cookie", oauthBindTokenCookie(
                bearerToken(request.headers.get("authorization")),
                request
            ));
            return response;
        }

        await access.revokeAll(authenticated.user);
        return legacySuccess({
            message: "All sessions have been revoked. Please log in again."
        });
    } catch (error) {
        return authFailure(error);
    }
}

function createTokenServices(
    env: StagedAuthEnv,
    users: D1AuthUserRepository,
    sessions: D1AuthSessionRepository,
    clock: () => number
) {
    const secret = env.JWT_SECRET?.trim() ?? "";
    if (!secret) {
        throw new AuthConfigurationError("JWT secret is not configured");
    }
    const accessLifetime = boundedIntegerEnv(
        env.JWT_ACCESS_TOKEN_EXPIRES_SECONDS,
        24 * 60 * 60,
        1,
        7 * 24 * 60 * 60
    );
    const refreshDays = boundedIntegerEnv(env.JWT_REFRESH_TOKEN_EXPIRE_DAYS, 30, 1, 365);
    const signer = new Hs256JwtSigner(secret, accessLifetime, clock);
    const verifier = new Hs256JwtVerifier(secret, clock);
    const tokens = new AuthTokenService(sessions, signer, refreshDays, clock);
    return { users, sessions, tokens, verifier };
}

function createTotpService(
    env: StagedAuthEnv,
    users: D1AuthUserRepository,
    state: D1ExpiringStateRepository,
    coordination: D1CoordinationRepository,
    tokens: AuthTokenService,
    clock: () => number
): TotpLoginService {
    let decryptor: TotpSecretDecryptor;
    try {
        decryptor = env.TOTP_ENCRYPTION_KEY?.trim()
            ? new AesGcmTotpSecretDecryptor(env.TOTP_ENCRYPTION_KEY)
            : new MissingTotpDecryptor();
    } catch {
        decryptor = new MissingTotpDecryptor();
    }
    return new TotpLoginService(users, state, coordination, tokens, decryptor, clock);
}

class MissingTotpDecryptor implements TotpSecretDecryptor {
    async decrypt(): Promise<string> {
        throw new Error("TOTP encryption key is not configured");
    }
}

class AuthConfigurationError extends Error {}

async function consumeRateLimit(
    coordination: D1CoordinationRepository,
    request: Request,
    scope: string,
    limit: number
): Promise<Response | null> {
    const result = await coordination.consumeFixedWindow({
        key: `${scope}:${clientIp(request)}`,
        limit,
        windowMs: 60_000
    });
    if (result.allowed) {
        return null;
    }
    return legacyError(
        429,
        "Too many requests, please try again later",
        "RATE_LIMIT_EXCEEDED",
        { reset_at: String(result.resetAt) }
    );
}

function clientIp(request: Request): string {
    return request.headers.get("cf-connecting-ip")?.trim() ||
        request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
        "unknown";
}

async function requiredJsonBody(request: Request): Promise<Record<string, unknown>> {
    const body = await optionalJsonBody(request);
    if (Object.keys(body).length === 0) {
        throw new RequestBodyError("Invalid request body");
    }
    return body;
}

async function optionalJsonBody(request: Request): Promise<Record<string, unknown>> {
    const text = await request.text();
    if (text.trim().length === 0) {
        return {};
    }
    if (new TextEncoder().encode(text).byteLength > 16 * 1024) {
        throw new RequestBodyError("Request body is too large");
    }
    try {
        const value: unknown = JSON.parse(text);
        if (value === null || typeof value !== "object" || Array.isArray(value)) {
            throw new RequestBodyError("Invalid request body");
        }
        return value as Record<string, unknown>;
    } catch (error) {
        if (error instanceof RequestBodyError) {
            throw error;
        }
        throw new RequestBodyError("Invalid request body");
    }
}

function stringField(body: Record<string, unknown>, key: string): string {
    const value = body[key];
    if (typeof value !== "string") {
        throw new RequestBodyError(`Invalid request: ${key} is required`);
    }
    return value;
}

class RequestBodyError extends Error {}

function authFailure(error: unknown): Response {
    if (error instanceof AccessAuthError) {
        return middlewareAuthError(error.status, error.code, error.message);
    }
    if (error instanceof PasswordAuthError) {
        return legacyError(error.status, error.message, error.code.toUpperCase());
    }
    if (error instanceof TotpAuthError) {
        return legacyError(error.status, error.message, error.code.toUpperCase());
    }
    if (error instanceof PendingOAuthFinalizationError) {
        return legacyError(error.status, error.message, error.code.toUpperCase());
    }
    if (error instanceof AuthRefreshError) {
        return legacyError(error.status, error.message, error.code);
    }
    if (error instanceof TurnstileVerificationError) {
        return legacyError(400, error.message, "TURNSTILE_VERIFICATION_FAILED");
    }
    if (error instanceof RequestBodyError) {
        return legacyError(400, error.message);
    }
    if (error instanceof AuthConfigurationError || error instanceof RangeError) {
        return legacyError(503, error instanceof Error ? error.message : "Authentication is not configured");
    }
    return legacyInternalError();
}

function clearOAuthCookies(response: Response, request: Request): Response {
    const secure = new URL(request.url).protocol === "https:";
    for (const [name, path] of OAUTH_COOKIES) {
        response.headers.append(
            "set-cookie",
            `${name}=; Path=${path}; Max-Age=0; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`
        );
    }
    return response;
}

function bearerToken(authorization: string | null): string {
    const value = authorization?.trim() ?? "";
    const match = /^Bearer\s+(.+)$/iu.exec(value);
    if (match === null || match[1].trim() === "") {
        throw new AccessAuthError("INVALID_TOKEN", "Authentication token is missing");
    }
    return match[1].trim();
}

function oauthBindTokenCookie(token: string, request: Request): string {
    const secure = new URL(request.url).protocol === "https:";
    return [
        `oauth_bind_access_token=${encodeURIComponent(token)}`,
        "Path=/api/v1/auth/oauth",
        "Max-Age=600",
        "HttpOnly",
        "SameSite=Lax",
        ...(secure ? ["Secure"] : [])
    ].join("; ");
}

async function cryptoHash(value: string): Promise<string> {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
    return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function boundedIntegerEnv(
    value: string | undefined,
    fallback: number,
    minimum: number,
    maximum: number
): number {
    if (value === undefined || value.trim() === "") {
        return fallback;
    }
    const parsed = Number(value);
    if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
        throw new AuthConfigurationError(`Authentication duration must be between ${minimum} and ${maximum}`);
    }
    return parsed;
}
