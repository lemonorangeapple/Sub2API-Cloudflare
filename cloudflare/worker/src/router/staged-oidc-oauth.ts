import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import { D1PendingAuthRepository } from "../repositories/pending-auth.ts";
import { D1SettingsRepository } from "../repositories/settings.ts";
import { AccessAuthService } from "../services/access-auth.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import {
    D1OIDCOAuthStateService,
    OIDCOAuthClient,
    OIDCOAuthError,
    resolveOIDCOAuthConfig,
    type OIDCOAuthConfig,
    type OIDCProviderUser
} from "../services/oidc-oauth.ts";
import { D1PendingAuthService } from "../services/pending-auth.ts";
import type { D1Database } from "../types/d1.ts";
import { ROUTER_RESPONSE_HEADER, legacyError, routerError } from "./responses.ts";
import {
    createPendingOAuthFinalizationService,
    STAGED_PENDING_OAUTH_SETTING_KEYS,
    type StagedPendingOAuthDependencies,
    type StagedPendingOAuthEnv
} from "./staged-pending-oauth.ts";

export const STAGED_OIDC_OAUTH_PATHS = {
    start: "/api/v1/auth/oauth/oidc/start",
    bindStart: "/api/v1/auth/oauth/oidc/bind/start",
    callback: "/api/v1/auth/oauth/oidc/callback"
} as const;

const SETTING_KEYS = [
    ...STAGED_PENDING_OAUTH_SETTING_KEYS,
    "email_verify_enabled",
    "force_email_on_third_party_signup",
    "oidc_connect_enabled",
    "oidc_connect_provider_name",
    "oidc_connect_client_id",
    "oidc_connect_client_secret",
    "oidc_connect_issuer_url",
    "oidc_connect_discovery_url",
    "oidc_connect_authorize_url",
    "oidc_connect_token_url",
    "oidc_connect_userinfo_url",
    "oidc_connect_jwks_url",
    "oidc_connect_scopes",
    "oidc_connect_redirect_url",
    "oidc_connect_frontend_redirect_url",
    "oidc_connect_token_auth_method",
    "oidc_connect_use_pkce",
    "oidc_connect_validate_id_token",
    "oidc_connect_allowed_signing_algs",
    "oidc_connect_clock_skew_seconds",
    "oidc_connect_require_email_verified",
    "oidc_connect_userinfo_email_path",
    "oidc_connect_userinfo_id_path",
    "oidc_connect_userinfo_username_path"
] as const;

const OAUTH_COOKIE_PATH = "/api/v1/auth/oauth";
const PROVIDER_COOKIE_PATH = "/api/v1/auth/oauth/oidc";
const COOKIE_TTL_SECONDS = 10 * 60;
const RESERVED_EMAIL_SUFFIXES = [
    "@linuxdo-connect.invalid",
    "@oidc-connect.invalid",
    "@wechat-connect.invalid",
    "@dingtalk-connect.invalid"
] as const;

export interface StagedOIDCOAuthEnv extends StagedPendingOAuthEnv {
    OIDC_ENABLED?: string;
    OIDC_PROVIDER_NAME?: string;
    OIDC_CLIENT_ID?: string;
    OIDC_CLIENT_SECRET?: string;
    OIDC_ISSUER_URL?: string;
    OIDC_DISCOVERY_URL?: string;
    OIDC_AUTHORIZE_URL?: string;
    OIDC_TOKEN_URL?: string;
    OIDC_USERINFO_URL?: string;
    OIDC_JWKS_URL?: string;
    OIDC_SCOPES?: string;
    OIDC_REDIRECT_URL?: string;
    OIDC_FRONTEND_REDIRECT_URL?: string;
    OIDC_TOKEN_AUTH_METHOD?: string;
    OIDC_USE_PKCE?: string;
    OIDC_VALIDATE_ID_TOKEN?: string;
    OIDC_ALLOWED_SIGNING_ALGS?: string;
    OIDC_CLOCK_SKEW_SECONDS?: string;
    OIDC_REQUIRE_EMAIL_VERIFIED?: string;
    OIDC_USERINFO_EMAIL_PATH?: string;
    OIDC_USERINFO_ID_PATH?: string;
    OIDC_USERINFO_USERNAME_PATH?: string;
}

export interface StagedOIDCOAuthDependencies extends StagedPendingOAuthDependencies {
    opaqueTokenFactory?: () => string;
}

export async function routeStagedOIDCOAuth(
    request: Request,
    env: StagedOIDCOAuthEnv,
    dependencies: StagedOIDCOAuthDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    if (!Object.values(STAGED_OIDC_OAUTH_PATHS).includes(
        path as typeof STAGED_OIDC_OAUTH_PATHS[keyof typeof STAGED_OIDC_OAUTH_PATHS]
    )) return null;
    if (request.method !== "GET") {
        return routerError(405, "method_not_allowed", `${path} requires GET`, { allow: "GET" });
    }
    if (env.DB === undefined) {
        return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");
    }
    const boundEnv = { ...env, DB: env.DB };
    const clock = dependencies.clock ?? Date.now;
    try {
        const settings = await new D1SettingsRepository(env.DB).getMany(SETTING_KEYS);
        const config = await resolveOIDCOAuthConfig(
            settings,
            oidcEnv(env),
            dependencies.fetchImplementation
        );
        if (path === STAGED_OIDC_OAUTH_PATHS.callback) {
            return callback(request, boundEnv, config, settings, dependencies, clock);
        }
        return start(
            request,
            boundEnv,
            config,
            path === STAGED_OIDC_OAUTH_PATHS.bindStart,
            dependencies,
            clock
        );
    } catch (error) {
        return oidcFailure(error);
    }
}

async function start(
    request: Request,
    env: StagedOIDCOAuthEnv & { DB: D1Database },
    config: OIDCOAuthConfig,
    binding: boolean,
    dependencies: StagedOIDCOAuthDependencies,
    clock: () => number
): Promise<Response> {
    let bindUserId: number | null = null;
    if (binding) {
        const rawToken = readCookie(request, "oauth_bind_access_token");
        if (rawToken === "") throw new OIDCOAuthError("unauthorized", 401, "authentication is required");
        bindUserId = (await createAccessService(env, clock)
            .authenticateAuthorization(`Bearer ${rawToken}`)).user.id;
    }
    const url = new URL(request.url);
    const started = await new D1OIDCOAuthStateService(
        new D1ExpiringStateRepository(env.DB, { clock }),
        dependencies.opaqueTokenFactory
    ).create(config, {
        redirectTo: sanitizeRedirect(url.searchParams.get("redirect")),
        intent: binding ? "bind_current_user" : "login",
        bindUserId,
        promoCode: boundedText(url.searchParams.get("promo_code"), 128)
    });
    const response = redirectResponse(started.authorizeUrl);
    appendCookie(response, "oidc_oauth_state", started.state, PROVIDER_COOKIE_PATH, request);
    appendCookie(response, "oauth_pending_browser_session", started.browserSessionKey, OAUTH_COOKIE_PATH, request);
    clearCookie(response, "oauth_pending_session", OAUTH_COOKIE_PATH, request);
    clearCookie(response, "oauth_bind_access_token", OAUTH_COOKIE_PATH, request);
    return response;
}

async function callback(
    request: Request,
    env: StagedOIDCOAuthEnv & { DB: D1Database },
    config: OIDCOAuthConfig,
    settings: Record<string, string>,
    dependencies: StagedOIDCOAuthDependencies,
    clock: () => number
): Promise<Response> {
    const url = new URL(request.url);
    const frontend = new URL(config.frontendRedirectUrl, request.url).toString();
    const providerError = url.searchParams.get("error")?.trim() ?? "";
    if (providerError !== "") {
        return callbackError(frontend, providerError, url.searchParams.get("error_description") ?? "", request);
    }
    const code = url.searchParams.get("code")?.trim() ?? "";
    const state = url.searchParams.get("state")?.trim() ?? "";
    if (code === "" || state === "" || readCookie(request, "oidc_oauth_state") !== state) {
        return callbackError(frontend, "invalid_state", "invalid oauth state", request);
    }
    const browserSessionKey = readCookie(request, "oauth_pending_browser_session");
    let stored;
    try {
        stored = await new D1OIDCOAuthStateService(
            new D1ExpiringStateRepository(env.DB, { clock }),
            dependencies.opaqueTokenFactory
        ).consume(state, browserSessionKey);
    } catch (error) {
        return callbackError(frontend, "invalid_state", errorMessage(error), request);
    }
    if (browserSessionKey !== stored.browserSessionKey) {
        return callbackError(frontend, "missing_browser_session", "missing oauth browser session", request);
    }

    let providerUser: OIDCProviderUser;
    try {
        providerUser = await new OIDCOAuthClient(
            dependencies.fetchImplementation,
            clock
        ).fetchUser(config, code, stored);
    } catch (error) {
        return callbackError(
            frontend,
            error instanceof OIDCOAuthError ? error.code : "userinfo_failed",
            errorMessage(error),
            request
        );
    }

    const users = new D1AuthUserRepository(env.DB);
    const identityOwner = await users.findByIdentity("oidc", providerUser.issuer, providerUser.subject);
    const compatOwner = identityOwner === null
        ? await findCompatOwner(users, providerUser.compatEmail)
        : null;
    const targetUserId = stored.intent === "bind_current_user"
        ? stored.bindUserId
        : identityOwner?.id ?? compatOwner?.id ?? null;
    if (stored.intent === "bind_current_user" && targetUserId === null) {
        return callbackError(frontend, "invalid_state", "invalid oauth bind target", request);
    }
    const completion = completionResponse(
        stored.redirectTo,
        providerUser,
        identityOwner !== null,
        compatOwner?.email ?? "",
        settings
    );
    const verifiedEmail = usableCompatEmail(providerUser.compatEmail);
    const fastPath = stored.intent === "login"
        && identityOwner === null
        && compatOwner === null
        && verifiedEmail !== ""
        && providerUser.emailVerified === true
        && settings.force_email_on_third_party_signup !== "true"
        && settings.invitation_code_enabled !== "true";
    if (fastPath && settings.backend_mode_enabled === "true") {
        return callbackError(
            frontend,
            "login_blocked",
            "Backend mode is active. Only admin login is allowed.",
            request
        );
    }
    const pendingService = new D1PendingAuthService(
        new D1PendingAuthRepository(env.DB),
        { clock, opaqueTokenFactory: dependencies.opaqueTokenFactory }
    );
    const pending = await pendingService.create({
        intent: stored.intent,
        providerType: "oidc",
        providerKey: providerUser.issuer,
        providerSubject: providerUser.subject,
        ...(targetUserId === null ? {} : { targetUserId }),
        redirectTo: stored.redirectTo,
        resolvedEmail: compatOwner?.email ?? providerUser.syntheticEmail,
        browserSessionKey: stored.browserSessionKey,
        upstreamIdentityClaims: {
            email: providerUser.syntheticEmail,
            username: providerUser.username,
            subject: providerUser.subject,
            issuer: providerUser.issuer,
            email_verified: providerUser.emailVerified === true,
            provider_fallback: config.providerName,
            suggested_display_name: providerUser.displayName,
            suggested_avatar_url: providerUser.avatarUrl,
            ...(providerUser.compatEmail === "" ? {} : { compat_email: providerUser.compatEmail })
        },
        localFlowState: {
            completion_response: completion,
            ...(stored.promoCode === "" ? {} : { promo_code: stored.promoCode })
        }
    });
    if (fastPath) {
        try {
            const payload = await createPendingOAuthFinalizationService(
                env.DB,
                env,
                dependencies,
                clock
            ).createAccount(
                pending.sessionToken,
                stored.browserSessionKey,
                {
                    email: verifiedEmail,
                    adoption: { adoptDisplayName: true, adoptAvatar: true }
                },
                settings,
                "oidc",
                "verified_provider_email"
            );
            return completedCallbackResponse(frontend, stored.redirectTo, payload, request);
        } catch {
            // Match the legacy contract: a fast-path registration failure falls back to account choice.
        }
    }
    const response = redirectResponse(frontend);
    appendCookie(response, "oauth_pending_session", pending.sessionToken, OAUTH_COOKIE_PATH, request);
    appendCookie(response, "oauth_pending_browser_session", stored.browserSessionKey, OAUTH_COOKIE_PATH, request);
    clearCookie(response, "oidc_oauth_state", PROVIDER_COOKIE_PATH, request);
    return response;
}

function completedCallbackResponse(
    frontend: string,
    redirect: string,
    payload: Record<string, unknown>,
    request: Request
): Response {
    const url = new URL(frontend);
    const fragment = new URLSearchParams({ redirect });
    for (const key of ["access_token", "refresh_token", "expires_in", "token_type"]) {
        const value = payload[key];
        if (typeof value === "string" || typeof value === "number") fragment.set(key, String(value));
    }
    url.hash = fragment.toString();
    const response = redirectResponse(url.toString());
    clearCookie(response, "oidc_oauth_state", PROVIDER_COOKIE_PATH, request);
    clearCookie(response, "oauth_pending_session", OAUTH_COOKIE_PATH, request);
    clearCookie(response, "oauth_pending_browser_session", OAUTH_COOKIE_PATH, request);
    return response;
}

function completionResponse(
    redirect: string,
    user: OIDCProviderUser,
    identityExists: boolean,
    compatOwnerEmail: string,
    settings: Record<string, string>
): Record<string, unknown> {
    const profile = {
        redirect,
        suggested_display_name: user.displayName,
        suggested_avatar_url: user.avatarUrl
    };
    if (identityExists) return profile;
    const forceEmail = settings.force_email_on_third_party_signup === "true";
    const response: Record<string, unknown> = {
        ...profile,
        step: "choose_account_action_required",
        adoption_required: true,
        email: compatOwnerEmail || user.syntheticEmail,
        resolved_email: compatOwnerEmail || user.syntheticEmail,
        existing_account_email: compatOwnerEmail,
        existing_account_bindable: compatOwnerEmail !== "",
        create_account_allowed: true,
        force_email_on_signup: forceEmail,
        choice_reason: compatOwnerEmail !== "" ? "compat_email_match" : "third_party_signup"
    };
    if ((forceEmail || settings.email_verify_enabled === "true") && compatOwnerEmail === "") {
        response.step = "create_account_required";
        response.email_binding_required = true;
        response.force_email_on_signup = true;
        response.choice_reason = settings.email_verify_enabled === "true"
            ? "email_verification_required"
            : "force_email_on_signup";
        delete response.email;
        delete response.resolved_email;
    }
    return response;
}

async function findCompatOwner(users: D1AuthUserRepository, emailValue: string) {
    const email = usableCompatEmail(emailValue);
    if (email === "") return null;
    return users.findByEmail(email);
}

function usableCompatEmail(emailValue: string): string {
    const email = emailValue.trim().toLowerCase();
    return email !== "" && /^[^\s@]+@[^\s@]+$/u.test(email)
        && !RESERVED_EMAIL_SUFFIXES.some((suffix) => email.endsWith(suffix))
        ? email
        : "";
}

function createAccessService(env: StagedOIDCOAuthEnv & { DB: D1Database }, clock: () => number) {
    const secret = env.JWT_SECRET?.trim() ?? "";
    if (secret === "") throw new OIDCOAuthError("oauth_config_invalid", 503, "JWT secret is not configured");
    const users = new D1AuthUserRepository(env.DB);
    const sessions = new D1AuthSessionRepository(env.DB);
    const accessSeconds = boundedInteger(env.JWT_ACCESS_TOKEN_EXPIRES_SECONDS, 86400, 1, 604800);
    const refreshDays = boundedInteger(env.JWT_REFRESH_TOKEN_EXPIRE_DAYS, 30, 1, 365);
    const tokens = new AuthTokenService(sessions, new Hs256JwtSigner(secret, accessSeconds, clock), refreshDays, clock);
    return new AccessAuthService(users, new Hs256JwtVerifier(secret, clock), tokens, clock);
}

function callbackError(frontend: string, code: string, message: string, request: Request): Response {
    const url = new URL(frontend);
    const fragment = new URLSearchParams({ error: boundedText(code, 128) || "oauth_error" });
    if (message.trim() !== "") fragment.set("error_message", boundedText(message, 512));
    url.hash = fragment.toString();
    const response = redirectResponse(url.toString());
    clearCookie(response, "oidc_oauth_state", PROVIDER_COOKIE_PATH, request);
    clearCookie(response, "oauth_pending_session", OAUTH_COOKIE_PATH, request);
    clearCookie(response, "oauth_pending_browser_session", OAUTH_COOKIE_PATH, request);
    return response;
}

function redirectResponse(location: string): Response {
    return new Response(null, {
        status: 302,
        headers: {
            "cache-control": "no-store",
            location,
            pragma: "no-cache",
            [ROUTER_RESPONSE_HEADER]: "sub2api-router",
            "x-content-type-options": "nosniff"
        }
    });
}

function appendCookie(response: Response, name: string, value: string, path: string, request: Request): void {
    response.headers.append("set-cookie", [
        `${name}=${encodeURIComponent(value)}`,
        `Path=${path}`,
        `Max-Age=${COOKIE_TTL_SECONDS}`,
        "HttpOnly",
        "SameSite=Lax",
        ...(new URL(request.url).protocol === "https:" ? ["Secure"] : [])
    ].join("; "));
}

function clearCookie(response: Response, name: string, path: string, request: Request): void {
    response.headers.append("set-cookie", [
        `${name}=`, `Path=${path}`, "Max-Age=0", "HttpOnly", "SameSite=Lax",
        ...(new URL(request.url).protocol === "https:" ? ["Secure"] : [])
    ].join("; "));
}

function readCookie(request: Request, name: string): string {
    for (const entry of (request.headers.get("cookie") ?? "").split(";")) {
        const separator = entry.indexOf("=");
        if (separator < 0 || entry.slice(0, separator).trim() !== name) continue;
        try { return decodeURIComponent(entry.slice(separator + 1).trim()); } catch { return ""; }
    }
    return "";
}

function sanitizeRedirect(value: string | null): string {
    const redirect = value?.trim() ?? "";
    return redirect !== "" && redirect.length <= 2048 && redirect.startsWith("/") && !redirect.startsWith("//")
        ? redirect
        : "/dashboard";
}

function boundedText(value: string | null | undefined, maximum: number): string {
    return (value ?? "").trim().slice(0, maximum);
}

function boundedInteger(raw: string | undefined, fallback: number, minimum: number, maximum: number): number {
    if (raw === undefined || raw.trim() === "") return fallback;
    const value = Number(raw);
    if (!Number.isInteger(value) || value < minimum || value > maximum) {
        throw new OIDCOAuthError("oauth_config_invalid", 503, "authentication duration is invalid");
    }
    return value;
}

function oidcEnv(env: StagedOIDCOAuthEnv): Record<string, string | undefined> {
    return {
        OIDC_ENABLED: env.OIDC_ENABLED,
        OIDC_PROVIDER_NAME: env.OIDC_PROVIDER_NAME,
        OIDC_CLIENT_ID: env.OIDC_CLIENT_ID,
        OIDC_CLIENT_SECRET: env.OIDC_CLIENT_SECRET,
        OIDC_ISSUER_URL: env.OIDC_ISSUER_URL,
        OIDC_DISCOVERY_URL: env.OIDC_DISCOVERY_URL,
        OIDC_AUTHORIZE_URL: env.OIDC_AUTHORIZE_URL,
        OIDC_TOKEN_URL: env.OIDC_TOKEN_URL,
        OIDC_USERINFO_URL: env.OIDC_USERINFO_URL,
        OIDC_JWKS_URL: env.OIDC_JWKS_URL,
        OIDC_SCOPES: env.OIDC_SCOPES,
        OIDC_REDIRECT_URL: env.OIDC_REDIRECT_URL,
        OIDC_FRONTEND_REDIRECT_URL: env.OIDC_FRONTEND_REDIRECT_URL,
        OIDC_TOKEN_AUTH_METHOD: env.OIDC_TOKEN_AUTH_METHOD,
        OIDC_USE_PKCE: env.OIDC_USE_PKCE,
        OIDC_VALIDATE_ID_TOKEN: env.OIDC_VALIDATE_ID_TOKEN,
        OIDC_ALLOWED_SIGNING_ALGS: env.OIDC_ALLOWED_SIGNING_ALGS,
        OIDC_CLOCK_SKEW_SECONDS: env.OIDC_CLOCK_SKEW_SECONDS,
        OIDC_REQUIRE_EMAIL_VERIFIED: env.OIDC_REQUIRE_EMAIL_VERIFIED,
        OIDC_USERINFO_EMAIL_PATH: env.OIDC_USERINFO_EMAIL_PATH,
        OIDC_USERINFO_ID_PATH: env.OIDC_USERINFO_ID_PATH,
        OIDC_USERINFO_USERNAME_PATH: env.OIDC_USERINFO_USERNAME_PATH
    };
}

function oidcFailure(error: unknown): Response {
    if (error instanceof OIDCOAuthError) return legacyError(error.status, error.message, error.code.toUpperCase());
    return legacyError(500, "OIDC OAuth request failed", "OAUTH_INTERNAL_ERROR");
}

function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : "oauth request failed";
}
