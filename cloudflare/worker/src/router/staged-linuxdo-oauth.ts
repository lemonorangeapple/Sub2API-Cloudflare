import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import { D1PendingAuthRepository } from "../repositories/pending-auth.ts";
import { D1SettingsRepository } from "../repositories/settings.ts";
import { AccessAuthService } from "../services/access-auth.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import {
    D1LinuxDoOAuthStateService,
    LinuxDoOAuthClient,
    LinuxDoOAuthError,
    resolveLinuxDoOAuthConfig,
    type LinuxDoOAuthConfig,
    type LinuxDoUserInfo
} from "../services/linuxdo-oauth.ts";
import { D1PendingAuthService, PendingAuthError } from "../services/pending-auth.ts";
import type { D1Database } from "../types/d1.ts";
import { ROUTER_RESPONSE_HEADER, legacyError, routerError } from "./responses.ts";

export const STAGED_LINUXDO_OAUTH_PATHS = {
    start: "/api/v1/auth/oauth/linuxdo/start",
    bindStart: "/api/v1/auth/oauth/linuxdo/bind/start",
    callback: "/api/v1/auth/oauth/linuxdo/callback"
} as const;

const SETTING_KEYS = [
    "backend_mode_enabled",
    "email_verify_enabled",
    "force_email_on_third_party_signup",
    "linuxdo_connect_enabled",
    "linuxdo_connect_client_id",
    "linuxdo_connect_client_secret",
    "linuxdo_connect_redirect_url"
] as const;

const OAUTH_COOKIE_PATH = "/api/v1/auth/oauth";
const PROVIDER_COOKIE_PATH = "/api/v1/auth/oauth/linuxdo";
const COOKIE_TTL_SECONDS = 10 * 60;

export interface StagedLinuxDoOAuthEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
    LINUXDO_CLIENT_ID?: string;
    LINUXDO_CLIENT_SECRET?: string;
    LINUXDO_AUTHORIZE_URL?: string;
    LINUXDO_TOKEN_URL?: string;
    LINUXDO_USERINFO_URL?: string;
    LINUXDO_SCOPES?: string;
    LINUXDO_REDIRECT_URL?: string;
    LINUXDO_FRONTEND_REDIRECT_URL?: string;
    LINUXDO_TOKEN_AUTH_METHOD?: string;
    LINUXDO_USE_PKCE?: string;
    LINUXDO_USERINFO_EMAIL_PATH?: string;
    LINUXDO_USERINFO_ID_PATH?: string;
    LINUXDO_USERINFO_USERNAME_PATH?: string;
}

export interface StagedLinuxDoOAuthDependencies {
    clock?: () => number;
    fetchImplementation?: typeof fetch;
    opaqueTokenFactory?: () => string;
}

export async function routeStagedLinuxDoOAuth(
    request: Request,
    env: StagedLinuxDoOAuthEnv,
    dependencies: StagedLinuxDoOAuthDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    if (!Object.values(STAGED_LINUXDO_OAUTH_PATHS).includes(
        path as typeof STAGED_LINUXDO_OAUTH_PATHS[keyof typeof STAGED_LINUXDO_OAUTH_PATHS]
    )) {
        return null;
    }
    if (request.method !== "GET") {
        return routerError(405, "method_not_allowed", `${path} requires GET`, { allow: "GET" });
    }
    if (env.DB === undefined) {
        return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");
    }
    const boundEnv = { ...env, DB: env.DB };

    const clock = dependencies.clock ?? Date.now;
    const settings = await new D1SettingsRepository(boundEnv.DB).getMany(SETTING_KEYS);
    let config: LinuxDoOAuthConfig;
    try {
        config = resolveLinuxDoOAuthConfig(settings, oauthEnv(env));
        if (path === STAGED_LINUXDO_OAUTH_PATHS.callback) {
            return await callback(request, boundEnv, config, settings, dependencies, clock);
        }
        return await start(
            request,
            boundEnv,
            config,
            path === STAGED_LINUXDO_OAUTH_PATHS.bindStart,
            dependencies,
            clock
        );
    } catch (error) {
        return linuxDoFailure(error);
    }
}

async function start(
    request: Request,
    env: StagedLinuxDoOAuthEnv & { DB: D1Database },
    config: LinuxDoOAuthConfig,
    binding: boolean,
    dependencies: StagedLinuxDoOAuthDependencies,
    clock: () => number
): Promise<Response> {
    let bindUserId: number | null = null;
    if (binding) {
        const rawToken = readCookie(request, "oauth_bind_access_token");
        if (rawToken === "") {
            throw new LinuxDoOAuthError("unauthorized", 401, "authentication is required for account binding");
        }
        const access = createAccessService(env, clock);
        const authenticated = await access.authenticateAuthorization(`Bearer ${rawToken}`);
        bindUserId = authenticated.user.id;
    }

    const stateService = new D1LinuxDoOAuthStateService(
        new D1ExpiringStateRepository(env.DB, { clock }),
        dependencies.opaqueTokenFactory
    );
    const url = new URL(request.url);
    const started = await stateService.create(config, {
        redirectTo: sanitizeRedirect(url.searchParams.get("redirect")),
        intent: binding ? "bind_current_user" : "login",
        bindUserId,
        promoCode: boundedText(url.searchParams.get("promo_code"), 128)
    });
    const response = redirectResponse(started.authorizeUrl);
    appendCookie(response, "linuxdo_oauth_state", started.state, PROVIDER_COOKIE_PATH, request);
    appendCookie(response, "oauth_pending_browser_session", started.browserSessionKey, OAUTH_COOKIE_PATH, request);
    clearCookie(response, "oauth_pending_session", OAUTH_COOKIE_PATH, request);
    clearCookie(response, "oauth_bind_access_token", OAUTH_COOKIE_PATH, request);
    return response;
}

async function callback(
    request: Request,
    env: StagedLinuxDoOAuthEnv & { DB: D1Database },
    config: LinuxDoOAuthConfig,
    settings: Record<string, string>,
    dependencies: StagedLinuxDoOAuthDependencies,
    clock: () => number
): Promise<Response> {
    const url = new URL(request.url);
    const frontend = absoluteFrontendUrl(config.frontendRedirectUrl, request.url);
    const providerError = url.searchParams.get("error")?.trim() ?? "";
    if (providerError !== "") {
        return callbackError(frontend, providerError, url.searchParams.get("error_description") ?? "", request);
    }
    const code = url.searchParams.get("code")?.trim() ?? "";
    const state = url.searchParams.get("state")?.trim() ?? "";
    if (code === "" || state === "") {
        return callbackError(frontend, "missing_params", "missing code/state", request);
    }
    if (readCookie(request, "linuxdo_oauth_state") !== state) {
        return callbackError(frontend, "invalid_state", "invalid oauth state", request);
    }

    const stateService = new D1LinuxDoOAuthStateService(
        new D1ExpiringStateRepository(env.DB, { clock }),
        dependencies.opaqueTokenFactory
    );
    const browserSessionKey = readCookie(request, "oauth_pending_browser_session");
    let stored;
    try {
        stored = await stateService.consume(state, browserSessionKey);
    } catch (error) {
        return callbackError(frontend, "invalid_state", errorMessage(error), request);
    }
    if (browserSessionKey !== stored.browserSessionKey) {
        return callbackError(frontend, "missing_browser_session", "missing oauth browser session", request);
    }

    let providerUser: LinuxDoUserInfo;
    try {
        providerUser = await new LinuxDoOAuthClient(dependencies.fetchImplementation).fetchUser(
            config,
            code,
            stored.codeVerifier
        );
    } catch (error) {
        const codeValue = error instanceof LinuxDoOAuthError ? error.code : "userinfo_failed";
        return callbackError(frontend, codeValue, errorMessage(error), request);
    }

    const users = new D1AuthUserRepository(env.DB);
    const identityOwner = await users.findByIdentity("linuxdo", "linuxdo", providerUser.subject);
    const compatOwner = identityOwner === null ? await findCompatOwner(users, providerUser.compatEmail) : null;
    const targetUserId = stored.intent === "bind_current_user"
        ? stored.bindUserId
        : identityOwner?.id ?? compatOwner?.id ?? null;
    if (stored.intent === "bind_current_user" && targetUserId === null) {
        return callbackError(frontend, "invalid_state", "invalid oauth bind target", request);
    }

    const completionResponse = buildCompletionResponse(
        stored.redirectTo,
        providerUser,
        identityOwner !== null,
        compatOwner?.email ?? "",
        settings
    );
    const pending = await new D1PendingAuthService(
        new D1PendingAuthRepository(env.DB),
        { clock, opaqueTokenFactory: dependencies.opaqueTokenFactory }
    ).create({
        intent: stored.intent,
        providerType: "linuxdo",
        providerKey: "linuxdo",
        providerSubject: providerUser.subject,
        ...(targetUserId === null ? {} : { targetUserId }),
        redirectTo: stored.redirectTo,
        resolvedEmail: compatOwner?.email ?? providerUser.email,
        browserSessionKey: stored.browserSessionKey,
        upstreamIdentityClaims: {
            email: providerUser.email,
            username: providerUser.username,
            subject: providerUser.subject,
            suggested_display_name: providerUser.displayName,
            suggested_avatar_url: providerUser.avatarUrl,
            ...(providerUser.compatEmail === "" ? {} : { compat_email: providerUser.compatEmail })
        },
        localFlowState: {
            completion_response: completionResponse,
            ...(stored.promoCode === "" ? {} : { promo_code: stored.promoCode })
        }
    });

    const response = redirectResponse(frontend);
    appendCookie(response, "oauth_pending_session", pending.sessionToken, OAUTH_COOKIE_PATH, request);
    appendCookie(response, "oauth_pending_browser_session", stored.browserSessionKey, OAUTH_COOKIE_PATH, request);
    clearCookie(response, "linuxdo_oauth_state", PROVIDER_COOKIE_PATH, request);
    return response;
}

function buildCompletionResponse(
    redirect: string,
    user: LinuxDoUserInfo,
    identityExists: boolean,
    compatEmail: string,
    settings: Record<string, string>
): Record<string, unknown> {
    const profile = {
        redirect,
        suggested_display_name: user.displayName,
        suggested_avatar_url: user.avatarUrl
    };
    if (identityExists) return profile;
    const forceEmail = settings.force_email_on_third_party_signup === "true";
    const verifyEmail = settings.email_verify_enabled === "true";
    const response: Record<string, unknown> = {
        ...profile,
        step: "choose_account_action_required",
        adoption_required: true,
        email: compatEmail || user.email,
        resolved_email: compatEmail || user.email,
        existing_account_email: compatEmail,
        existing_account_bindable: compatEmail !== "",
        create_account_allowed: true,
        force_email_on_signup: forceEmail,
        choice_reason: compatEmail !== "" ? "compat_email_match" : "third_party_signup"
    };
    if ((forceEmail || verifyEmail) && compatEmail === "") {
        response.step = "create_account_required";
        response.email_binding_required = true;
        response.force_email_on_signup = true;
        response.choice_reason = verifyEmail ? "email_verification_required" : "force_email_on_signup";
        delete response.email;
        delete response.resolved_email;
    }
    return response;
}

async function findCompatOwner(users: D1AuthUserRepository, emailValue: string) {
    const email = emailValue.trim().toLowerCase();
    if (email === "" || email.endsWith("@linuxdo-connect.invalid") || !/^[^\s@]+@[^\s@]+$/u.test(email)) {
        return null;
    }
    return users.findByEmail(email);
}

function createAccessService(env: StagedLinuxDoOAuthEnv & { DB: D1Database }, clock: () => number) {
    const secret = env.JWT_SECRET?.trim() ?? "";
    if (secret === "") throw new LinuxDoOAuthError("oauth_config_invalid", 503, "JWT secret is not configured");
    const users = new D1AuthUserRepository(env.DB);
    const sessions = new D1AuthSessionRepository(env.DB);
    const accessSeconds = boundedInteger(env.JWT_ACCESS_TOKEN_EXPIRES_SECONDS, 24 * 60 * 60, 1, 604800);
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
    clearCookie(response, "linuxdo_oauth_state", PROVIDER_COOKIE_PATH, request);
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
    const secure = new URL(request.url).protocol === "https:";
    response.headers.append("set-cookie", [
        `${name}=${encodeURIComponent(value)}`,
        `Path=${path}`,
        `Max-Age=${COOKIE_TTL_SECONDS}`,
        "HttpOnly",
        "SameSite=Lax",
        ...(secure ? ["Secure"] : [])
    ].join("; "));
}

function clearCookie(response: Response, name: string, path: string, request: Request): void {
    const secure = new URL(request.url).protocol === "https:";
    response.headers.append("set-cookie", [
        `${name}=`, `Path=${path}`, "Max-Age=0", "HttpOnly", "SameSite=Lax",
        ...(secure ? ["Secure"] : [])
    ].join("; "));
}

function readCookie(request: Request, name: string): string {
    const raw = request.headers.get("cookie") ?? "";
    for (const entry of raw.split(";")) {
        const separator = entry.indexOf("=");
        if (separator < 0 || entry.slice(0, separator).trim() !== name) continue;
        try { return decodeURIComponent(entry.slice(separator + 1).trim()); } catch { return ""; }
    }
    return "";
}

function sanitizeRedirect(value: string | null): string {
    const redirect = value?.trim() ?? "";
    if (redirect === "" || redirect.length > 2048 || !redirect.startsWith("/") || redirect.startsWith("//")) {
        return "/dashboard";
    }
    return redirect;
}

function absoluteFrontendUrl(value: string, base: string): string {
    return new URL(value, base).toString();
}

function boundedText(value: string | null | undefined, maximum: number): string {
    return (value ?? "").trim().slice(0, maximum);
}

function boundedInteger(raw: string | undefined, fallback: number, minimum: number, maximum: number): number {
    if (raw === undefined || raw.trim() === "") return fallback;
    const value = Number(raw);
    if (!Number.isInteger(value) || value < minimum || value > maximum) {
        throw new LinuxDoOAuthError("oauth_config_invalid", 503, "authentication duration is invalid");
    }
    return value;
}

function oauthEnv(env: StagedLinuxDoOAuthEnv): Record<string, string | undefined> {
    return {
        LINUXDO_CLIENT_ID: env.LINUXDO_CLIENT_ID,
        LINUXDO_CLIENT_SECRET: env.LINUXDO_CLIENT_SECRET,
        LINUXDO_AUTHORIZE_URL: env.LINUXDO_AUTHORIZE_URL,
        LINUXDO_TOKEN_URL: env.LINUXDO_TOKEN_URL,
        LINUXDO_USERINFO_URL: env.LINUXDO_USERINFO_URL,
        LINUXDO_SCOPES: env.LINUXDO_SCOPES,
        LINUXDO_REDIRECT_URL: env.LINUXDO_REDIRECT_URL,
        LINUXDO_FRONTEND_REDIRECT_URL: env.LINUXDO_FRONTEND_REDIRECT_URL,
        LINUXDO_TOKEN_AUTH_METHOD: env.LINUXDO_TOKEN_AUTH_METHOD,
        LINUXDO_USE_PKCE: env.LINUXDO_USE_PKCE,
        LINUXDO_USERINFO_EMAIL_PATH: env.LINUXDO_USERINFO_EMAIL_PATH,
        LINUXDO_USERINFO_ID_PATH: env.LINUXDO_USERINFO_ID_PATH,
        LINUXDO_USERINFO_USERNAME_PATH: env.LINUXDO_USERINFO_USERNAME_PATH
    };
}

function linuxDoFailure(error: unknown): Response {
    if (error instanceof LinuxDoOAuthError || error instanceof PendingAuthError) {
        return legacyError(error.status, error.message, error.code.toUpperCase());
    }
    if (error instanceof Error && error.name === "AccessAuthError") {
        return legacyError(401, error.message, "UNAUTHORIZED");
    }
    console.error("staged linuxdo oauth failed", error);
    return legacyError(500, "internal server error");
}

function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : "oauth request failed";
}
