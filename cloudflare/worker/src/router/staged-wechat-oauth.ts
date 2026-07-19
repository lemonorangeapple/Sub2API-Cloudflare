import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import { D1PendingAuthRepository } from "../repositories/pending-auth.ts";
import { D1SettingsRepository } from "../repositories/settings.ts";
import { AccessAuthService } from "../services/access-auth.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import { D1PendingAuthService } from "../services/pending-auth.ts";
import {
    buildWeChatAuthorizeUrl,
    D1WeChatOAuthStateService,
    WeChatOAuthClient,
    WeChatOAuthError,
    resolveWeChatMode,
    resolveWeChatOAuthConfig,
    type WeChatOAuthConfig,
    type WeChatOAuthIdentity
} from "../services/wechat-oauth.ts";
import {
    D1WeChatPaymentOAuthStateService,
    WeChatPaymentOAuthError,
    WeChatPaymentResumeService,
    normalizePaymentRedirect,
    normalizePaymentScope,
    normalizePaymentType,
    parsePaymentPlanId,
    resolvePaymentResumeKeys
} from "../services/wechat-payment-oauth.ts";
import type { D1Database } from "../types/d1.ts";
import { ROUTER_RESPONSE_HEADER, legacyError, routerError } from "./responses.ts";
import {
    STAGED_PENDING_OAUTH_SETTING_KEYS,
    type StagedPendingOAuthDependencies,
    type StagedPendingOAuthEnv
} from "./staged-pending-oauth.ts";

export const STAGED_WECHAT_OAUTH_PATHS = {
    start: "/api/v1/auth/oauth/wechat/start",
    bindStart: "/api/v1/auth/oauth/wechat/bind/start",
    callback: "/api/v1/auth/oauth/wechat/callback",
    paymentStart: "/api/v1/auth/oauth/wechat/payment/start",
    paymentCallback: "/api/v1/auth/oauth/wechat/payment/callback"
} as const;

const SETTING_KEYS = [
    ...STAGED_PENDING_OAUTH_SETTING_KEYS,
    "email_verify_enabled",
    "force_email_on_third_party_signup",
    "wechat_connect_enabled",
    "wechat_connect_app_id",
    "wechat_connect_app_secret",
    "wechat_connect_open_app_id",
    "wechat_connect_open_app_secret",
    "wechat_connect_mp_app_id",
    "wechat_connect_mp_app_secret",
    "wechat_connect_open_enabled",
    "wechat_connect_mp_enabled",
    "wechat_connect_mode",
    "wechat_connect_scopes",
    "wechat_connect_redirect_url",
    "wechat_connect_frontend_redirect_url"
] as const;

const OAUTH_COOKIE_PATH = "/api/v1/auth/oauth";
const PROVIDER_COOKIE_PATH = "/api/v1/auth/oauth/wechat";
const PAYMENT_COOKIE_PATH = "/api/v1/auth/oauth/wechat/payment";
const COOKIE_TTL_SECONDS = 10 * 60;
const PROVIDER_KEY = "wechat-main";

export interface StagedWeChatOAuthEnv extends StagedPendingOAuthEnv {
    WECHAT_CONNECT_ENABLED?: string;
    WECHAT_CONNECT_APP_ID?: string;
    WECHAT_CONNECT_APP_SECRET?: string;
    WECHAT_CONNECT_OPEN_APP_ID?: string;
    WECHAT_CONNECT_OPEN_APP_SECRET?: string;
    WECHAT_CONNECT_MP_APP_ID?: string;
    WECHAT_CONNECT_MP_APP_SECRET?: string;
    WECHAT_CONNECT_OPEN_ENABLED?: string;
    WECHAT_CONNECT_MP_ENABLED?: string;
    WECHAT_CONNECT_SCOPES?: string;
    WECHAT_CONNECT_REDIRECT_URL?: string;
    WECHAT_CONNECT_FRONTEND_REDIRECT_URL?: string;
    WECHAT_CONNECT_OPEN_AUTHORIZE_URL?: string;
    WECHAT_CONNECT_MP_AUTHORIZE_URL?: string;
    WECHAT_CONNECT_TOKEN_URL?: string;
    WECHAT_CONNECT_USERINFO_URL?: string;
    WECHAT_PAYMENT_FRONTEND_REDIRECT_URL?: string;
    PAYMENT_RESUME_SIGNING_KEY?: string;
    TOTP_ENCRYPTION_KEY?: string;
}

export interface StagedWeChatOAuthDependencies extends StagedPendingOAuthDependencies {
    opaqueTokenFactory?: () => string;
}

export async function routeStagedWeChatOAuth(
    request: Request,
    env: StagedWeChatOAuthEnv,
    dependencies: StagedWeChatOAuthDependencies = {}
): Promise<Response | null> {
    const path = new URL(request.url).pathname;
    if (!Object.values(STAGED_WECHAT_OAUTH_PATHS).includes(
        path as typeof STAGED_WECHAT_OAUTH_PATHS[keyof typeof STAGED_WECHAT_OAUTH_PATHS]
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
        if (path === STAGED_WECHAT_OAUTH_PATHS.paymentCallback) {
            return paymentCallback(request, boundEnv, settings, dependencies, clock);
        }
        if (path === STAGED_WECHAT_OAUTH_PATHS.paymentStart) {
            return paymentStart(request, boundEnv, settings, dependencies, clock);
        }
        if (path === STAGED_WECHAT_OAUTH_PATHS.callback) {
            return callback(request, boundEnv, settings, dependencies, clock);
        }
        return start(
            request,
            boundEnv,
            settings,
            path === STAGED_WECHAT_OAUTH_PATHS.bindStart,
            dependencies,
            clock
        );
    } catch (error) {
        return wechatFailure(error);
    }
}

async function paymentStart(
    request: Request,
    env: StagedWeChatOAuthEnv & { DB: D1Database },
    settings: Record<string, string>,
    dependencies: StagedWeChatOAuthDependencies,
    clock: () => number
): Promise<Response> {
    const url = new URL(request.url);
    const callbackUrl = `${url.origin}${STAGED_WECHAT_OAUTH_PATHS.paymentCallback}`;
    const baseConfig = resolveWeChatOAuthConfig("mp", settings, wechatEnv(env), callbackUrl);
    const scope = normalizePaymentScope(url.searchParams.get("scope") ?? "");
    const config: WeChatOAuthConfig = { ...baseConfig, redirectUrl: callbackUrl, scope };
    const paymentTypeValue = url.searchParams.get("payment_type") ?? "";
    normalizePaymentType(paymentTypeValue);
    const started = await new D1WeChatPaymentOAuthStateService(
        new D1ExpiringStateRepository(env.DB, { clock }),
        dependencies.opaqueTokenFactory
    ).create({
        paymentType: paymentTypeValue.trim() as "wxpay" | "wxpay_direct",
        amount: boundedText(url.searchParams.get("amount"), 64),
        orderType: boundedText(url.searchParams.get("order_type"), 64),
        planId: parsePaymentPlanId(url.searchParams.get("plan_id") ?? ""),
        redirectTo: normalizePaymentRedirect(url.searchParams.get("redirect") ?? ""),
        scope
    });
    const response = redirectResponse(buildWeChatAuthorizeUrl(config, started.state));
    appendCookie(response, "wechat_payment_oauth_state", started.state, PAYMENT_COOKIE_PATH, request);
    appendCookie(
        response,
        "wechat_payment_oauth_browser",
        started.browserSessionKey,
        PAYMENT_COOKIE_PATH,
        request
    );
    return response;
}

async function paymentCallback(
    request: Request,
    env: StagedWeChatOAuthEnv & { DB: D1Database },
    settings: Record<string, string>,
    dependencies: StagedWeChatOAuthDependencies,
    clock: () => number
): Promise<Response> {
    const url = new URL(request.url);
    const frontend = new URL(
        env.WECHAT_PAYMENT_FRONTEND_REDIRECT_URL?.trim() || "/auth/wechat/payment/callback",
        request.url
    ).toString();
    const providerError = url.searchParams.get("error")?.trim()
        || url.searchParams.get("errcode")?.trim() || "";
    if (providerError !== "") {
        return paymentCallbackError(frontend, providerError, url.searchParams.get("errmsg") ?? "", request);
    }
    const code = url.searchParams.get("code")?.trim() ?? "";
    const state = url.searchParams.get("state")?.trim() ?? "";
    if (code === "" || state === "" || readCookie(request, "wechat_payment_oauth_state") !== state) {
        return paymentCallbackError(frontend, "invalid_state", "invalid oauth state", request);
    }
    const browser = readCookie(request, "wechat_payment_oauth_browser");
    let stored;
    try {
        stored = await new D1WeChatPaymentOAuthStateService(
            new D1ExpiringStateRepository(env.DB, { clock }),
            dependencies.opaqueTokenFactory
        ).consume(state, browser);
    } catch (error) {
        return paymentCallbackError(frontend, "invalid_state", errorMessage(error), request);
    }
    try {
        const callbackUrl = `${url.origin}${STAGED_WECHAT_OAUTH_PATHS.paymentCallback}`;
        const baseConfig = resolveWeChatOAuthConfig("mp", settings, wechatEnv(env), callbackUrl);
        const config: WeChatOAuthConfig = {
            ...baseConfig,
            redirectUrl: callbackUrl,
            scope: stored.scope
        };
        const providerToken = await new WeChatOAuthClient(dependencies.fetchImplementation)
            .exchangeCode(config, code);
        if (providerToken.openId === "") {
            throw new WeChatPaymentOAuthError("missing_openid", 502, "missing openid");
        }
        const keys = resolvePaymentResumeKeys(env);
        const resumeToken = await new WeChatPaymentResumeService(
            keys.signingKey,
            keys.verifyFallbacks,
            clock
        ).create({
            openId: providerToken.openId,
            paymentType: stored.paymentType,
            amount: stored.amount,
            orderType: stored.orderType,
            planId: stored.planId,
            redirectTo: stored.redirectTo,
            scope: providerToken.scope || stored.scope
        });
        const redirect = new URL(frontend);
        redirect.hash = new URLSearchParams({
            wechat_resume_token: resumeToken,
            redirect: stored.redirectTo
        }).toString();
        return clearPaymentCookies(redirectResponse(redirect.toString()), request);
    } catch (error) {
        return paymentCallbackError(
            frontend,
            error instanceof WeChatOAuthError || error instanceof WeChatPaymentOAuthError
                ? error.code
                : "token_exchange_failed",
            errorMessage(error),
            request
        );
    }
}

async function start(
    request: Request,
    env: StagedWeChatOAuthEnv & { DB: D1Database },
    settings: Record<string, string>,
    binding: boolean,
    dependencies: StagedWeChatOAuthDependencies,
    clock: () => number
): Promise<Response> {
    let bindUserId: number | null = null;
    if (binding) {
        const rawToken = readCookie(request, "oauth_bind_access_token");
        if (rawToken === "") throw new WeChatOAuthError("unauthorized", 401, "authentication is required");
        bindUserId = (await createAccessService(env, clock)
            .authenticateAuthorization(`Bearer ${rawToken}`)).user.id;
    }
    const url = new URL(request.url);
    const mode = resolveWeChatMode(url.searchParams.get("mode"), request.headers.get("user-agent") ?? "");
    const callbackFallback = `${url.origin}${STAGED_WECHAT_OAUTH_PATHS.callback}`;
    const config = resolveWeChatOAuthConfig(mode, settings, wechatEnv(env), callbackFallback);
    const started = await new D1WeChatOAuthStateService(
        new D1ExpiringStateRepository(env.DB, { clock }),
        dependencies.opaqueTokenFactory
    ).create(config, {
        redirectTo: sanitizeRedirect(url.searchParams.get("redirect")),
        intent: binding ? "bind_current_user" : "login",
        bindUserId,
        promoCode: boundedText(url.searchParams.get("promo_code"), 128)
    });
    const response = redirectResponse(started.authorizeUrl);
    appendCookie(response, "wechat_oauth_state", started.state, PROVIDER_COOKIE_PATH, request);
    appendCookie(response, "oauth_pending_browser_session", started.browserSessionKey, OAUTH_COOKIE_PATH, request);
    clearCookie(response, "oauth_pending_session", OAUTH_COOKIE_PATH, request);
    clearCookie(response, "oauth_bind_access_token", OAUTH_COOKIE_PATH, request);
    return response;
}

async function callback(
    request: Request,
    env: StagedWeChatOAuthEnv & { DB: D1Database },
    settings: Record<string, string>,
    dependencies: StagedWeChatOAuthDependencies,
    clock: () => number
): Promise<Response> {
    const url = new URL(request.url);
    const frontendFallback = frontendUrl(settings, env, request.url);
    const providerError = url.searchParams.get("error")?.trim()
        || url.searchParams.get("errcode")?.trim() || "";
    if (providerError !== "") {
        return callbackError(frontendFallback, providerError, url.searchParams.get("errmsg") ?? "", request);
    }
    const code = url.searchParams.get("code")?.trim() ?? "";
    const state = url.searchParams.get("state")?.trim() ?? "";
    if (code === "" || state === "" || readCookie(request, "wechat_oauth_state") !== state) {
        return callbackError(frontendFallback, "invalid_state", "invalid oauth state", request);
    }
    const browserSessionKey = readCookie(request, "oauth_pending_browser_session");
    let stored;
    try {
        stored = await new D1WeChatOAuthStateService(
            new D1ExpiringStateRepository(env.DB, { clock }),
            dependencies.opaqueTokenFactory
        ).consume(state, browserSessionKey);
    } catch (error) {
        return callbackError(frontendFallback, "invalid_state", errorMessage(error), request);
    }
    if (browserSessionKey !== stored.browserSessionKey) {
        return callbackError(frontendFallback, "missing_browser_session", "missing oauth browser session", request);
    }

    let config: WeChatOAuthConfig;
    let providerUser: WeChatOAuthIdentity;
    try {
        config = resolveWeChatOAuthConfig(
            stored.mode,
            settings,
            wechatEnv(env),
            `${url.origin}${STAGED_WECHAT_OAUTH_PATHS.callback}`
        );
        providerUser = await new WeChatOAuthClient(dependencies.fetchImplementation)
            .fetchIdentity(config, code);
    } catch (error) {
        return callbackError(
            frontendFallback,
            error instanceof WeChatOAuthError ? error.code : "userinfo_failed",
            errorMessage(error),
            request
        );
    }

    const frontend = new URL(config.frontendRedirectUrl, request.url).toString();
    const users = new D1AuthUserRepository(env.DB);
    let identityOwner;
    try {
        identityOwner = await users.findByWeChatIdentity(
            providerUser.subject,
            stored.mode,
            config.appId,
            providerUser.openId
        );
    } catch (error) {
        return callbackError(frontend, "identity_conflict", errorMessage(error), request);
    }
    if (stored.intent === "bind_current_user" && identityOwner !== null
        && identityOwner.id !== stored.bindUserId) {
        return callbackError(frontend, "identity_already_bound", "wechat identity is already bound", request);
    }
    const targetUserId = stored.intent === "bind_current_user"
        ? stored.bindUserId
        : identityOwner?.id ?? null;
    if (stored.intent === "bind_current_user" && targetUserId === null) {
        return callbackError(frontend, "invalid_state", "invalid oauth bind target", request);
    }
    const completion = buildCompletionResponse(
        stored.redirectTo,
        providerUser,
        identityOwner !== null,
        settings
    );
    const pending = await new D1PendingAuthService(
        new D1PendingAuthRepository(env.DB),
        { clock, opaqueTokenFactory: dependencies.opaqueTokenFactory }
    ).create({
        intent: stored.intent,
        providerType: "wechat",
        providerKey: PROVIDER_KEY,
        providerSubject: providerUser.subject,
        ...(targetUserId === null ? {} : { targetUserId }),
        redirectTo: stored.redirectTo,
        resolvedEmail: identityOwner?.email ?? providerUser.syntheticEmail,
        browserSessionKey: stored.browserSessionKey,
        upstreamIdentityClaims: {
            email: providerUser.syntheticEmail,
            username: providerUser.username,
            subject: providerUser.subject,
            openid: providerUser.openId,
            unionid: providerUser.unionId,
            mode: stored.mode,
            channel: stored.mode,
            channel_app_id: config.appId,
            channel_subject: providerUser.openId,
            suggested_display_name: providerUser.displayName,
            suggested_avatar_url: providerUser.avatarUrl
        },
        localFlowState: {
            completion_response: completion,
            ...(stored.promoCode === "" ? {} : { promo_code: stored.promoCode })
        }
    });
    const response = redirectResponse(frontend);
    appendCookie(response, "oauth_pending_session", pending.sessionToken, OAUTH_COOKIE_PATH, request);
    appendCookie(response, "oauth_pending_browser_session", stored.browserSessionKey, OAUTH_COOKIE_PATH, request);
    clearCookie(response, "wechat_oauth_state", PROVIDER_COOKIE_PATH, request);
    return response;
}

function buildCompletionResponse(
    redirect: string,
    user: WeChatOAuthIdentity,
    identityExists: boolean,
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
        email: user.syntheticEmail,
        resolved_email: user.syntheticEmail,
        existing_account_email: "",
        existing_account_bindable: false,
        create_account_allowed: true,
        force_email_on_signup: forceEmail,
        choice_reason: "third_party_signup"
    };
    if (forceEmail || verifyEmail) {
        response.step = "create_account_required";
        response.email_binding_required = true;
        response.force_email_on_signup = true;
        response.choice_reason = verifyEmail ? "email_verification_required" : "force_email_on_signup";
        delete response.email;
        delete response.resolved_email;
    }
    return response;
}

function createAccessService(env: StagedWeChatOAuthEnv & { DB: D1Database }, clock: () => number) {
    const secret = env.JWT_SECRET?.trim() ?? "";
    if (secret === "") throw new WeChatOAuthError("oauth_config_invalid", 503, "JWT secret is not configured");
    const users = new D1AuthUserRepository(env.DB);
    const sessions = new D1AuthSessionRepository(env.DB);
    const accessSeconds = boundedInteger(env.JWT_ACCESS_TOKEN_EXPIRES_SECONDS, 86400, 1, 604800);
    const refreshDays = boundedInteger(env.JWT_REFRESH_TOKEN_EXPIRE_DAYS, 30, 1, 365);
    const tokens = new AuthTokenService(sessions, new Hs256JwtSigner(secret, accessSeconds, clock), refreshDays, clock);
    return new AccessAuthService(users, new Hs256JwtVerifier(secret, clock), tokens, clock);
}

function frontendUrl(settings: Record<string, string>, env: StagedWeChatOAuthEnv, base: string): string {
    const configured = settings.wechat_connect_frontend_redirect_url?.trim()
        || env.WECHAT_CONNECT_FRONTEND_REDIRECT_URL?.trim()
        || "/auth/wechat/callback";
    return new URL(configured, base).toString();
}

function callbackError(frontend: string, code: string, message: string, request: Request): Response {
    const url = new URL(frontend);
    const fragment = new URLSearchParams({ error: boundedText(code, 128) || "oauth_error" });
    if (message.trim() !== "") fragment.set("error_message", boundedText(message, 512));
    url.hash = fragment.toString();
    const response = redirectResponse(url.toString());
    clearCookie(response, "wechat_oauth_state", PROVIDER_COOKIE_PATH, request);
    clearCookie(response, "oauth_pending_session", OAUTH_COOKIE_PATH, request);
    clearCookie(response, "oauth_pending_browser_session", OAUTH_COOKIE_PATH, request);
    return response;
}

function paymentCallbackError(frontend: string, code: string, message: string, request: Request): Response {
    const url = new URL(frontend);
    const fragment = new URLSearchParams({ error: boundedText(code, 128) || "oauth_error" });
    if (message.trim() !== "") fragment.set("error_description", boundedText(message, 512));
    url.hash = fragment.toString();
    return clearPaymentCookies(redirectResponse(url.toString()), request);
}

function clearPaymentCookies(response: Response, request: Request): Response {
    clearCookie(response, "wechat_payment_oauth_state", PAYMENT_COOKIE_PATH, request);
    clearCookie(response, "wechat_payment_oauth_browser", PAYMENT_COOKIE_PATH, request);
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
        throw new WeChatOAuthError("oauth_config_invalid", 503, "authentication duration is invalid");
    }
    return value;
}

function wechatEnv(env: StagedWeChatOAuthEnv): Record<string, string | undefined> {
    return {
        WECHAT_CONNECT_ENABLED: env.WECHAT_CONNECT_ENABLED,
        WECHAT_CONNECT_APP_ID: env.WECHAT_CONNECT_APP_ID,
        WECHAT_CONNECT_APP_SECRET: env.WECHAT_CONNECT_APP_SECRET,
        WECHAT_CONNECT_OPEN_APP_ID: env.WECHAT_CONNECT_OPEN_APP_ID,
        WECHAT_CONNECT_OPEN_APP_SECRET: env.WECHAT_CONNECT_OPEN_APP_SECRET,
        WECHAT_CONNECT_MP_APP_ID: env.WECHAT_CONNECT_MP_APP_ID,
        WECHAT_CONNECT_MP_APP_SECRET: env.WECHAT_CONNECT_MP_APP_SECRET,
        WECHAT_CONNECT_OPEN_ENABLED: env.WECHAT_CONNECT_OPEN_ENABLED,
        WECHAT_CONNECT_MP_ENABLED: env.WECHAT_CONNECT_MP_ENABLED,
        WECHAT_CONNECT_SCOPES: env.WECHAT_CONNECT_SCOPES,
        WECHAT_CONNECT_REDIRECT_URL: env.WECHAT_CONNECT_REDIRECT_URL,
        WECHAT_CONNECT_FRONTEND_REDIRECT_URL: env.WECHAT_CONNECT_FRONTEND_REDIRECT_URL,
        WECHAT_CONNECT_OPEN_AUTHORIZE_URL: env.WECHAT_CONNECT_OPEN_AUTHORIZE_URL,
        WECHAT_CONNECT_MP_AUTHORIZE_URL: env.WECHAT_CONNECT_MP_AUTHORIZE_URL,
        WECHAT_CONNECT_TOKEN_URL: env.WECHAT_CONNECT_TOKEN_URL,
        WECHAT_CONNECT_USERINFO_URL: env.WECHAT_CONNECT_USERINFO_URL
    };
}

function wechatFailure(error: unknown): Response {
    if (error instanceof WeChatOAuthError) {
        return legacyError(error.status, error.message, error.code.toUpperCase());
    }
    if (error instanceof WeChatPaymentOAuthError) {
        return legacyError(error.status, error.message, error.code.toUpperCase());
    }
    return legacyError(500, "WeChat OAuth request failed", "OAUTH_INTERNAL_ERROR");
}

function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : "oauth request failed";
}
