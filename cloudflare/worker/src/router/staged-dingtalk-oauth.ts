import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import { D1PendingAuthRepository } from "../repositories/pending-auth.ts";
import { D1SettingsRepository } from "../repositories/settings.ts";
import { AccessAuthService } from "../services/access-auth.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import {
    D1DingTalkOAuthStateService,
    DingTalkOAuthClient,
    DingTalkOAuthError,
    resolveDingTalkOAuthConfig,
    type DingTalkIdentity,
    type DingTalkOAuthConfig
} from "../services/dingtalk-oauth.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import { D1PendingAuthService } from "../services/pending-auth.ts";
import type { D1Database } from "../types/d1.ts";
import { ROUTER_RESPONSE_HEADER, legacyError, routerError } from "./responses.ts";
import {
    createPendingOAuthFinalizationService,
    STAGED_PENDING_OAUTH_SETTING_KEYS,
    type StagedPendingOAuthDependencies,
    type StagedPendingOAuthEnv
} from "./staged-pending-oauth.ts";

export const STAGED_DINGTALK_OAUTH_PATHS = {
    start: "/api/v1/auth/oauth/dingtalk/start",
    bindStart: "/api/v1/auth/oauth/dingtalk/bind/start",
    callback: "/api/v1/auth/oauth/dingtalk/callback"
} as const;

const SETTING_KEYS = [
    ...STAGED_PENDING_OAUTH_SETTING_KEYS,
    "email_verify_enabled",
    "force_email_on_third_party_signup",
    "dingtalk_connect_enabled",
    "dingtalk_connect_client_id",
    "dingtalk_connect_client_secret",
    "dingtalk_connect_redirect_url",
    "dingtalk_connect_corp_restriction_policy",
    "dingtalk_connect_internal_corp_id",
    "dingtalk_connect_bypass_registration",
    "dingtalk_connect_sync_corp_email",
    "dingtalk_connect_sync_display_name",
    "dingtalk_connect_sync_dept",
    "dingtalk_connect_sync_corp_email_attr_key",
    "dingtalk_connect_sync_display_name_attr_key",
    "dingtalk_connect_sync_dept_attr_key"
] as const;

const OAUTH_COOKIE_PATH = "/api/v1/auth/oauth";
const PROVIDER_COOKIE_PATH = "/api/v1/auth/oauth/dingtalk";
const COOKIE_TTL_SECONDS = 10 * 60;
const RESERVED_EMAIL_SUFFIXES = [
    "@linuxdo-connect.invalid",
    "@oidc-connect.invalid",
    "@wechat-connect.invalid",
    "@dingtalk-connect.invalid"
] as const;

export interface StagedDingTalkOAuthEnv extends StagedPendingOAuthEnv {
    DINGTALK_ENABLED?: string;
    DINGTALK_CLIENT_ID?: string;
    DINGTALK_CLIENT_SECRET?: string;
    DINGTALK_AUTHORIZE_URL?: string;
    DINGTALK_TOKEN_URL?: string;
    DINGTALK_USERINFO_URL?: string;
    DINGTALK_APP_TOKEN_URL?: string;
    DINGTALK_USER_BY_UNIONID_URL?: string;
    DINGTALK_STAFF_INFO_URL?: string;
    DINGTALK_DEPARTMENT_INFO_URL?: string;
    DINGTALK_API_BASE_URL?: string;
    DINGTALK_OAPI_BASE_URL?: string;
    DINGTALK_SCOPES?: string;
    DINGTALK_REDIRECT_URL?: string;
    DINGTALK_FRONTEND_REDIRECT_URL?: string;
    DINGTALK_CORP_POLICY?: string;
    DINGTALK_BYPASS_REGISTRATION?: string;
    DINGTALK_REQUIRE_EMAIL?: string;
}

export interface StagedDingTalkOAuthDependencies extends StagedPendingOAuthDependencies {
    opaqueTokenFactory?: () => string;
}

export async function routeStagedDingTalkOAuth(
    request: Request,
    env: StagedDingTalkOAuthEnv,
    dependencies: StagedDingTalkOAuthDependencies = {}
): Promise<Response | null> {
    const path = new URL(request.url).pathname;
    if (!Object.values(STAGED_DINGTALK_OAUTH_PATHS).includes(
        path as typeof STAGED_DINGTALK_OAUTH_PATHS[keyof typeof STAGED_DINGTALK_OAUTH_PATHS]
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
        const callbackFallback = new URL(STAGED_DINGTALK_OAUTH_PATHS.callback, request.url).toString();
        const config = resolveDingTalkOAuthConfig(settings, dingtalkEnv(env), callbackFallback);
        if (path === STAGED_DINGTALK_OAUTH_PATHS.callback) {
            return callback(request, boundEnv, config, settings, dependencies, clock);
        }
        return start(
            request,
            boundEnv,
            config,
            path === STAGED_DINGTALK_OAUTH_PATHS.bindStart,
            dependencies,
            clock
        );
    } catch (error) {
        return dingtalkFailure(error);
    }
}

async function start(
    request: Request,
    env: StagedDingTalkOAuthEnv & { DB: D1Database },
    config: DingTalkOAuthConfig,
    binding: boolean,
    dependencies: StagedDingTalkOAuthDependencies,
    clock: () => number
): Promise<Response> {
    let bindUserId: number | null = null;
    if (binding) {
        const rawToken = readCookie(request, "oauth_bind_access_token");
        if (rawToken === "") throw new DingTalkOAuthError("unauthorized", 401, "authentication is required");
        bindUserId = (await createAccessService(env, clock)
            .authenticateAuthorization(`Bearer ${rawToken}`)).user.id;
    }
    const url = new URL(request.url);
    const started = await new D1DingTalkOAuthStateService(
        new D1ExpiringStateRepository(env.DB, { clock }),
        dependencies.opaqueTokenFactory
    ).create(config, {
        redirectTo: sanitizeRedirect(url.searchParams.get("redirect")),
        intent: binding ? "bind_current_user" : "login",
        bindUserId,
        promoCode: boundedText(url.searchParams.get("promo_code"), 128)
    });
    const response = redirectResponse(started.authorizeUrl);
    appendCookie(response, "dingtalk_oauth_state", started.state, PROVIDER_COOKIE_PATH, request);
    appendCookie(response, "oauth_pending_browser_session", started.browserSessionKey, OAUTH_COOKIE_PATH, request);
    clearCookie(response, "oauth_pending_session", OAUTH_COOKIE_PATH, request);
    clearCookie(response, "oauth_bind_access_token", OAUTH_COOKIE_PATH, request);
    return response;
}

async function callback(
    request: Request,
    env: StagedDingTalkOAuthEnv & { DB: D1Database },
    config: DingTalkOAuthConfig,
    settings: Record<string, string>,
    dependencies: StagedDingTalkOAuthDependencies,
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
    if (code === "" || state === "" || readCookie(request, "dingtalk_oauth_state") !== state) {
        return callbackError(frontend, "invalid_state", "invalid oauth state", request);
    }
    const browserSessionKey = readCookie(request, "oauth_pending_browser_session");
    let stored;
    try {
        stored = await new D1DingTalkOAuthStateService(
            new D1ExpiringStateRepository(env.DB, { clock }),
            dependencies.opaqueTokenFactory
        ).consume(state, browserSessionKey);
    } catch (error) {
        return callbackError(frontend, "invalid_state", errorMessage(error), request);
    }
    if (browserSessionKey !== stored.browserSessionKey) {
        return callbackError(frontend, "missing_browser_session", "missing oauth browser session", request);
    }

    let identity: DingTalkIdentity;
    const client = new DingTalkOAuthClient(dependencies.fetchImplementation);
    try {
        identity = await client.fetchIdentity(config, code);
    } catch (error) {
        return callbackError(
            frontend,
            error instanceof DingTalkOAuthError ? error.code : "userinfo_failed",
            errorMessage(error),
            request
        );
    }

    const users = new D1AuthUserRepository(env.DB);
    const identityOwner = await users.findByIdentity("dingtalk", "dingtalk", identity.subject);
    const compatOwner = identityOwner === null && config.requireEmail
        ? await findCompatOwner(users, identity.email)
        : null;
    const targetUserId = stored.intent === "bind_current_user"
        ? stored.bindUserId
        : identityOwner?.id ?? compatOwner?.id ?? null;
    if (stored.intent === "bind_current_user" && targetUserId === null) {
        return callbackError(frontend, "invalid_state", "invalid oauth bind target", request);
    }
    if (stored.intent === "bind_current_user" && identityOwner !== null && identityOwner.id !== targetUserId) {
        return callbackError(frontend, "identity_conflict", "dingtalk identity belongs to another user", request);
    }

    const signupBlocked = settings.registration_enabled !== "true" && !config.bypassRegistration;
    const attributeSync = await dingTalkAttributeSyncState(config, settings, client, identity);
    const completion = completionResponse(
        stored.redirectTo,
        identity,
        stored.intent === "bind_current_user" || identityOwner !== null,
        compatOwner?.email ?? "",
        settings,
        config,
        signupBlocked
    );
    const pending = await new D1PendingAuthService(
        new D1PendingAuthRepository(env.DB),
        { clock, opaqueTokenFactory: dependencies.opaqueTokenFactory }
    ).create({
        intent: stored.intent,
        providerType: "dingtalk",
        providerKey: "dingtalk",
        providerSubject: identity.subject,
        ...(targetUserId === null ? {} : { targetUserId }),
        redirectTo: stored.redirectTo,
        resolvedEmail: compatOwner?.email
            ?? (config.requireEmail ? identity.email : identity.syntheticEmail),
        browserSessionKey: stored.browserSessionKey,
        upstreamIdentityClaims: {
            email: identity.email,
            synthetic_email: identity.syntheticEmail,
            username: identity.username,
            nickname: identity.nickname,
            subject: identity.subject,
            corp_user_id: identity.corpUserId,
            union_id: identity.subject,
            corp_id: identity.corpId,
            primary_dept_id: identity.primaryDeptId,
            suggested_display_name: identity.displayName,
            ...(identity.email === "" ? {} : { compat_email: identity.email })
        },
        localFlowState: {
            completion_response: completion,
            ...(stored.promoCode === "" ? {} : { promo_code: stored.promoCode }),
            ...(config.bypassRegistration ? { registration_bypass_allowed: true } : {}),
            ...(attributeSync === null ? {} : { dingtalk_attribute_sync: attributeSync })
        }
    });

    const directProviderRegistration = stored.intent === "login"
        && identityOwner === null
        && compatOwner === null
        && !config.requireEmail
        && !signupBlocked
        && settings.invitation_code_enabled !== "true";
    if (directProviderRegistration) {
        try {
            const payload = await createPendingOAuthFinalizationService(
                env.DB,
                env,
                dependencies,
                clock
            ).createAccount(
                pending.sessionToken,
                stored.browserSessionKey,
                { adoption: { adoptDisplayName: false, adoptAvatar: false } },
                settings,
                "dingtalk",
                "provider_identity"
            );
            return completedCallbackResponse(frontend, stored.redirectTo, payload, request);
        } catch (error) {
            return callbackError(frontend, errorCode(error), errorMessage(error), request);
        }
    }

    const response = redirectResponse(frontend);
    appendCookie(response, "oauth_pending_session", pending.sessionToken, OAUTH_COOKIE_PATH, request);
    appendCookie(response, "oauth_pending_browser_session", stored.browserSessionKey, OAUTH_COOKIE_PATH, request);
    clearCookie(response, "dingtalk_oauth_state", PROVIDER_COOKIE_PATH, request);
    return response;
}

async function dingTalkAttributeSyncState(
    config: DingTalkOAuthConfig,
    settings: Record<string, string>,
    client: DingTalkOAuthClient,
    identity: DingTalkIdentity
): Promise<Record<string, unknown> | null> {
    if (config.corpPolicy !== "internal_only") return null;
    const syncName = settings.dingtalk_connect_sync_display_name === "true";
    const syncEmail = settings.dingtalk_connect_sync_corp_email === "true";
    const syncDepartment = settings.dingtalk_connect_sync_dept === "true";
    if (!syncName && !syncEmail && !syncDepartment) return null;
    const attributes: { key: string; value: string }[] = [];
    if (syncName && identity.username !== "") {
        attributes.push({
            key: settings.dingtalk_connect_sync_display_name_attr_key || "dingtalk_name",
            value: identity.username
        });
    }
    if (syncEmail && identity.email !== "") {
        attributes.push({
            key: settings.dingtalk_connect_sync_corp_email_attr_key || "dingtalk_email",
            value: identity.email
        });
    }
    if (syncDepartment && identity.primaryDeptId > 0) {
        try {
            attributes.push({
                key: settings.dingtalk_connect_sync_dept_attr_key || "dingtalk_department",
                value: await client.resolveDepartmentPath(config, identity.primaryDeptId)
            });
        } catch {
            // Department lookup is eventually consistent; other enterprise fields still sync.
        }
    }
    return {
        username_on_registration: syncName,
        username: identity.nickname || identity.username,
        attributes
    };
}

function completionResponse(
    redirect: string,
    identity: DingTalkIdentity,
    identityExists: boolean,
    compatOwnerEmail: string,
    settings: Record<string, string>,
    config: DingTalkOAuthConfig,
    signupBlocked: boolean
): Record<string, unknown> {
    const profile = { redirect, suggested_display_name: identity.displayName };
    if (identityExists) return profile;
    if (signupBlocked) {
        return {
            ...profile,
            step: "bind_login_required",
            existing_account_bindable: true,
            create_account_allowed: false,
            choice_reason: "signup_blocked_redirect_to_bind"
        };
    }
    if (!config.requireEmail) {
        return settings.invitation_code_enabled === "true"
            ? { ...profile, error: "invitation_required", synthetic_email: identity.syntheticEmail }
            : { ...profile, synthetic_email: identity.syntheticEmail };
    }
    if (identity.email === "") {
        return { ...profile, step: "email_completion", requires_email_completion: true };
    }
    const forceEmail = settings.force_email_on_third_party_signup === "true";
    return {
        ...profile,
        step: "choose_account_action_required",
        adoption_required: true,
        email: compatOwnerEmail || identity.email,
        resolved_email: compatOwnerEmail || identity.email,
        compat_email: identity.email,
        existing_account_email: compatOwnerEmail,
        existing_account_bindable: compatOwnerEmail !== "",
        create_account_allowed: true,
        force_email_on_signup: forceEmail,
        choice_reason: compatOwnerEmail !== "" ? "compat_email_match"
            : forceEmail ? "force_email_on_signup" : "third_party_signup"
    };
}

async function findCompatOwner(users: D1AuthUserRepository, emailValue: string) {
    const email = usableCompatEmail(emailValue);
    return email === "" ? null : users.findByEmail(email);
}

function usableCompatEmail(emailValue: string): string {
    const email = emailValue.trim().toLowerCase();
    return email !== "" && /^[^\s@]+@[^\s@]+$/u.test(email)
        && !RESERVED_EMAIL_SUFFIXES.some((suffix) => email.endsWith(suffix)) ? email : "";
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
    clearCookie(response, "dingtalk_oauth_state", PROVIDER_COOKIE_PATH, request);
    clearCookie(response, "oauth_pending_session", OAUTH_COOKIE_PATH, request);
    clearCookie(response, "oauth_pending_browser_session", OAUTH_COOKIE_PATH, request);
    return response;
}

function createAccessService(env: StagedDingTalkOAuthEnv & { DB: D1Database }, clock: () => number) {
    const secret = env.JWT_SECRET?.trim() ?? "";
    if (secret === "") throw new DingTalkOAuthError("oauth_config_invalid", 503, "JWT secret is not configured");
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
    clearCookie(response, "dingtalk_oauth_state", PROVIDER_COOKIE_PATH, request);
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
        `${name}=${encodeURIComponent(value)}`, `Path=${path}`, `Max-Age=${COOKIE_TTL_SECONDS}`,
        "HttpOnly", "SameSite=Lax", ...(new URL(request.url).protocol === "https:" ? ["Secure"] : [])
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
        ? redirect : "/dashboard";
}

function boundedText(value: string | null | undefined, maximum: number): string {
    return (value ?? "").trim().slice(0, maximum);
}

function boundedInteger(raw: string | undefined, fallback: number, minimum: number, maximum: number): number {
    if (raw === undefined || raw.trim() === "") return fallback;
    const value = Number(raw);
    if (!Number.isInteger(value) || value < minimum || value > maximum) {
        throw new DingTalkOAuthError("oauth_config_invalid", 503, "authentication duration is invalid");
    }
    return value;
}

function dingtalkEnv(env: StagedDingTalkOAuthEnv): Record<string, string | undefined> {
    return {
        DINGTALK_ENABLED: env.DINGTALK_ENABLED,
        DINGTALK_CLIENT_ID: env.DINGTALK_CLIENT_ID,
        DINGTALK_CLIENT_SECRET: env.DINGTALK_CLIENT_SECRET,
        DINGTALK_AUTHORIZE_URL: env.DINGTALK_AUTHORIZE_URL,
        DINGTALK_TOKEN_URL: env.DINGTALK_TOKEN_URL,
        DINGTALK_USERINFO_URL: env.DINGTALK_USERINFO_URL,
        DINGTALK_APP_TOKEN_URL: env.DINGTALK_APP_TOKEN_URL,
        DINGTALK_USER_BY_UNIONID_URL: env.DINGTALK_USER_BY_UNIONID_URL,
        DINGTALK_STAFF_INFO_URL: env.DINGTALK_STAFF_INFO_URL,
        DINGTALK_DEPARTMENT_INFO_URL: env.DINGTALK_DEPARTMENT_INFO_URL,
        DINGTALK_API_BASE_URL: env.DINGTALK_API_BASE_URL,
        DINGTALK_OAPI_BASE_URL: env.DINGTALK_OAPI_BASE_URL,
        DINGTALK_SCOPES: env.DINGTALK_SCOPES,
        DINGTALK_REDIRECT_URL: env.DINGTALK_REDIRECT_URL,
        DINGTALK_FRONTEND_REDIRECT_URL: env.DINGTALK_FRONTEND_REDIRECT_URL,
        DINGTALK_CORP_POLICY: env.DINGTALK_CORP_POLICY,
        DINGTALK_BYPASS_REGISTRATION: env.DINGTALK_BYPASS_REGISTRATION,
        DINGTALK_REQUIRE_EMAIL: env.DINGTALK_REQUIRE_EMAIL
    };
}

function dingtalkFailure(error: unknown): Response {
    if (error instanceof DingTalkOAuthError) return legacyError(error.status, error.message, error.code.toUpperCase());
    return legacyError(500, "DingTalk OAuth request failed", "OAUTH_INTERNAL_ERROR");
}

function errorCode(error: unknown): string {
    return error !== null && typeof error === "object" && "code" in error && typeof error.code === "string"
        ? error.code : "registration_failed";
}

function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : "oauth request failed";
}
