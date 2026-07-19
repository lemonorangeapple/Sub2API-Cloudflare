import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import { D1PendingAuthRepository } from "../repositories/pending-auth.ts";
import { D1SettingsRepository } from "../repositories/settings.ts";
import {
    D1EmailOAuthStateService,
    EmailOAuthClient,
    EmailOAuthError,
    resolveEmailOAuthConfig,
    type EmailOAuthConfig,
    type EmailOAuthProvider,
    type EmailOAuthProfile
} from "../services/email-oauth.ts";
import { D1PendingAuthService } from "../services/pending-auth.ts";
import type { D1Database } from "../types/d1.ts";
import { legacyError, ROUTER_RESPONSE_HEADER, routerError } from "./responses.ts";
import {
    STAGED_PENDING_OAUTH_SETTING_KEYS,
    type StagedPendingOAuthDependencies,
    type StagedPendingOAuthEnv
} from "./staged-pending-oauth.ts";

export const STAGED_EMAIL_OAUTH_PATHS = {
    githubStart: "/api/v1/auth/oauth/github/start",
    githubCallback: "/api/v1/auth/oauth/github/callback",
    googleStart: "/api/v1/auth/oauth/google/start",
    googleCallback: "/api/v1/auth/oauth/google/callback"
} as const;

const SETTING_KEYS = [
    ...STAGED_PENDING_OAUTH_SETTING_KEYS,
    "github_oauth_enabled",
    "github_oauth_client_id",
    "github_oauth_client_secret",
    "github_oauth_redirect_url",
    "github_oauth_frontend_redirect_url",
    "google_oauth_enabled",
    "google_oauth_client_id",
    "google_oauth_client_secret",
    "google_oauth_redirect_url",
    "google_oauth_frontend_redirect_url"
] as const;
const COOKIE_PATH = "/api/v1/auth/oauth";
const COOKIE_TTL_SECONDS = 10 * 60;

export interface StagedEmailOAuthEnv extends StagedPendingOAuthEnv {
    GITHUB_OAUTH_ENABLED?: string;
    GITHUB_OAUTH_CLIENT_ID?: string;
    GITHUB_OAUTH_CLIENT_SECRET?: string;
    GITHUB_OAUTH_REDIRECT_URL?: string;
    GITHUB_OAUTH_FRONTEND_REDIRECT_URL?: string;
    GITHUB_OAUTH_AUTHORIZE_URL?: string;
    GITHUB_OAUTH_TOKEN_URL?: string;
    GITHUB_OAUTH_USERINFO_URL?: string;
    GITHUB_OAUTH_EMAILS_URL?: string;
    GITHUB_OAUTH_SCOPES?: string;
    GOOGLE_OAUTH_ENABLED?: string;
    GOOGLE_OAUTH_CLIENT_ID?: string;
    GOOGLE_OAUTH_CLIENT_SECRET?: string;
    GOOGLE_OAUTH_REDIRECT_URL?: string;
    GOOGLE_OAUTH_FRONTEND_REDIRECT_URL?: string;
    GOOGLE_OAUTH_AUTHORIZE_URL?: string;
    GOOGLE_OAUTH_TOKEN_URL?: string;
    GOOGLE_OAUTH_USERINFO_URL?: string;
    GOOGLE_OAUTH_SCOPES?: string;
}

export interface StagedEmailOAuthDependencies extends StagedPendingOAuthDependencies {
    opaqueTokenFactory?: () => string;
}

export async function routeStagedEmailOAuth(
    request: Request,
    env: StagedEmailOAuthEnv,
    dependencies: StagedEmailOAuthDependencies = {}
): Promise<Response | null> {
    const path = new URL(request.url).pathname;
    if (!Object.values(STAGED_EMAIL_OAUTH_PATHS).includes(
        path as typeof STAGED_EMAIL_OAUTH_PATHS[keyof typeof STAGED_EMAIL_OAUTH_PATHS]
    )) return null;
    if (request.method !== "GET") return routerError(405, "method_not_allowed", `${path} requires GET`, { allow: "GET" });
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");
    const provider: EmailOAuthProvider = path.includes("/github/") ? "github" : "google";
    const callbackPath = provider === "github"
        ? STAGED_EMAIL_OAUTH_PATHS.githubCallback
        : STAGED_EMAIL_OAUTH_PATHS.googleCallback;
    try {
        const settings = await new D1SettingsRepository(env.DB).getMany(SETTING_KEYS);
        const config = resolveEmailOAuthConfig(provider, settings, providerEnv(env));
        return path === callbackPath
            ? callback(request, env.DB, config, settings, dependencies)
            : start(request, env.DB, config, dependencies);
    } catch (error) {
        if (error instanceof EmailOAuthError) return legacyError(error.status, error.message, error.code.toUpperCase());
        return legacyError(500, "Email OAuth request failed", "OAUTH_INTERNAL_ERROR");
    }
}

async function start(
    request: Request,
    db: D1Database,
    config: EmailOAuthConfig,
    dependencies: StagedEmailOAuthDependencies
): Promise<Response> {
    const url = new URL(request.url);
    const started = await new D1EmailOAuthStateService(
        new D1ExpiringStateRepository(db, { clock: dependencies.clock }),
        dependencies.opaqueTokenFactory
    ).create(config, {
        redirectTo: sanitizeRedirect(url.searchParams.get("redirect")),
        promoCode: bounded(url.searchParams.get("promo_code"), 128),
        affiliateCode: bounded(url.searchParams.get("aff_code") || url.searchParams.get("aff"), 128)
    });
    const response = redirectResponse(started.authorizeUrl);
    setCookie(response, "email_oauth_state", started.state, request);
    setCookie(response, "oauth_pending_browser_session", started.browserSessionKey, request);
    clearCookie(response, "oauth_pending_session", request);
    return response;
}

async function callback(
    request: Request,
    db: D1Database,
    config: EmailOAuthConfig,
    settings: Record<string, string>,
    dependencies: StagedEmailOAuthDependencies
): Promise<Response> {
    const url = new URL(request.url);
    const frontend = new URL(config.frontendRedirectUrl, request.url).toString();
    const providerError = url.searchParams.get("error")?.trim() ?? "";
    if (providerError !== "") {
        return callbackError(frontend, providerError, url.searchParams.get("error_description") ?? "", request);
    }
    const code = url.searchParams.get("code")?.trim() ?? "";
    const state = url.searchParams.get("state")?.trim() ?? "";
    const browser = readCookie(request, "oauth_pending_browser_session");
    if (code === "" || state === "" || readCookie(request, "email_oauth_state") !== state || browser === "") {
        return callbackError(frontend, "invalid_state", "invalid oauth state", request);
    }
    let stored;
    try {
        stored = await new D1EmailOAuthStateService(
            new D1ExpiringStateRepository(db, { clock: dependencies.clock }),
            dependencies.opaqueTokenFactory
        ).consume(config.provider, state, browser);
    } catch (error) {
        return callbackError(frontend, "invalid_state", errorMessage(error), request);
    }
    let profile: EmailOAuthProfile;
    try {
        profile = await new EmailOAuthClient(dependencies.fetchImplementation).fetchProfile(config, code);
    } catch (error) {
        return callbackError(frontend, error instanceof EmailOAuthError ? error.code : "userinfo_failed", errorMessage(error), request);
    }

    const users = new D1AuthUserRepository(db);
    const identityOwner = await users.findByIdentity(config.provider, config.provider, profile.subject);
    if (identityOwner !== null && identityOwner.email.trim().toLowerCase() !== profile.email) {
        return callbackError(frontend, "auth_identity_email_mismatch", "oauth identity belongs to a different email", request);
    }
    const emailOwner = identityOwner === null ? await users.findByEmail(profile.email) : null;
    const target = identityOwner ?? emailOwner;
    const invitationRequired = settings.invitation_code_enabled === "true";
    const completion: Record<string, unknown> = target === null ? {
        step: "choose_account_action_required",
        error: invitationRequired ? "invitation_required" : "registration_completion_required",
        choice_reason: invitationRequired ? "invitation_required" : "registration_completion_required",
        adoption_required: false,
        create_account_allowed: true,
        existing_account_bindable: false,
        force_email_on_signup: true,
        invitation_required: invitationRequired,
        email: profile.email,
        resolved_email: profile.email,
        provider: config.provider,
        redirect: stored.redirectTo,
        frontend_callback: config.frontendRedirectUrl
    } : { redirect: stored.redirectTo, adoption_required: false };
    const pending = await new D1PendingAuthService(
        new D1PendingAuthRepository(db),
        { clock: dependencies.clock, opaqueTokenFactory: dependencies.opaqueTokenFactory }
    ).create({
        intent: "login",
        providerType: config.provider,
        providerKey: config.provider,
        providerSubject: profile.subject,
        ...(target === null ? {} : { targetUserId: target.id }),
        redirectTo: stored.redirectTo,
        resolvedEmail: profile.email,
        browserSessionKey: stored.browserSessionKey,
        upstreamIdentityClaims: {
            email: profile.email,
            email_verified: true,
            username: profile.username,
            provider: config.provider,
            provider_key: config.provider,
            provider_subject: profile.subject,
            suggested_display_name: profile.displayName,
            suggested_avatar_url: profile.avatarUrl,
            ...(stored.affiliateCode === "" ? {} : { aff_code: stored.affiliateCode }),
            ...profile.metadata
        },
        localFlowState: {
            completion_response: completion,
            ...(stored.promoCode === "" ? {} : { promo_code: stored.promoCode }),
            ...(stored.affiliateCode === "" ? {} : { affiliate_code: stored.affiliateCode })
        }
    });
    const response = redirectResponse(frontend);
    setCookie(response, "oauth_pending_session", pending.sessionToken, request);
    setCookie(response, "oauth_pending_browser_session", stored.browserSessionKey, request);
    clearCookie(response, "email_oauth_state", request);
    return response;
}

function callbackError(frontend: string, code: string, message: string, request: Request): Response {
    const url = new URL(frontend);
    const fragment = new URLSearchParams({ error: bounded(code, 128) || "oauth_error" });
    if (message.trim() !== "") fragment.set("error_message", bounded(message, 512));
    url.hash = fragment.toString();
    const response = redirectResponse(url.toString());
    clearCookie(response, "email_oauth_state", request);
    clearCookie(response, "oauth_pending_session", request);
    clearCookie(response, "oauth_pending_browser_session", request);
    return response;
}

function providerEnv(env: StagedEmailOAuthEnv): Record<string, string | undefined> {
    return {
        GITHUB_OAUTH_ENABLED: env.GITHUB_OAUTH_ENABLED,
        GITHUB_OAUTH_CLIENT_ID: env.GITHUB_OAUTH_CLIENT_ID,
        GITHUB_OAUTH_CLIENT_SECRET: env.GITHUB_OAUTH_CLIENT_SECRET,
        GITHUB_OAUTH_REDIRECT_URL: env.GITHUB_OAUTH_REDIRECT_URL,
        GITHUB_OAUTH_FRONTEND_REDIRECT_URL: env.GITHUB_OAUTH_FRONTEND_REDIRECT_URL,
        GITHUB_OAUTH_AUTHORIZE_URL: env.GITHUB_OAUTH_AUTHORIZE_URL,
        GITHUB_OAUTH_TOKEN_URL: env.GITHUB_OAUTH_TOKEN_URL,
        GITHUB_OAUTH_USERINFO_URL: env.GITHUB_OAUTH_USERINFO_URL,
        GITHUB_OAUTH_EMAILS_URL: env.GITHUB_OAUTH_EMAILS_URL,
        GITHUB_OAUTH_SCOPES: env.GITHUB_OAUTH_SCOPES,
        GOOGLE_OAUTH_ENABLED: env.GOOGLE_OAUTH_ENABLED,
        GOOGLE_OAUTH_CLIENT_ID: env.GOOGLE_OAUTH_CLIENT_ID,
        GOOGLE_OAUTH_CLIENT_SECRET: env.GOOGLE_OAUTH_CLIENT_SECRET,
        GOOGLE_OAUTH_REDIRECT_URL: env.GOOGLE_OAUTH_REDIRECT_URL,
        GOOGLE_OAUTH_FRONTEND_REDIRECT_URL: env.GOOGLE_OAUTH_FRONTEND_REDIRECT_URL,
        GOOGLE_OAUTH_AUTHORIZE_URL: env.GOOGLE_OAUTH_AUTHORIZE_URL,
        GOOGLE_OAUTH_TOKEN_URL: env.GOOGLE_OAUTH_TOKEN_URL,
        GOOGLE_OAUTH_USERINFO_URL: env.GOOGLE_OAUTH_USERINFO_URL,
        GOOGLE_OAUTH_SCOPES: env.GOOGLE_OAUTH_SCOPES
    };
}

function redirectResponse(location: string): Response {
    return new Response(null, { status: 302, headers: {
        "cache-control": "no-store",
        location,
        pragma: "no-cache",
        [ROUTER_RESPONSE_HEADER]: "sub2api-router",
        "x-content-type-options": "nosniff"
    } });
}

function setCookie(response: Response, name: string, value: string, request: Request): void {
    response.headers.append("set-cookie", [
        `${name}=${encodeURIComponent(value)}`, `Path=${COOKIE_PATH}`, `Max-Age=${COOKIE_TTL_SECONDS}`,
        "HttpOnly", "SameSite=Lax", ...(new URL(request.url).protocol === "https:" ? ["Secure"] : [])
    ].join("; "));
}

function clearCookie(response: Response, name: string, request: Request): void {
    response.headers.append("set-cookie", [
        `${name}=`, `Path=${COOKIE_PATH}`, "Max-Age=0", "HttpOnly", "SameSite=Lax",
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
    return redirect.startsWith("/") && !redirect.startsWith("//") && redirect.length <= 2048
        ? redirect : "/dashboard";
}

function bounded(value: string | null | undefined, maximum: number): string {
    return (value ?? "").trim().slice(0, maximum);
}

function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : "oauth request failed";
}
