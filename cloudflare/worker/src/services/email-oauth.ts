import type { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import { randomHex, sha256Hex } from "../utils/crypto.ts";

export type EmailOAuthProvider = "github" | "google";

export interface EmailOAuthConfig {
    provider: EmailOAuthProvider;
    enabled: boolean;
    clientId: string;
    clientSecret: string;
    redirectUrl: string;
    frontendRedirectUrl: string;
    authorizeUrl: string;
    tokenUrl: string;
    userInfoUrl: string;
    emailsUrl: string;
    scopes: string;
}

export interface EmailOAuthState {
    provider: EmailOAuthProvider;
    browserSessionKey: string;
    redirectTo: string;
    promoCode: string;
    affiliateCode: string;
}

export interface EmailOAuthProfile {
    subject: string;
    email: string;
    username: string;
    displayName: string;
    avatarUrl: string;
    metadata: Record<string, unknown>;
}

export class EmailOAuthError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "EmailOAuthError";
        this.code = code;
        this.status = status;
    }
}

export class D1EmailOAuthStateService {
    readonly #state: D1ExpiringStateRepository;
    readonly #tokens: () => string;

    constructor(state: D1ExpiringStateRepository, tokenFactory: () => string = () => randomHex(32)) {
        this.#state = state;
        this.#tokens = tokenFactory;
    }

    async create(config: EmailOAuthConfig, input: Omit<EmailOAuthState, "provider" | "browserSessionKey">) {
        validateConfig(config);
        const state = opaque(this.#tokens());
        const browserSessionKey = opaque(this.#tokens());
        await this.#state.put(await stateKey(config.provider, state, browserSessionKey), {
            ...input,
            provider: config.provider,
            browserSessionKey
        } satisfies EmailOAuthState, 10 * 60 * 1000);
        const authorize = new URL(config.authorizeUrl);
        authorize.searchParams.set("response_type", "code");
        authorize.searchParams.set("client_id", config.clientId);
        authorize.searchParams.set("redirect_uri", config.redirectUrl);
        authorize.searchParams.set("state", state);
        if (config.scopes !== "") authorize.searchParams.set("scope", config.scopes);
        return { state, browserSessionKey, authorizeUrl: authorize.toString() };
    }

    async consume(provider: EmailOAuthProvider, stateValue: string, browserValue: string): Promise<EmailOAuthState> {
        const state = opaque(stateValue);
        const browser = opaque(browserValue);
        const stored = await this.#state.take<EmailOAuthState>(await stateKey(provider, state, browser));
        if (stored === null || stored.value.provider !== provider || stored.value.browserSessionKey !== browser) {
            throw new EmailOAuthError("invalid_state", 400, "invalid or expired oauth state");
        }
        return stored.value;
    }
}

export class EmailOAuthClient {
    readonly #fetch: typeof fetch;

    constructor(fetchImplementation: typeof fetch = fetch) {
        this.#fetch = fetchImplementation;
    }

    async fetchProfile(config: EmailOAuthConfig, codeValue: string): Promise<EmailOAuthProfile> {
        validateConfig(config);
        const code = codeValue.trim();
        if (code === "") throw new EmailOAuthError("missing_params", 400, "missing oauth code");
        const body = new URLSearchParams({
            grant_type: "authorization_code",
            client_id: config.clientId,
            client_secret: config.clientSecret,
            code,
            redirect_uri: config.redirectUrl
        });
        const token = await this.#json(config.tokenUrl, {
            method: "POST",
            headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
            body
        }, "token_exchange_failed");
        const accessToken = text(token.access_token);
        if (accessToken === "") throw new EmailOAuthError("token_exchange_failed", 502, "missing access_token");
        const headers = { accept: "application/json", authorization: `Bearer ${accessToken}` };
        const profile = await this.#json(config.userInfoUrl, { headers }, "userinfo_failed");
        return config.provider === "github"
            ? this.#github(config, profile, headers)
            : googleProfile(profile);
    }

    async #github(config: EmailOAuthConfig, profile: Record<string, unknown>, headers: HeadersInit) {
        const subject = text(profile.id);
        if (subject === "") throw new EmailOAuthError("userinfo_failed", 502, "github user id is missing");
        if (config.emailsUrl === "") throw new EmailOAuthError("userinfo_failed", 502, "github emails url is missing");
        const emails = await this.#array(config.emailsUrl, { headers });
        const selected = emails.find((item) => item.primary === true && item.verified === true)
            ?? emails.find((item) => item.verified === true);
        const email = normalizedEmail(selected?.email);
        if (email === "") throw new EmailOAuthError("userinfo_failed", 502, "github verified email is missing");
        const login = text(profile.login);
        const name = text(profile.name);
        return {
            subject,
            email,
            username: login || name || `github_${subject}`,
            displayName: name || login,
            avatarUrl: httpUrl(profile.avatar_url),
            metadata: { login }
        } satisfies EmailOAuthProfile;
    }

    async #json(url: string, init: RequestInit, code: string): Promise<Record<string, unknown>> {
        let response: Response;
        try { response = await this.#fetch(url, init); } catch {
            throw new EmailOAuthError(code, 502, `${code.replaceAll("_", " ")}`);
        }
        const raw = await response.text();
        if (!response.ok) throw new EmailOAuthError(code, 502, `${code.replaceAll("_", " ")}`);
        try {
            const value: unknown = JSON.parse(raw);
            if (value !== null && typeof value === "object" && !Array.isArray(value)) {
                return value as Record<string, unknown>;
            }
        } catch { /* handled below */ }
        const values = new URLSearchParams(raw);
        const parsed: Record<string, unknown> = {};
        values.forEach((value, key) => { parsed[key] = value; });
        if (Object.keys(parsed).length > 0) return parsed;
        throw new EmailOAuthError(code, 502, "oauth response is invalid");
    }

    async #array(url: string, init: RequestInit): Promise<Record<string, unknown>[]> {
        let response: Response;
        try { response = await this.#fetch(url, init); } catch {
            throw new EmailOAuthError("userinfo_failed", 502, "failed to fetch github emails");
        }
        if (!response.ok) throw new EmailOAuthError("userinfo_failed", 502, "failed to fetch github emails");
        try {
            const value: unknown = await response.json();
            if (Array.isArray(value)) return value.filter(isObject);
        } catch { /* handled below */ }
        throw new EmailOAuthError("userinfo_failed", 502, "github emails response is invalid");
    }
}

export function resolveEmailOAuthConfig(
    provider: EmailOAuthProvider,
    settings: Record<string, string>,
    env: Record<string, string | undefined>
): EmailOAuthConfig {
    const prefix = `${provider}_oauth`;
    const upper = `${provider.toUpperCase()}_OAUTH`;
    const github = provider === "github";
    const config: EmailOAuthConfig = {
        provider,
        enabled: bool(settings[`${prefix}_enabled`], env[`${upper}_ENABLED`]),
        clientId: first(settings[`${prefix}_client_id`], env[`${upper}_CLIENT_ID`]),
        clientSecret: first(env[`${upper}_CLIENT_SECRET`], settings[`${prefix}_client_secret`]),
        redirectUrl: first(settings[`${prefix}_redirect_url`], env[`${upper}_REDIRECT_URL`]),
        frontendRedirectUrl: first(settings[`${prefix}_frontend_redirect_url`], env[`${upper}_FRONTEND_REDIRECT_URL`], "/auth/oauth/callback"),
        authorizeUrl: first(env[`${upper}_AUTHORIZE_URL`], github ? "https://github.com/login/oauth/authorize" : "https://accounts.google.com/o/oauth2/v2/auth"),
        tokenUrl: first(env[`${upper}_TOKEN_URL`], github ? "https://github.com/login/oauth/access_token" : "https://oauth2.googleapis.com/token"),
        userInfoUrl: first(env[`${upper}_USERINFO_URL`], github ? "https://api.github.com/user" : "https://openidconnect.googleapis.com/v1/userinfo"),
        emailsUrl: github ? first(env[`${upper}_EMAILS_URL`], "https://api.github.com/user/emails") : "",
        scopes: first(env[`${upper}_SCOPES`], github ? "read:user user:email" : "openid email profile")
    };
    validateConfig(config);
    return config;
}

function googleProfile(profile: Record<string, unknown>): EmailOAuthProfile {
    const subject = text(profile.sub);
    const email = normalizedEmail(profile.email);
    if (subject === "") throw new EmailOAuthError("userinfo_failed", 502, "google subject is missing");
    if (email === "" || profile.email_verified !== true) {
        throw new EmailOAuthError("userinfo_failed", 502, "google verified email is missing");
    }
    const name = text(profile.name);
    return {
        subject,
        email,
        username: text(profile.given_name) || name || email,
        displayName: name,
        avatarUrl: httpUrl(profile.picture),
        metadata: { email_verified: true }
    };
}

function validateConfig(config: EmailOAuthConfig): void {
    if (!config.enabled) throw new EmailOAuthError("oauth_disabled", 404, "oauth login is disabled");
    if (config.clientId === "" || config.clientSecret === "" || config.redirectUrl === "") {
        throw new EmailOAuthError("oauth_config_invalid", 503, "oauth configuration is incomplete");
    }
    for (const value of [config.authorizeUrl, config.tokenUrl, config.userInfoUrl, config.redirectUrl]) {
        try { if (!/^https?:$/u.test(new URL(value).protocol)) throw new TypeError(); } catch {
            throw new EmailOAuthError("oauth_config_invalid", 503, "oauth URL is invalid");
        }
    }
}

async function stateKey(provider: string, state: string, browser: string) {
    return `oauth-email-state:${provider}:${await sha256Hex(`${state}\n${browser}`)}`;
}

function opaque(value: string): string {
    const result = value.trim();
    if (!/^[A-Za-z0-9_-]{32,256}$/u.test(result)) throw new EmailOAuthError("invalid_state", 400, "invalid oauth state");
    return result;
}

function normalizedEmail(value: unknown): string {
    const email = text(value).toLowerCase();
    return /^[^\s@]+@[^\s@]+$/u.test(email) ? email : "";
}

function httpUrl(value: unknown): string {
    const raw = text(value);
    try { return /^https?:$/u.test(new URL(raw).protocol) ? raw : ""; } catch { return ""; }
}

function text(value: unknown): string {
    return typeof value === "string" || typeof value === "number" ? String(value).trim() : "";
}

function first(...values: Array<string | undefined>): string {
    return values.map((value) => value?.trim() ?? "").find(Boolean) ?? "";
}

function bool(setting: string | undefined, environment: string | undefined): boolean {
    return first(setting, environment).toLowerCase() === "true";
}

function isObject(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}
