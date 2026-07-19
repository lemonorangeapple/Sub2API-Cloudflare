import type { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import { randomHex, sha256Hex } from "../utils/crypto.ts";

export type WeChatOAuthMode = "open" | "mp";

export interface WeChatOAuthConfig {
    mode: WeChatOAuthMode;
    appId: string;
    appSecret: string;
    authorizeUrl: string;
    tokenUrl: string;
    userInfoUrl: string;
    scope: string;
    redirectUrl: string;
    frontendRedirectUrl: string;
    requiresUnionId: boolean;
}

export interface WeChatOAuthState {
    browserSessionKey: string;
    mode: WeChatOAuthMode;
    intent: "login" | "bind_current_user";
    bindUserId: number | null;
    redirectTo: string;
    promoCode: string;
}

export interface WeChatOAuthIdentity {
    subject: string;
    openId: string;
    unionId: string;
    username: string;
    displayName: string;
    avatarUrl: string;
    syntheticEmail: string;
}

export interface WeChatOAuthToken {
    accessToken: string;
    openId: string;
    unionId: string;
    scope: string;
}

export class WeChatOAuthError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "WeChatOAuthError";
        this.code = code;
        this.status = status;
    }
}

export class D1WeChatOAuthStateService {
    readonly #state: D1ExpiringStateRepository;
    readonly #tokens: () => string;

    constructor(state: D1ExpiringStateRepository, tokenFactory: () => string = () => randomHex(32)) {
        this.#state = state;
        this.#tokens = tokenFactory;
    }

    async create(config: WeChatOAuthConfig, input: Omit<WeChatOAuthState, "browserSessionKey" | "mode">) {
        validateConfig(config);
        const state = opaque(this.#tokens());
        const browserSessionKey = opaque(this.#tokens());
        await this.#state.put(await stateKey(state, browserSessionKey), {
            ...input, mode: config.mode, browserSessionKey
        } satisfies WeChatOAuthState, 10 * 60 * 1000);
        return { state, browserSessionKey, authorizeUrl: buildWeChatAuthorizeUrl(config, state) };
    }

    async consume(stateValue: string, browserValue: string): Promise<WeChatOAuthState> {
        const state = opaque(stateValue);
        const browser = opaque(browserValue);
        const stored = await this.#state.take<WeChatOAuthState>(await stateKey(state, browser));
        if (stored === null || stored.value.browserSessionKey !== browser) {
            throw new WeChatOAuthError("invalid_state", 400, "invalid or expired oauth state");
        }
        return stored.value;
    }
}

export class WeChatOAuthClient {
    readonly #fetch: typeof fetch;

    constructor(fetchImplementation: typeof fetch = fetch) {
        this.#fetch = fetchImplementation;
    }

    async fetchIdentity(config: WeChatOAuthConfig, code: string): Promise<WeChatOAuthIdentity> {
        const token = await this.exchangeCode(config, code);
        const url = new URL(config.userInfoUrl);
        url.searchParams.set("access_token", token.accessToken);
        url.searchParams.set("openid", token.openId);
        url.searchParams.set("lang", "zh_CN");
        const info = await this.#request(url.toString(), "wechat userinfo");
        const openId = first(text(info.openid), token.openId);
        const unionId = first(text(info.unionid), token.unionId);
        const subject = unionId || (config.requiresUnionId ? "" : openId);
        if (subject === "") throw new WeChatOAuthError("wechat_missing_unionid", 502, "wechat unionid is missing");
        if (!/^[A-Za-z0-9_-]{1,50}$/u.test(subject) || !/^[A-Za-z0-9_-]{1,128}$/u.test(openId)) {
            throw new WeChatOAuthError("userinfo_failed", 502, "wechat identity is invalid");
        }
        const nickname = text(info.nickname);
        return {
            subject,
            openId,
            unionId,
            username: nickname || fallbackUsername(subject),
            displayName: nickname,
            avatarUrl: httpUrl(info.headimgurl),
            syntheticEmail: `wechat-${subject}@wechat-connect.invalid`
        };
    }

    async exchangeCode(config: WeChatOAuthConfig, codeValue: string): Promise<WeChatOAuthToken> {
        validateConfig(config);
        const code = codeValue.trim();
        if (code === "") throw new WeChatOAuthError("missing_params", 400, "missing oauth code");
        const url = new URL(config.tokenUrl);
        url.searchParams.set("appid", config.appId);
        url.searchParams.set("secret", config.appSecret);
        url.searchParams.set("code", code);
        url.searchParams.set("grant_type", "authorization_code");
        const token = await this.#request(url.toString(), "wechat access token");
        const errorCode = numberValue(token.errcode);
        if (errorCode !== 0) {
            throw new WeChatOAuthError("token_exchange_failed", 502, `wechat access token error ${errorCode}`);
        }
        const accessToken = text(token.access_token);
        if (accessToken === "") throw new WeChatOAuthError("token_exchange_failed", 502, "wechat access token is missing");
        return {
            accessToken,
            openId: text(token.openid),
            unionId: text(token.unionid),
            scope: text(token.scope)
        };
    }

    async #request(url: string, label: string): Promise<Record<string, unknown>> {
        let response: Response;
        try { response = await this.#fetch(url, { headers: { accept: "application/json" } }); } catch {
            throw new WeChatOAuthError("provider_error", 502, `${label} request failed`);
        }
        if (!response.ok) throw new WeChatOAuthError("provider_error", 502, `${label} request failed`);
        let value: unknown;
        try { value = await response.json(); } catch {
            throw new WeChatOAuthError("provider_error", 502, `${label} response is invalid`);
        }
        if (!isObject(value)) throw new WeChatOAuthError("provider_error", 502, `${label} response is invalid`);
        const errorCode = numberValue(value.errcode);
        if (errorCode !== 0) throw new WeChatOAuthError("provider_error", 502, `${label} error ${errorCode}`);
        return value;
    }
}

export function resolveWeChatOAuthConfig(
    mode: WeChatOAuthMode,
    settings: Record<string, string>,
    env: Record<string, string | undefined>,
    callbackFallback = ""
): WeChatOAuthConfig {
    const generalEnabled = bool(first(settings.wechat_connect_enabled, env.WECHAT_CONNECT_ENABLED));
    const legacyId = first(settings.wechat_connect_app_id, env.WECHAT_CONNECT_APP_ID);
    const legacySecret = first(env.WECHAT_CONNECT_APP_SECRET, settings.wechat_connect_app_secret);
    const openId = first(settings.wechat_connect_open_app_id, env.WECHAT_CONNECT_OPEN_APP_ID, legacyId);
    const openSecret = first(env.WECHAT_CONNECT_OPEN_APP_SECRET, settings.wechat_connect_open_app_secret, legacySecret);
    const mpId = first(settings.wechat_connect_mp_app_id, env.WECHAT_CONNECT_MP_APP_ID, legacyId);
    const mpSecret = first(env.WECHAT_CONNECT_MP_APP_SECRET, settings.wechat_connect_mp_app_secret, legacySecret);
    const openEnabled = enabled(settings.wechat_connect_open_enabled, env.WECHAT_CONNECT_OPEN_ENABLED, generalEnabled && openId !== "" && openSecret !== "");
    const mpEnabled = enabled(settings.wechat_connect_mp_enabled, env.WECHAT_CONNECT_MP_ENABLED, generalEnabled && mpId !== "" && mpSecret !== "");
    if (!(mode === "open" ? openEnabled : mpEnabled)) {
        throw new WeChatOAuthError("oauth_disabled", 404, "wechat oauth is disabled");
    }
    const config: WeChatOAuthConfig = {
        mode,
        appId: mode === "open" ? openId : mpId,
        appSecret: mode === "open" ? openSecret : mpSecret,
        authorizeUrl: first(
            env[`WECHAT_CONNECT_${mode.toUpperCase()}_AUTHORIZE_URL`],
            mode === "open" ? "https://open.weixin.qq.com/connect/qrconnect" : "https://open.weixin.qq.com/connect/oauth2/authorize"
        ),
        tokenUrl: first(env.WECHAT_CONNECT_TOKEN_URL, "https://api.weixin.qq.com/sns/oauth2/access_token"),
        userInfoUrl: first(env.WECHAT_CONNECT_USERINFO_URL, "https://api.weixin.qq.com/sns/userinfo"),
        scope: normalizeScope(first(settings.wechat_connect_scopes, env.WECHAT_CONNECT_SCOPES), mode),
        redirectUrl: first(settings.wechat_connect_redirect_url, env.WECHAT_CONNECT_REDIRECT_URL, callbackFallback),
        frontendRedirectUrl: first(settings.wechat_connect_frontend_redirect_url, env.WECHAT_CONNECT_FRONTEND_REDIRECT_URL, "/auth/wechat/callback"),
        requiresUnionId: openEnabled && mpEnabled
    };
    validateConfig(config);
    return config;
}

export function resolveWeChatMode(raw: string | null, userAgent = ""): WeChatOAuthMode {
    const mode = raw?.trim().toLowerCase() ?? "";
    if (mode === "") return userAgent.toLowerCase().includes("micromessenger") ? "mp" : "open";
    if (mode !== "open" && mode !== "mp") throw new WeChatOAuthError("invalid_mode", 400, "wechat oauth mode must be open or mp");
    return mode;
}

export function buildWeChatAuthorizeUrl(config: WeChatOAuthConfig, state: string): string {
    const url = new URL(config.authorizeUrl);
    url.searchParams.set("appid", config.appId);
    url.searchParams.set("redirect_uri", config.redirectUrl);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", config.scope);
    url.searchParams.set("state", state);
    url.hash = "wechat_redirect";
    return url.toString();
}

function validateConfig(config: WeChatOAuthConfig): void {
    if (config.appId === "" || config.appSecret === "" || config.redirectUrl === "") {
        throw new WeChatOAuthError("oauth_config_invalid", 503, "wechat oauth configuration is incomplete");
    }
    for (const value of [config.authorizeUrl, config.tokenUrl, config.userInfoUrl, config.redirectUrl]) {
        try { if (!/^https?:$/u.test(new URL(value).protocol)) throw new TypeError(); } catch {
            throw new WeChatOAuthError("oauth_config_invalid", 503, "wechat oauth URL is invalid");
        }
    }
}

function normalizeScope(raw: string, mode: WeChatOAuthMode): string {
    if (mode === "open") return "snsapi_login";
    return raw === "snsapi_base" ? "snsapi_base" : "snsapi_userinfo";
}

async function stateKey(state: string, browser: string) {
    return `oauth-wechat-state:${await sha256Hex(`${state}\n${browser}`)}`;
}

function opaque(value: string): string {
    const result = value.trim();
    if (!/^[A-Za-z0-9_-]{32,256}$/u.test(result)) throw new WeChatOAuthError("invalid_state", 400, "invalid oauth state");
    return result;
}

function fallbackUsername(subject: string): string {
    return `wechat_${subject.replace(/[^A-Za-z0-9_-]/gu, "_").slice(0, 64) || "user"}`;
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

function bool(value: string): boolean {
    return value.trim().toLowerCase() === "true";
}

function enabled(setting: string | undefined, environment: string | undefined, fallback: boolean): boolean {
    const raw = first(setting, environment);
    return raw === "" ? fallback : bool(raw);
}

function numberValue(value: unknown): number {
    return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function isObject(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}
