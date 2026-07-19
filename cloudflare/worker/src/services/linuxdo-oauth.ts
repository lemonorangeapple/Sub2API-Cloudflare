import type { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import { base64Encode, base64UrlEncode, randomHex, sha256, sha256Hex, utf8 } from "../utils/crypto.ts";

const STATE_TTL_MS = 10 * 60 * 1000;
const SYNTHETIC_EMAIL_DOMAIN = "@linuxdo-connect.invalid";
const MAX_SUBJECT_LENGTH = 64 - "linuxdo-".length;

export interface LinuxDoOAuthConfig {
    enabled: boolean;
    clientId: string;
    clientSecret: string;
    authorizeUrl: string;
    tokenUrl: string;
    userInfoUrl: string;
    scopes: string;
    redirectUrl: string;
    frontendRedirectUrl: string;
    tokenAuthMethod: "client_secret_post" | "client_secret_basic" | "none";
    usePkce: boolean;
    userInfoEmailPath: string;
    userInfoIdPath: string;
    userInfoUsernamePath: string;
}

export interface LinuxDoOAuthState {
    browserSessionKey: string;
    redirectTo: string;
    intent: "login" | "bind_current_user";
    bindUserId: number | null;
    promoCode: string;
    codeVerifier: string;
}

export interface LinuxDoOAuthStartResult {
    authorizeUrl: string;
    state: string;
    browserSessionKey: string;
}

export interface LinuxDoUserInfo {
    email: string;
    compatEmail: string;
    username: string;
    subject: string;
    displayName: string;
    avatarUrl: string;
}

export class LinuxDoOAuthError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "LinuxDoOAuthError";
        this.code = code;
        this.status = status;
    }
}

export class D1LinuxDoOAuthStateService {
    readonly #state: D1ExpiringStateRepository;
    readonly #opaqueTokenFactory: () => string;

    constructor(
        state: D1ExpiringStateRepository,
        opaqueTokenFactory: () => string = () => randomHex(32)
    ) {
        this.#state = state;
        this.#opaqueTokenFactory = opaqueTokenFactory;
    }

    async create(
        config: LinuxDoOAuthConfig,
        input: Omit<LinuxDoOAuthState, "browserSessionKey" | "codeVerifier">
    ): Promise<LinuxDoOAuthStartResult> {
        validateConfig(config);
        const state = this.#opaqueTokenFactory();
        const browserSessionKey = this.#opaqueTokenFactory();
        const codeVerifier = config.usePkce ? this.#opaqueTokenFactory() : "";
        await this.#state.put(await stateKey(state, browserSessionKey), {
            ...input,
            browserSessionKey,
            codeVerifier
        } satisfies LinuxDoOAuthState, STATE_TTL_MS);

        const url = new URL(config.authorizeUrl);
        url.searchParams.set("response_type", "code");
        url.searchParams.set("client_id", config.clientId);
        url.searchParams.set("redirect_uri", config.redirectUrl);
        if (config.scopes !== "") url.searchParams.set("scope", config.scopes);
        url.searchParams.set("state", state);
        if (codeVerifier !== "") {
            url.searchParams.set("code_challenge", base64UrlEncode(await sha256(codeVerifier)));
            url.searchParams.set("code_challenge_method", "S256");
        }
        return { authorizeUrl: url.toString(), state, browserSessionKey };
    }

    async consume(state: string, browserSessionKeyValue: string): Promise<LinuxDoOAuthState> {
        const normalized = state.trim();
        const browserSessionKey = browserSessionKeyValue.trim();
        if (!/^[a-f0-9]{64}$/u.test(normalized)) {
            throw new LinuxDoOAuthError("invalid_state", 400, "invalid oauth state");
        }
        if (!/^[a-f0-9]{64}$/u.test(browserSessionKey)) {
            throw new LinuxDoOAuthError("invalid_state", 400, "invalid oauth browser session");
        }
        const stored = await this.#state.take<LinuxDoOAuthState>(
            await stateKey(normalized, browserSessionKey)
        );
        if (stored === null) {
            throw new LinuxDoOAuthError("invalid_state", 400, "invalid or expired oauth state");
        }
        return stored.value;
    }
}

export class LinuxDoOAuthClient {
    readonly #fetch: typeof fetch;

    constructor(fetchImplementation: typeof fetch = fetch) {
        this.#fetch = fetchImplementation;
    }

    async fetchUser(config: LinuxDoOAuthConfig, codeValue: string, codeVerifier = ""): Promise<LinuxDoUserInfo> {
        validateConfig(config);
        const code = codeValue.trim();
        if (code === "") {
            throw new LinuxDoOAuthError("missing_params", 400, "missing oauth code");
        }
        const form = new URLSearchParams({
            grant_type: "authorization_code",
            client_id: config.clientId,
            code,
            redirect_uri: config.redirectUrl
        });
        if (codeVerifier !== "") form.set("code_verifier", codeVerifier);
        const headers = new Headers({
            accept: "application/json",
            "content-type": "application/x-www-form-urlencoded"
        });
        if (config.tokenAuthMethod === "client_secret_post") {
            form.set("client_secret", config.clientSecret);
        } else if (config.tokenAuthMethod === "client_secret_basic") {
            headers.set(
                "authorization",
                `Basic ${base64Encode(utf8(`${config.clientId}:${config.clientSecret}`))}`
            );
        }

        const tokenResponse = await this.#fetch(config.tokenUrl, {
            method: "POST",
            headers,
            body: form.toString()
        });
        const tokenBody = await tokenResponse.text();
        if (!tokenResponse.ok) {
            throw new LinuxDoOAuthError(
                "token_exchange_failed",
                502,
                providerErrorMessage(tokenBody, "failed to exchange oauth code")
            );
        }
        const token = parseTokenResponse(tokenBody);
        if (token.accessToken === "") {
            throw new LinuxDoOAuthError("token_exchange_failed", 502, "oauth token response is invalid");
        }
        const userResponse = await this.#fetch(config.userInfoUrl, {
            headers: {
                accept: "application/json",
                authorization: `${token.tokenType || "Bearer"} ${token.accessToken}`
            }
        });
        const userBody = await userResponse.text();
        if (!userResponse.ok) {
            throw new LinuxDoOAuthError("userinfo_failed", 502, "failed to fetch oauth user info");
        }
        return parseUserInfo(userBody, config);
    }
}

export function resolveLinuxDoOAuthConfig(
    settings: Record<string, string>,
    env: Record<string, string | undefined>
): LinuxDoOAuthConfig {
    const tokenAuthMethod = firstNonEmpty(env.LINUXDO_TOKEN_AUTH_METHOD, "client_secret_post").toLowerCase();
    if (!isTokenAuthMethod(tokenAuthMethod)) {
        throw new LinuxDoOAuthError("oauth_config_invalid", 503, "oauth token auth method is invalid");
    }
    return {
        enabled: settings.linuxdo_connect_enabled === "true",
        clientId: firstNonEmpty(settings.linuxdo_connect_client_id, env.LINUXDO_CLIENT_ID),
        clientSecret: firstNonEmpty(settings.linuxdo_connect_client_secret, env.LINUXDO_CLIENT_SECRET),
        authorizeUrl: firstNonEmpty(env.LINUXDO_AUTHORIZE_URL, "https://connect.linux.do/oauth2/authorize"),
        tokenUrl: firstNonEmpty(env.LINUXDO_TOKEN_URL, "https://connect.linux.do/oauth2/token"),
        userInfoUrl: firstNonEmpty(env.LINUXDO_USERINFO_URL, "https://connect.linux.do/api/user"),
        scopes: firstNonEmpty(env.LINUXDO_SCOPES, "user"),
        redirectUrl: firstNonEmpty(settings.linuxdo_connect_redirect_url, env.LINUXDO_REDIRECT_URL),
        frontendRedirectUrl: firstNonEmpty(env.LINUXDO_FRONTEND_REDIRECT_URL, "/auth/linuxdo/callback"),
        tokenAuthMethod,
        usePkce: env.LINUXDO_USE_PKCE?.trim().toLowerCase() === "true",
        userInfoEmailPath: env.LINUXDO_USERINFO_EMAIL_PATH?.trim() ?? "",
        userInfoIdPath: env.LINUXDO_USERINFO_ID_PATH?.trim() ?? "",
        userInfoUsernamePath: env.LINUXDO_USERINFO_USERNAME_PATH?.trim() ?? ""
    };
}

function validateConfig(config: LinuxDoOAuthConfig): void {
    if (!config.enabled) throw new LinuxDoOAuthError("oauth_disabled", 404, "oauth login is disabled");
    for (const [label, value] of [
        ["client id", config.clientId],
        ["authorize url", config.authorizeUrl],
        ["token url", config.tokenUrl],
        ["userinfo url", config.userInfoUrl],
        ["redirect url", config.redirectUrl],
        ["frontend redirect url", config.frontendRedirectUrl]
    ] as const) {
        if (value.trim() === "") {
            throw new LinuxDoOAuthError("oauth_config_invalid", 503, `oauth ${label} is not configured`);
        }
    }
    if (config.tokenAuthMethod !== "none" && config.clientSecret.trim() === "") {
        throw new LinuxDoOAuthError("oauth_config_invalid", 503, "oauth client secret is not configured");
    }
    for (const value of [config.authorizeUrl, config.tokenUrl, config.userInfoUrl, config.redirectUrl]) {
        assertHttpUrl(value);
    }
    assertFrontendRedirect(config.frontendRedirectUrl);
}

function parseTokenResponse(body: string): { accessToken: string; tokenType: string } {
    const trimmed = body.trim();
    try {
        const parsed: unknown = JSON.parse(trimmed);
        if (isObject(parsed)) {
            return {
                accessToken: stringValue(parsed.access_token),
                tokenType: stringValue(parsed.token_type)
            };
        }
    } catch {
        // Some OAuth servers return application/x-www-form-urlencoded despite an Accept JSON header.
    }
    const values = new URLSearchParams(trimmed);
    return {
        accessToken: values.get("access_token")?.trim() ?? "",
        tokenType: values.get("token_type")?.trim() ?? ""
    };
}

function parseUserInfo(body: string, config: LinuxDoOAuthConfig): LinuxDoUserInfo {
    let parsed: unknown;
    try {
        parsed = JSON.parse(body);
    } catch {
        throw new LinuxDoOAuthError("userinfo_failed", 502, "oauth user info response is invalid");
    }
    if (!isObject(parsed)) {
        throw new LinuxDoOAuthError("userinfo_failed", 502, "oauth user info response is invalid");
    }
    const subject = firstPath(parsed, [
        config.userInfoIdPath, "sub", "id", "user_id", "uid", "user.id"
    ]);
    if (!new RegExp(`^[A-Za-z0-9_-]{1,${MAX_SUBJECT_LENGTH}}$`, "u").test(subject)) {
        throw new LinuxDoOAuthError("userinfo_failed", 502, "oauth user info is missing a safe id");
    }
    const compatEmail = firstPath(parsed, [
        config.userInfoEmailPath, "email", "user.email", "data.email", "attributes.email"
    ]);
    const username = firstPath(parsed, [
        config.userInfoUsernamePath, "username", "preferred_username", "name", "user.username", "user.name"
    ]) || `linuxdo_${subject}`;
    const displayName = firstPath(parsed, [
        "name", "nickname", "display_name", "user.name", "user.username"
    ]) || username;
    const avatarUrl = firstPath(parsed, [
        "avatar_url", "avatar", "picture", "profile_image_url", "user.avatar", "user.avatar_url"
    ]);
    return {
        email: `linuxdo-${subject}${SYNTHETIC_EMAIL_DOMAIN}`,
        compatEmail,
        username,
        subject,
        displayName,
        avatarUrl
    };
}

function firstPath(value: Record<string, unknown>, paths: readonly string[]): string {
    for (const path of paths) {
        const normalized = path.trim();
        if (normalized === "") continue;
        let current: unknown = value;
        for (const part of normalized.split(".")) {
            current = isObject(current) ? current[part] : undefined;
        }
        const result = stringValue(current);
        if (result !== "") return result;
    }
    return "";
}

function providerErrorMessage(body: string, fallback: string): string {
    try {
        const parsed: unknown = JSON.parse(body);
        if (isObject(parsed)) {
            return firstNonEmpty(
                stringValue(parsed.error_description),
                stringValue(parsed.message),
                stringValue(parsed.error),
                fallback
            );
        }
    } catch {
        const values = new URLSearchParams(body);
        return firstNonEmpty(
            values.get("error_description") ?? "",
            values.get("error") ?? "",
            fallback
        );
    }
    return fallback;
}

async function stateKey(state: string, browserSessionKey: string): Promise<string> {
    return `oauth-linuxdo-state:${await sha256Hex(`${state}\n${browserSessionKey}`)}`;
}

function assertHttpUrl(value: string): void {
    let url: URL;
    try { url = new URL(value); } catch {
        throw new LinuxDoOAuthError("oauth_config_invalid", 503, "oauth URL is invalid");
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") {
        throw new LinuxDoOAuthError("oauth_config_invalid", 503, "oauth URL is invalid");
    }
}

function assertFrontendRedirect(value: string): void {
    if (value.startsWith("/")) return;
    assertHttpUrl(value);
}

function isTokenAuthMethod(value: string): value is LinuxDoOAuthConfig["tokenAuthMethod"] {
    return value === "client_secret_post" || value === "client_secret_basic" || value === "none";
}

function firstNonEmpty(...values: Array<string | undefined>): string {
    for (const value of values) {
        const normalized = value?.trim() ?? "";
        if (normalized !== "") return normalized;
    }
    return "";
}

function stringValue(value: unknown): string {
    if (typeof value === "string" || typeof value === "number") return String(value).trim();
    return "";
}

function isObject(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}
