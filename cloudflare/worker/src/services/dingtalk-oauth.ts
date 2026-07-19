import type { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import { randomHex, sha256Hex } from "../utils/crypto.ts";

export interface DingTalkOAuthConfig {
    enabled: boolean;
    clientId: string;
    clientSecret: string;
    authorizeUrl: string;
    tokenUrl: string;
    userInfoUrl: string;
    appTokenUrl: string;
    userByUnionIdUrl: string;
    staffInfoUrl: string;
    departmentInfoUrl: string;
    scopes: string;
    redirectUrl: string;
    frontendRedirectUrl: string;
    corpPolicy: "none" | "internal_only";
    bypassRegistration: boolean;
    requireEmail: boolean;
}

export interface DingTalkOAuthState {
    browserSessionKey: string;
    intent: "login" | "bind_current_user";
    bindUserId: number | null;
    redirectTo: string;
    promoCode: string;
}

export interface DingTalkIdentity {
    subject: string;
    corpId: string;
    corpUserId: string;
    email: string;
    username: string;
    displayName: string;
    nickname: string;
    primaryDeptId: number;
    syntheticEmail: string;
}

export class DingTalkOAuthError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "DingTalkOAuthError";
        this.code = code;
        this.status = status;
    }
}

export class D1DingTalkOAuthStateService {
    readonly #state: D1ExpiringStateRepository;
    readonly #tokens: () => string;

    constructor(state: D1ExpiringStateRepository, tokenFactory: () => string = () => randomHex(32)) {
        this.#state = state;
        this.#tokens = tokenFactory;
    }

    async create(config: DingTalkOAuthConfig, input: Omit<DingTalkOAuthState, "browserSessionKey">) {
        validateConfig(config);
        const state = opaque(this.#tokens());
        const browserSessionKey = opaque(this.#tokens());
        await this.#state.put(await stateKey(state, browserSessionKey), {
            ...input,
            browserSessionKey
        } satisfies DingTalkOAuthState, 10 * 60 * 1000);
        return { state, browserSessionKey, authorizeUrl: buildDingTalkAuthorizeUrl(config, state) };
    }

    async consume(stateValue: string, browserValue: string): Promise<DingTalkOAuthState> {
        const state = opaque(stateValue);
        const browser = opaque(browserValue);
        const stored = await this.#state.take<DingTalkOAuthState>(await stateKey(state, browser));
        if (stored === null || stored.value.browserSessionKey !== browser) {
            throw new DingTalkOAuthError("invalid_state", 400, "invalid or expired dingtalk oauth state");
        }
        return stored.value;
    }
}

export class DingTalkOAuthClient {
    readonly #fetch: typeof fetch;

    constructor(fetchImplementation: typeof fetch = fetch) {
        this.#fetch = fetchImplementation;
    }

    async fetchIdentity(config: DingTalkOAuthConfig, codeValue: string): Promise<DingTalkIdentity> {
        validateConfig(config);
        const code = codeValue.trim();
        if (code === "") throw new DingTalkOAuthError("missing_params", 400, "missing oauth code");
        const userToken = await this.#json(config.tokenUrl, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                clientId: config.clientId,
                clientSecret: config.clientSecret,
                code,
                grantType: "authorization_code"
            })
        }, "exchange_code");
        const accessToken = text(userToken.accessToken);
        if (accessToken === "") throw providerError("exchange_code", userToken);
        const corpId = text(userToken.corpId);
        const me = await this.#json(config.userInfoUrl, {
            headers: { "x-acs-dingtalk-access-token": accessToken }
        }, "get_union_id");
        const subject = text(me.unionId);
        if (!/^[A-Za-z0-9_-]{1,55}$/u.test(subject)) {
            throw new DingTalkOAuthError("userinfo_failed", 502, "dingtalk unionId is invalid");
        }
        const nickname = bounded(text(me.nick), 100);
        let staff = emptyStaff();
        try {
            staff = await this.#fetchStaff(config, subject);
        } catch (error) {
            if (config.corpPolicy === "internal_only") throw error;
        }
        const email = usableEmail(staff.email);
        const displayName = nickname || staff.name;
        return {
            subject,
            corpId,
            corpUserId: staff.userId,
            email,
            username: staff.name,
            displayName,
            nickname,
            primaryDeptId: staff.deptIds.find((value) => value > 1)
                ?? staff.deptIds.find((value) => value > 0) ?? 0,
            syntheticEmail: `dingtalk-${subject.toLowerCase()}@dingtalk-connect.invalid`
        };
    }

    async resolveDepartmentPath(config: DingTalkOAuthConfig, departmentId: number): Promise<string> {
        validateConfig(config);
        if (!Number.isSafeInteger(departmentId) || departmentId <= 0) return "";
        const appTokenValue = await this.#json(config.appTokenUrl, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ appKey: config.clientId, appSecret: config.clientSecret })
        }, "get_app_token");
        const appToken = text(appTokenValue.accessToken);
        if (appToken === "") throw providerError("get_app_token", appTokenValue);
        const parts: string[] = [];
        const visited = new Set<number>();
        let current = departmentId;
        for (let depth = 0; depth < 50 && current > 0 && !visited.has(current); depth += 1) {
            visited.add(current);
            const value = await this.#json(withAccessToken(config.departmentInfoUrl, appToken), {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ dept_id: current, language: "zh_CN" })
            }, "get_department");
            assertLegacySuccess(value, "get_department");
            const result = object(value.result);
            const name = bounded(text(result.name), 200);
            if (name !== "") parts.unshift(name);
            const parent = Number(result.parent_id);
            if (!Number.isSafeInteger(parent) || parent < 1 || parent === current) break;
            current = parent;
        }
        if (parts.length > 0) parts.shift();
        return parts.join("/");
    }

    async #fetchStaff(config: DingTalkOAuthConfig, unionId: string) {
        const appTokenValue = await this.#json(config.appTokenUrl, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ appKey: config.clientId, appSecret: config.clientSecret })
        }, "get_app_token");
        const appToken = text(appTokenValue.accessToken);
        if (appToken === "") throw providerError("get_app_token", appTokenValue);
        const userUrl = withAccessToken(config.userByUnionIdUrl, appToken);
        const userValue = await this.#json(userUrl, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ unionid: unionId })
        }, "get_user_id");
        assertLegacySuccess(userValue, "get_user_id");
        const userId = text(object(userValue.result).userid);
        if (userId === "") throw providerError("get_user_id", userValue);
        const staffValue = await this.#json(withAccessToken(config.staffInfoUrl, appToken), {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ userid: userId })
        }, "get_staff_info");
        assertLegacySuccess(staffValue, "get_staff_info");
        const result = object(staffValue.result);
        const extension = parseExtension(text(result.extension));
        return {
            userId: text(result.userid) || userId,
            name: bounded(text(result.name), 100),
            email: text(result.org_email) || text(result.email) || text(extension["企业邮箱"]),
            deptIds: Array.isArray(result.dept_id_list)
                ? result.dept_id_list.map(Number).filter((value) => Number.isSafeInteger(value) && value > 0)
                : []
        };
    }

    async #json(url: string, init: RequestInit, step: string): Promise<Record<string, unknown>> {
        let response: Response;
        try { response = await this.#fetch(url, init); } catch {
            throw new DingTalkOAuthError("upstream_error", 502, `dingtalk ${step} request failed`);
        }
        let value: unknown;
        try { value = await response.json(); } catch {
            throw new DingTalkOAuthError("upstream_error", 502, `dingtalk ${step} response is invalid`);
        }
        if (!response.ok || !isObject(value)) throw providerError(step, isObject(value) ? value : {});
        return value;
    }
}

export function resolveDingTalkOAuthConfig(
    settings: Record<string, string>,
    env: Record<string, string | undefined>,
    callbackFallback = ""
): DingTalkOAuthConfig {
    const policyValue = first(settings.dingtalk_connect_corp_restriction_policy, env.DINGTALK_CORP_POLICY, "none");
    if (policyValue !== "none" && policyValue !== "internal_only") {
        throw new DingTalkOAuthError("oauth_config_invalid", 503, "dingtalk corp policy is invalid");
    }
    const apiBase = first(env.DINGTALK_API_BASE_URL, "https://api.dingtalk.com").replace(/\/$/u, "");
    const oapiBase = first(env.DINGTALK_OAPI_BASE_URL, "https://oapi.dingtalk.com").replace(/\/$/u, "");
    const config: DingTalkOAuthConfig = {
        enabled: bool(first(settings.dingtalk_connect_enabled, env.DINGTALK_ENABLED)),
        clientId: first(settings.dingtalk_connect_client_id, env.DINGTALK_CLIENT_ID),
        clientSecret: first(env.DINGTALK_CLIENT_SECRET, settings.dingtalk_connect_client_secret),
        authorizeUrl: first(env.DINGTALK_AUTHORIZE_URL, "https://login.dingtalk.com/oauth2/auth"),
        tokenUrl: first(env.DINGTALK_TOKEN_URL, `${apiBase}/v1.0/oauth2/userAccessToken`),
        userInfoUrl: first(env.DINGTALK_USERINFO_URL, `${apiBase}/v1.0/contact/users/me`),
        appTokenUrl: first(env.DINGTALK_APP_TOKEN_URL, `${apiBase}/v1.0/oauth2/accessToken`),
        userByUnionIdUrl: first(env.DINGTALK_USER_BY_UNIONID_URL, `${oapiBase}/topapi/user/getbyunionid`),
        staffInfoUrl: first(env.DINGTALK_STAFF_INFO_URL, `${oapiBase}/topapi/v2/user/get`),
        departmentInfoUrl: first(env.DINGTALK_DEPARTMENT_INFO_URL, `${oapiBase}/topapi/v2/department/get`),
        scopes: first(env.DINGTALK_SCOPES, "openid"),
        redirectUrl: first(settings.dingtalk_connect_redirect_url, env.DINGTALK_REDIRECT_URL, callbackFallback),
        frontendRedirectUrl: first(env.DINGTALK_FRONTEND_REDIRECT_URL, "/auth/dingtalk/callback"),
        corpPolicy: policyValue,
        bypassRegistration: policyValue === "internal_only"
            && bool(first(settings.dingtalk_connect_bypass_registration, env.DINGTALK_BYPASS_REGISTRATION)),
        requireEmail: !/^(false|0)$/iu.test(first(env.DINGTALK_REQUIRE_EMAIL, "true"))
    };
    validateConfig(config);
    return config;
}

export function buildDingTalkAuthorizeUrl(config: DingTalkOAuthConfig, state: string): string {
    const url = new URL(config.authorizeUrl);
    url.searchParams.set("client_id", config.clientId);
    url.searchParams.set("redirect_uri", config.redirectUrl);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", config.scopes || "openid");
    url.searchParams.set("state", state);
    url.searchParams.set("prompt", "consent");
    return url.toString();
}

function validateConfig(config: DingTalkOAuthConfig): void {
    if (!config.enabled) throw new DingTalkOAuthError("oauth_disabled", 404, "dingtalk oauth is disabled");
    if (config.clientId === "" || config.clientSecret === "" || config.redirectUrl === "") {
        throw new DingTalkOAuthError("oauth_config_invalid", 503, "dingtalk oauth configuration is incomplete");
    }
    for (const value of [config.authorizeUrl, config.tokenUrl, config.userInfoUrl, config.appTokenUrl,
        config.userByUnionIdUrl, config.staffInfoUrl, config.departmentInfoUrl, config.redirectUrl]) {
        try { if (!/^https?:$/u.test(new URL(value).protocol)) throw new TypeError(); } catch {
            throw new DingTalkOAuthError("oauth_config_invalid", 503, "dingtalk oauth URL is invalid");
        }
    }
}

function withAccessToken(value: string, token: string): string {
    const url = new URL(value);
    url.searchParams.set("access_token", token);
    return url.toString();
}

function assertLegacySuccess(value: Record<string, unknown>, step: string): void {
    const code = Number(value.errcode ?? 0);
    if (Number.isFinite(code) && code !== 0) throw providerError(step, value);
}

function providerError(step: string, value: Record<string, unknown>): DingTalkOAuthError {
    const providerCode = text(value.code) || text(value.errcode);
    const message = text(value.message) || text(value.errmsg) || `dingtalk ${step} failed`;
    return new DingTalkOAuthError(
        providerCode === "60011" || providerCode === "60121" ? "corp_rejected" : "upstream_error",
        502,
        providerCode === "" ? message : `dingtalk[${providerCode}] ${message}`
    );
}

async function stateKey(state: string, browser: string): Promise<string> {
    return `oauth-dingtalk-state:${await sha256Hex(`${state}\n${browser}`)}`;
}

function opaque(value: string): string {
    const result = value.trim();
    if (!/^[A-Za-z0-9_-]{32,256}$/u.test(result)) {
        throw new DingTalkOAuthError("invalid_state", 400, "invalid dingtalk oauth state");
    }
    return result;
}

function usableEmail(value: string): string {
    const email = value.trim().toLowerCase();
    return email.length <= 254 && /^[^\s@]+@[^\s@]+$/u.test(email) ? email : "";
}

function emptyStaff() {
    return { userId: "", name: "", email: "", deptIds: [] as number[] };
}

function parseExtension(value: string): Record<string, unknown> {
    try { const parsed: unknown = JSON.parse(value); return isObject(parsed) ? parsed : {}; } catch { return {}; }
}

function object(value: unknown): Record<string, unknown> {
    return isObject(value) ? value : {};
}

function bounded(value: string, maximum: number): string {
    return [...value.trim()].slice(0, maximum).join("");
}

function text(value: unknown): string {
    return typeof value === "string" || typeof value === "number" ? String(value).trim() : "";
}

function first(...values: Array<string | undefined>): string {
    return values.map((value) => value?.trim() ?? "").find(Boolean) ?? "";
}

function bool(value: string): boolean {
    return /^(true|1)$/iu.test(value.trim());
}

function isObject(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}
