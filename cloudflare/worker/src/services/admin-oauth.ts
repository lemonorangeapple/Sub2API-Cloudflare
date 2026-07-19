import { D1AccountRepository } from "../repositories/accounts.ts";
import type { D1Database } from "../types/d1.ts";
import { firstRow, runStatement } from "../repositories/d1.ts";

export class AdminOAuthError extends Error {
    readonly status: number;
    readonly code: string;
    constructor(status: number, code: string, message: string) {
        super(message);
        this.status = status;
        this.code = code;
    }
}

const SESSION_TTL_MS = 30 * 60 * 1000;

interface OAuthSession {
    state: string;
    codeVerifier: string;
    codeChallenge: string;
    proxyUrl: string;
    redirectUri: string;
    clientId: string;
    scope: string;
    createdAt: string;
    projectId?: string;
    oauthType?: string;
    tierId?: string;
}

function randomHex(bytes: number): string {
    const arr = new Uint8Array(bytes);
    crypto.getRandomValues(arr);
    return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function base64UrlEncode(buf: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(buf)))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(data: string): Promise<ArrayBuffer> {
    return crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
}

function nowISO(): string {
    return new Date().toISOString();
}

function unixNow(): number {
    return Math.floor(Date.now() / 1000);
}

// Provider configurations
interface OAuthProviderConfig {
    authorizeUrl: string;
    tokenUrl: string;
    clientId: string;
    redirectUri: string;
    scope: string;
}

const GROK_CONFIG: OAuthProviderConfig = {
    authorizeUrl: "https://auth.x.ai/oauth2/authorize",
    tokenUrl: "https://auth.x.ai/oauth2/token",
    clientId: "b1a00492-073a-47ea-816f-4c329264a828",
    redirectUri: "http://127.0.0.1:56121/callback",
    scope: "openid profile email offline_access grok-cli:access api:access",
};
const OPENAI_CONFIG: OAuthProviderConfig = {
    authorizeUrl: "https://auth.openai.com/oauth/authorize",
    tokenUrl: "https://auth.openai.com/oauth/token",
    clientId: "app_EMoamEEZ73f0CkXaXp7hrann",
    redirectUri: "http://localhost:1455/auth/callback",
    scope: "openid profile email offline_access",
};
const GEMINI_CODE_ASSIST_CONFIG: OAuthProviderConfig = {
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    clientId: "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com",
    redirectUri: "https://codeassist.google.com/authcode",
    scope: "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile",
};
const GEMINI_AI_STUDIO_CONFIG: OAuthProviderConfig = {
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    clientId: "",
    redirectUri: "http://localhost:1455/auth/callback",
    scope: "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/generative-language.retriever",
};
const ANTIGRAVITY_CONFIG: OAuthProviderConfig = {
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    clientId: "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com",
    redirectUri: "http://localhost:8085/callback",
    scope: "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/cclog https://www.googleapis.com/auth/experimentsandconfigs",
};

export type OAuthProvider = "openai" | "gemini" | "antigravity" | "grok";

export class D1AdminOAuthService {
    readonly #db: D1Database;
    readonly #repo: D1AccountRepository;

    constructor(db: D1Database) {
        this.#db = db;
        this.#repo = new D1AccountRepository(db);
    }

    // --- Session management ---

    async #saveSession(provider: string, sessionId: string, session: OAuthSession): Promise<void> {
        const key = `oauth_session:${provider}:${sessionId}`;
        await runStatement(
            this.#db,
            `INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)`,
            [key, JSON.stringify(session), nowISO()]
        );
    }

    async #getSession(provider: string, sessionId: string): Promise<OAuthSession | null> {
        const key = `oauth_session:${provider}:${sessionId}`;
        const row = await firstRow<{ value: string }>(
            this.#db,
            `SELECT value FROM settings WHERE key = ?`,
            [key]
        );
        if (!row) return null;
        const session: OAuthSession = JSON.parse(row.value);
        if (Date.now() - new Date(session.createdAt).getTime() > SESSION_TTL_MS) {
            await runStatement(this.#db, `DELETE FROM settings WHERE key = ?`, [key]);
            return null;
        }
        return session;
    }

    async #deleteSession(provider: string, sessionId: string): Promise<void> {
        await runStatement(this.#db, `DELETE FROM settings WHERE key = ?`, [`oauth_session:${provider}:${sessionId}`]);
    }

    // --- PKCE helpers ---

    async #generatePKCE(): Promise<{ codeVerifier: string; codeChallenge: string }> {
        const codeVerifier = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
        const challengeBytes = await sha256(codeVerifier);
        const codeChallenge = base64UrlEncode(challengeBytes);
        return { codeVerifier, codeChallenge };
    }

    async #generatePKCEOpenAI(): Promise<{ codeVerifier: string; codeChallenge: string }> {
        const codeVerifier = randomHex(64);
        const challengeBytes = await sha256(codeVerifier);
        const codeChallenge = base64UrlEncode(challengeBytes);
        return { codeVerifier, codeChallenge };
    }

    // --- OAuth token exchange using fetch ---

    async #exchangeToken(config: OAuthProviderConfig, body: Record<string, string>): Promise<Record<string, unknown>> {
        const params = new URLSearchParams(body);
        const resp = await fetch(config.tokenUrl, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: params.toString(),
            signal: AbortSignal.timeout(30000),
        });
        if (!resp.ok) {
            const text = await resp.text();
            let detail: string;
            try {
                const j = JSON.parse(text);
                detail = j.error_description || j.error || text;
            } catch {
                detail = text;
            }
            throw new AdminOAuthError(502, "TOKEN_EXCHANGE_FAILED", `Token exchange failed: ${detail}`);
        }
        return resp.json();
    }

    // === Grok (xAI) ===

    async grokGenerateAuthURL(proxyId?: number, redirectUri?: string): Promise<{ auth_url: string; session_id: string; state: string }> {
        const state = randomHex(32);
        const nonce = randomHex(16);
        const { codeVerifier, codeChallenge } = await this.#generatePKCE();
        const sessionId = randomHex(16);
        const effectiveRedirect = redirectUri || GROK_CONFIG.redirectUri;
        const effectiveClientId = GROK_CONFIG.clientId;

        const params = new URLSearchParams({
            response_type: "code",
            client_id: effectiveClientId,
            redirect_uri: effectiveRedirect,
            scope: GROK_CONFIG.scope,
            state,
            nonce,
            code_challenge: codeChallenge,
            code_challenge_method: "S256",
            plan: "generic",
            referrer: "sub2api",
        });

        await this.#saveSession("grok", sessionId, {
            state,
            codeVerifier,
            codeChallenge,
            proxyUrl: "",
            redirectUri: effectiveRedirect,
            clientId: effectiveClientId,
            scope: GROK_CONFIG.scope,
            createdAt: nowISO(),
        });

        return { auth_url: `${GROK_CONFIG.authorizeUrl}?${params.toString()}`, session_id: sessionId, state };
    }

    async grokExchangeCode(sessionId: string, code: string, state: string, redirectUri?: string, proxyId?: number): Promise<Record<string, unknown>> {
        const session = await this.#getSession("grok", sessionId);
        if (!session) throw new AdminOAuthError(400, "SESSION_EXPIRED", "OAuth session expired or not found");
        if (session.state !== state) throw new AdminOAuthError(400, "STATE_MISMATCH", "State parameter does not match");
        await this.#deleteSession("grok", sessionId);
        const effectiveRedirect = redirectUri || session.redirectUri;

        const tokenData = await this.#exchangeToken(GROK_CONFIG, {
            grant_type: "authorization_code",
            code,
            redirect_uri: effectiveRedirect,
            client_id: session.clientId,
            code_verifier: session.codeVerifier,
        });

        return this.#enrichGrokToken(tokenData);
    }

    async #enrichGrokToken(tokenData: Record<string, unknown>): Promise<Record<string, unknown>> {
        const expiresIn = Number(tokenData.expires_in) || 0;
        return {
            access_token: tokenData.access_token || "",
            refresh_token: tokenData.refresh_token || "",
            id_token: tokenData.id_token || "",
            token_type: tokenData.token_type || "Bearer",
            expires_in: expiresIn,
            expires_at: expiresIn > 0 ? unixNow() + expiresIn : 0,
            client_id: GROK_CONFIG.clientId,
            scope: GROK_CONFIG.scope,
        };
    }

    async grokRefreshToken(refreshToken: string, proxyId?: number, clientId?: string): Promise<Record<string, unknown>> {
        const effectiveClientId = clientId || GROK_CONFIG.clientId;
        const tokenData = await this.#exchangeToken(GROK_CONFIG, {
            grant_type: "refresh_token",
            refresh_token: refreshToken,
            client_id: effectiveClientId,
        });
        return this.#enrichGrokToken({
            ...tokenData,
            refresh_token: (tokenData.refresh_token as string) || refreshToken,
        });
    }

    async grokBuildAccountCredentials(tokenInfo: Record<string, unknown>): Promise<Record<string, string>> {
        const creds: Record<string, string> = {
            access_token: String(tokenInfo.access_token || ""),
            base_url: "https://cli-chat-proxy.grok.com/v1",
        };
        const expiresAt = Number(tokenInfo.expires_at) || 0;
        if (expiresAt > 0) {
            creds.expires_at = new Date(expiresAt * 1000).toISOString();
        }
        for (const field of ["refresh_token", "token_type", "id_token", "client_id", "scope"]) {
            if (tokenInfo[field]) creds[field] = String(tokenInfo[field]);
        }
        return creds;
    }

    async grokRefreshAccountToken(accountId: number): Promise<Record<string, unknown>> {
        const account = await this.#repo.getById(accountId);
        if (!account) throw new AdminOAuthError(404, "NOT_FOUND", "Account not found");
        if (account.platform !== "grok") throw new AdminOAuthError(400, "PLATFORM_MISMATCH", "Account platform does not match Grok OAuth endpoint");
        if (account.type !== "oauth") throw new AdminOAuthError(400, "NOT_OAUTH", "Cannot refresh non-OAuth account credentials");
        const creds = JSON.parse(account.credentials) as Record<string, string>;
        const refreshToken = creds.refresh_token;
        if (!refreshToken) throw new AdminOAuthError(400, "NO_REFRESH_TOKEN", "Account has no refresh token");
        const tokenInfo = await this.grokRefreshToken(refreshToken);
        const newCredentials = await this.grokBuildAccountCredentials(tokenInfo);
        for (const [k, v] of Object.entries(creds)) {
            if (!(k in newCredentials)) newCredentials[k] = v;
        }
        const updated = await this.#repo.update(accountId, {
            credentials: JSON.stringify(newCredentials),
        });
        if (!updated) throw new AdminOAuthError(500, "UPDATE_FAILED", "Failed to update account credentials");
        return this.#toAccountJson(updated);
    }

    async grokCreateAccountFromOAuth(input: {
        sessionId: string; code: string; state: string; redirectUri?: string;
        proxyId?: number; name?: string; concurrency?: number; priority?: number; groupIds?: number[];
    }): Promise<Record<string, unknown>> {
        const tokenInfo = await this.grokExchangeCode(input.sessionId, input.code, input.state, input.redirectUri, input.proxyId);
        const credentials = await this.grokBuildAccountCredentials(tokenInfo);
        const name = input.name || (tokenInfo.email as string) || "Grok OAuth Account";
        const account = await this.#repo.create({
            name, platform: "grok", type: "oauth",
            credentials: JSON.stringify(credentials),
            proxy_id: input.proxyId ?? null,
            concurrency: input.concurrency ?? 3,
            priority: input.priority ?? 50,
        });
        if (input.groupIds && input.groupIds.length > 0) {
            await this.#repo.setGroups(account.id, input.groupIds);
        }
        return this.#toAccountJson(account);
    }

    async grokCreateAccountsFromSSO(input: {
        sso_tokens?: string[]; sso_token?: string; name?: string; proxy_id?: number;
        group_ids?: number[]; concurrency?: number; priority?: number;
    }): Promise<{ created: Record<string, unknown>[]; failed: { index: number; error: string }[] }> {
        const tokens = this.#normalizeSSOTokens(input.sso_tokens, input.sso_token);
        const created: Record<string, unknown>[] = [];
        const failed: { index: number; error: string }[] = [];
        for (let i = 0; i < tokens.length; i++) {
            try {
                const mockTokenInfo = { access_token: tokens[i], refresh_token: "", expires_in: 86400, email: `user${i + 1}@x.ai` };
                const credentials = await this.grokBuildAccountCredentials(mockTokenInfo);
                const baseName = input.name || mockTokenInfo.email || `Grok SSO #${i + 1}`;
                const accountName = tokens.length > 1 ? `${baseName} #${i + 1}` : baseName;
                const account = await this.#repo.create({
                    name: accountName,
                    platform: "grok", type: "oauth",
                    credentials: JSON.stringify(credentials),
                    proxy_id: input.proxy_id ?? null,
                    concurrency: input.concurrency ?? 3,
                    priority: input.priority ?? 50,
                });
                if (input.group_ids && input.group_ids.length > 0) {
                    await this.#repo.setGroups(account.id, input.group_ids);
                }
                created.push(this.#toAccountJson(account));
            } catch (err) {
                failed.push({ index: i + 1, error: err instanceof Error ? err.message : "unknown error" });
            }
        }
        return { created, failed };
    }

    #normalizeSSOTokens(tokens?: string[], single?: string): string[] {
        const items: string[] = [];
        if (single?.trim()) items.push(single.trim());
        if (tokens) items.push(...tokens);
        const seen = new Set<string>();
        const result: string[] = [];
        for (const item of items) {
            const parts = item.replace(/[,\r]/g, "\n").split("\n");
            for (let part of parts) {
                part = part.trim();
                if (!part || seen.has(part)) continue;
                seen.add(part);
                result.push(part);
            }
        }
        return result;
    }

    async #grokQueryQuota(accountId: number): Promise<Record<string, unknown>> {
        const account = await this.#repo.getById(accountId);
        if (!account) throw new AdminOAuthError(404, "NOT_FOUND", "Account not found");
        try {
            const creds = JSON.parse(account.credentials) as Record<string, unknown>;
            const token = typeof creds.access_token === "string" ? creds.access_token : undefined;
            if (token) {
                const res = await fetch("https://api.x.ai/v1/api/billing/usage", {
                    headers: { authorization: `Bearer ${token}`, accept: "application/json" },
                    signal: AbortSignal.timeout(15000),
                });
                if (res.ok) {
                    const data = await res.json() as Record<string, unknown>;
                    return { enabled: true, account_id: accountId, ...data };
                }
            }
        } catch {
            // Fall through
        }
        return {
            enabled: false,
            reason: "grok quota query failed — check account credentials or upstream API availability",
            account_id: accountId,
        };
    }

    async #grokResetQuota(accountId: number): Promise<Record<string, unknown>> {
        try {
            const account = await this.#repo.getById(accountId);
            if (account) {
                const creds = JSON.parse(account.credentials) as Record<string, unknown>;
                const token = typeof creds.access_token === "string" ? creds.access_token : undefined;
                if (token) {
                    const res = await fetch("https://api.x.ai/v1/api/billing/usage/reset", {
                        method: "POST",
                        headers: { authorization: `Bearer ${token}`, "content-type": "application/json", accept: "application/json" },
                        signal: AbortSignal.timeout(15000),
                    });
                    if (res.ok) {
                        const data = await res.json() as Record<string, unknown>;
                        return { success: true, account_id: accountId, ...data };
                    }
                }
            }
        } catch {
            // Fall through
        }
        return { success: false, reason: "quota reset not available in serverless mode", account_id: accountId };
    }

    grokRuntimeSanity(): Record<string, unknown> {
        const hasClientId = GROK_CONFIG.clientId !== "";
        const hasScopes = GROK_CONFIG.scope !== "";
        return {
            status: "ok",
            mode: "serverless",
            oauth_client_configured: hasClientId,
            authorize_url: GROK_CONFIG.authorizeUrl,
            token_url: GROK_CONFIG.tokenUrl,
            scopes: GROK_CONFIG.scope,
            client_id_present: hasClientId,
        };
    }

    // === OpenAI ===

    async openaiGenerateAuthURL(proxyId?: number, redirectUri?: string): Promise<{ auth_url: string; session_id: string }> {
        const state = randomHex(32);
        const { codeVerifier, codeChallenge } = await this.#generatePKCEOpenAI();
        const sessionId = randomHex(16);
        const effectiveRedirect = redirectUri || OPENAI_CONFIG.redirectUri;

        const params = new URLSearchParams({
            response_type: "code",
            client_id: OPENAI_CONFIG.clientId,
            redirect_uri: effectiveRedirect,
            scope: OPENAI_CONFIG.scope,
            state,
            code_challenge: codeChallenge,
            code_challenge_method: "S256",
            id_token_add_organizations: "true",
            codex_cli_simplified_flow: "true",
        });

        await this.#saveSession("openai", sessionId, {
            state, codeVerifier, codeChallenge,
            proxyUrl: "", redirectUri: effectiveRedirect,
            clientId: OPENAI_CONFIG.clientId, scope: OPENAI_CONFIG.scope,
            createdAt: nowISO(),
        });

        return { auth_url: `${OPENAI_CONFIG.authorizeUrl}?${params.toString()}`, session_id: sessionId };
    }

    async openaiExchangeCode(sessionId: string, code: string, state: string, redirectUri?: string, proxyId?: number): Promise<Record<string, unknown>> {
        const session = await this.#getSession("openai", sessionId);
        if (!session) throw new AdminOAuthError(400, "SESSION_EXPIRED", "OAuth session expired or not found");
        if (session.state !== state) throw new AdminOAuthError(400, "STATE_MISMATCH", "State parameter does not match");
        await this.#deleteSession("openai", sessionId);
        const effectiveRedirect = redirectUri || session.redirectUri;

        const tokenData = await this.#exchangeToken(OPENAI_CONFIG, {
            grant_type: "authorization_code",
            code,
            redirect_uri: effectiveRedirect,
            client_id: session.clientId,
            code_verifier: session.codeVerifier,
        });

        return this.#enrichOpenAIToken(tokenData);
    }

    async #enrichOpenAIToken(tokenData: Record<string, unknown>): Promise<Record<string, unknown>> {
        const expiresIn = Number(tokenData.expires_in) || 0;
        return {
            access_token: tokenData.access_token || "",
            refresh_token: tokenData.refresh_token || "",
            id_token: tokenData.id_token || "",
            expires_in: expiresIn,
            expires_at: expiresIn > 0 ? unixNow() + expiresIn : 0,
            client_id: OPENAI_CONFIG.clientId,
        };
    }

    async openaiRefreshToken(refreshToken: string, proxyId?: number, clientId?: string): Promise<Record<string, unknown>> {
        const effectiveClientId = clientId || OPENAI_CONFIG.clientId;
        const tokenData = await this.#exchangeToken(OPENAI_CONFIG, {
            grant_type: "refresh_token",
            refresh_token: refreshToken,
            client_id: effectiveClientId,
        });
        return this.#enrichOpenAIToken({
            ...tokenData,
            refresh_token: (tokenData.refresh_token as string) || refreshToken,
        });
    }

    async openaiBuildAccountCredentials(tokenInfo: Record<string, unknown>): Promise<Record<string, string>> {
        const creds: Record<string, string> = { access_token: String(tokenInfo.access_token || "") };
        const expiresAt = Number(tokenInfo.expires_at) || 0;
        if (expiresAt > 0) creds.expires_at = new Date(expiresAt * 1000).toISOString();
        for (const field of ["refresh_token", "id_token", "client_id"]) {
            if (tokenInfo[field]) creds[field] = String(tokenInfo[field]);
        }
        return creds;
    }

    async openaiRefreshAccountToken(accountId: number): Promise<Record<string, unknown>> {
        const account = await this.#repo.getById(accountId);
        if (!account) throw new AdminOAuthError(404, "NOT_FOUND", "Account not found");
        if (account.platform !== "openai") throw new AdminOAuthError(400, "PLATFORM_MISMATCH", "Account platform does not match OpenAI OAuth endpoint");
        if (account.type !== "oauth") throw new AdminOAuthError(400, "NOT_OAUTH", "Cannot refresh non-OAuth account credentials");
        const creds = JSON.parse(account.credentials) as Record<string, string>;
        const refreshToken = creds.refresh_token;
        if (!refreshToken) throw new AdminOAuthError(400, "NO_REFRESH_TOKEN", "Account has no refresh token");
        const tokenInfo = await this.openaiRefreshToken(refreshToken);
        const newCredentials = await this.openaiBuildAccountCredentials(tokenInfo);
        for (const [k, v] of Object.entries(creds)) {
            if (!(k in newCredentials)) newCredentials[k] = v;
        }
        const updated = await this.#repo.update(accountId, { credentials: JSON.stringify(newCredentials) });
        if (!updated) throw new AdminOAuthError(500, "UPDATE_FAILED", "Failed to update account credentials");
        return this.#toAccountJson(updated);
    }

    async openaiCreateAccountFromOAuth(input: {
        sessionId: string; code: string; state: string; redirectUri?: string;
        proxyId?: number; name?: string; concurrency?: number; priority?: number; groupIds?: number[];
    }): Promise<Record<string, unknown>> {
        const tokenInfo = await this.openaiExchangeCode(input.sessionId, input.code, input.state, input.redirectUri, input.proxyId);
        const credentials = await this.openaiBuildAccountCredentials(tokenInfo);
        const name = input.name || (tokenInfo.email as string) || "OpenAI OAuth Account";
        const account = await this.#repo.create({
            name, platform: "openai", type: "oauth",
            credentials: JSON.stringify(credentials),
            proxy_id: input.proxyId ?? null,
            concurrency: input.concurrency ?? 3,
            priority: input.priority ?? 50,
        });
        if (input.groupIds && input.groupIds.length > 0) {
            await this.#repo.setGroups(account.id, input.groupIds);
        }
        return this.#toAccountJson(account);
    }

    async openaiCreateFromCodexPAT(input: {
        accessToken: string; name?: string; proxyId?: number;
        concurrency?: number; priority?: number; groupIds?: number[];
        notes?: string; rateMultiplier?: number; loadFactor?: number;
        expiresAt?: number; autoPauseOnExpired?: boolean;
    }): Promise<Record<string, unknown>> {
        const now = unixNow();
        const mockTokenInfo: Record<string, unknown> = {
            access_token: input.accessToken,
            refresh_token: "",
            expires_in: 86400 * 30,
            expires_at: now + 86400 * 30,
        };
        const credentials = await this.openaiBuildAccountCredentials(mockTokenInfo);
        const name = input.name || "Codex PAT Account";
        const account = await this.#repo.create({
            name, platform: "openai", type: "oauth",
            credentials: JSON.stringify(credentials),
            extra: JSON.stringify({
                import_source: "codex_personal_access_token",
                auth_provider: "codex_personal_access_token",
                imported_at: nowISO(),
            }),
            proxy_id: input.proxyId ?? null,
            concurrency: input.concurrency ?? 3,
            priority: input.priority ?? 50,
            rate_multiplier: input.rateMultiplier ?? 1.0,
            load_factor: input.loadFactor ?? null,
            expires_at: input.expiresAt ? new Date(input.expiresAt * 1000).toISOString() : null,
            auto_pause_on_expired: input.autoPauseOnExpired ?? 1,
        });
        if (input.groupIds && input.groupIds.length > 0) {
            await this.#repo.setGroups(account.id, input.groupIds);
        }
        return this.#toAccountJson(account);
    }

    async #openaiQueryQuota(accountId: number): Promise<Record<string, unknown>> {
        const account = await this.#repo.getById(accountId);
        if (!account) throw new AdminOAuthError(404, "NOT_FOUND", "Account not found");
        try {
            const creds = JSON.parse(account.credentials) as Record<string, unknown>;
            const token = typeof creds.access_token === "string" ? creds.access_token : undefined;
            if (token) {
                const subRes = await fetch("https://api.openai.com/v1/dashboard/billing/subscription", {
                    headers: { authorization: `Bearer ${token}`, accept: "application/json" },
                    signal: AbortSignal.timeout(15000),
                });
                if (subRes.ok) {
                    const subData = await subRes.json() as Record<string, unknown>;
                    const grantsRes = await fetch("https://api.openai.com/v1/dashboard/billing/credit_grants", {
                        headers: { authorization: `Bearer ${token}`, accept: "application/json" },
                        signal: AbortSignal.timeout(15000),
                    });
                    let grantsData: Record<string, unknown> = {};
                    if (grantsRes.ok) {
                        grantsData = await grantsRes.json() as Record<string, unknown>;
                    }
                    return {
                        enabled: true,
                        account_id: accountId,
                        subscription: subData,
                        credit_grants: grantsData,
                    };
                }
            }
        } catch {
            // Fall through
        }
        return { enabled: false, reason: "openai quota query failed — check account credentials or upstream API availability", account_id: accountId };
    }

    async #openaiResetQuota(accountId: number): Promise<Record<string, unknown>> {
        return { success: false, reason: "quota reset not available in serverless mode", account_id: accountId };
    }

    // === Gemini ===

    geminiGetCapabilities(): Record<string, unknown> {
        const aiStudioConfigured = GEMINI_AI_STUDIO_CONFIG.clientId !== "";
        const codeAssistConfigured = GEMINI_CODE_ASSIST_CONFIG.clientId !== "";
        return {
            ai_studio_oauth_enabled: aiStudioConfigured,
            code_assist_oauth_enabled: codeAssistConfigured,
            required_redirect_uris: [
                "http://localhost:1455/auth/callback",
                ...(codeAssistConfigured ? ["https://codeassist.google.com/authcode"] : []),
            ],
        };
    }

    async geminiGenerateAuthURL(proxyId?: number, redirectUri?: string, projectId?: string, oauthType = "code_assist", tierId?: string): Promise<{ auth_url: string; session_id: string; state: string }> {
        const state = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
        const { codeVerifier, codeChallenge } = await this.#generatePKCE();
        const sessionId = randomHex(16);
        const isCodeAssist = oauthType === "code_assist" || oauthType === "google_one";
        const config = isCodeAssist ? GEMINI_CODE_ASSIST_CONFIG : GEMINI_AI_STUDIO_CONFIG;
        if (oauthType === "ai_studio" && !config.clientId) {
            throw new AdminOAuthError(400, "CLIENT_NOT_CONFIGURED", "AI Studio OAuth requires your own OAuth Client configuration");
        }
        const effectiveClientId = config.clientId;

        const params = new URLSearchParams({
            response_type: "code",
            client_id: effectiveClientId,
            redirect_uri: redirectUri || config.redirectUri,
            scope: config.scope,
            state,
            code_challenge: codeChallenge,
            code_challenge_method: "S256",
            access_type: "offline",
            prompt: "consent",
            include_granted_scopes: "true",
        });

        await this.#saveSession("gemini", sessionId, {
            state, codeVerifier, codeChallenge,
            proxyUrl: "", redirectUri: redirectUri || config.redirectUri,
            clientId: effectiveClientId, scope: config.scope,
            createdAt: nowISO(),
            projectId, oauthType, tierId,
        });

        return { auth_url: `${config.authorizeUrl}?${params.toString()}`, session_id: sessionId, state };
    }

    async geminiExchangeCode(sessionId: string, state: string, code: string, proxyId?: number, oauthType?: string, tierId?: string): Promise<Record<string, unknown>> {
        const session = await this.#getSession("gemini", sessionId);
        if (!session) throw new AdminOAuthError(400, "SESSION_EXPIRED", "OAuth session expired or not found");
        if (session.state !== state) throw new AdminOAuthError(400, "STATE_MISMATCH", "State parameter does not match");
        await this.#deleteSession("gemini", sessionId);
        const effectiveOAuthType = oauthType || session.oauthType || "code_assist";
        const isCodeAssist = effectiveOAuthType === "code_assist" || effectiveOAuthType === "google_one";
        const config = isCodeAssist ? GEMINI_CODE_ASSIST_CONFIG : GEMINI_AI_STUDIO_CONFIG;
        const clientSecret = GEMINI_CODE_ASSIST_CONFIG.clientId === config.clientId ? "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" : "";

        const tokenData = await this.#exchangeToken(config, {
            grant_type: "authorization_code",
            code,
            redirect_uri: session.redirectUri,
            client_id: session.clientId,
            client_secret: clientSecret,
            code_verifier: session.codeVerifier,
        });

        const expiresIn = Number(tokenData.expires_in) || 0;
        return {
            access_token: tokenData.access_token || "",
            refresh_token: tokenData.refresh_token || "",
            expires_in: expiresIn,
            expires_at: expiresIn > 0 ? unixNow() + expiresIn : 0,
            token_type: tokenData.token_type || "Bearer",
            scope: tokenData.scope || config.scope,
            project_id: session.projectId || "",
            oauth_type: effectiveOAuthType,
            tier_id: tierId || session.tierId || "",
        };
    }

    async geminiRefreshToken(oauthType: string, refreshToken: string, proxyId?: number): Promise<Record<string, unknown>> {
        const isCodeAssist = oauthType === "code_assist" || oauthType === "google_one";
        const config = isCodeAssist ? GEMINI_CODE_ASSIST_CONFIG : GEMINI_AI_STUDIO_CONFIG;
        const clientSecret = GEMINI_CODE_ASSIST_CONFIG.clientId === config.clientId ? "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" : "";
        const tokenData = await this.#exchangeToken(config, {
            grant_type: "refresh_token",
            refresh_token: refreshToken,
            client_id: config.clientId,
            client_secret: clientSecret,
        });
        const expiresIn = Number(tokenData.expires_in) || 0;
        return {
            access_token: tokenData.access_token || "",
            refresh_token: tokenData.refresh_token || refreshToken,
            expires_in: expiresIn,
            expires_at: expiresIn > 0 ? unixNow() + expiresIn : 0,
            token_type: tokenData.token_type || "Bearer",
            scope: tokenData.scope || config.scope,
            oauth_type: oauthType,
        };
    }

    // === Antigravity ===

    async antigravityGenerateAuthURL(proxyId?: number): Promise<{ auth_url: string; session_id: string; state: string }> {
        const state = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
        const { codeVerifier, codeChallenge } = await this.#generatePKCE();
        const sessionId = randomHex(16);

        const params = new URLSearchParams({
            response_type: "code",
            client_id: ANTIGRAVITY_CONFIG.clientId,
            redirect_uri: ANTIGRAVITY_CONFIG.redirectUri,
            scope: ANTIGRAVITY_CONFIG.scope,
            state,
            code_challenge: codeChallenge,
            code_challenge_method: "S256",
            access_type: "offline",
            prompt: "consent",
            include_granted_scopes: "true",
        });

        await this.#saveSession("antigravity", sessionId, {
            state, codeVerifier, codeChallenge,
            proxyUrl: "", redirectUri: ANTIGRAVITY_CONFIG.redirectUri,
            clientId: ANTIGRAVITY_CONFIG.clientId, scope: ANTIGRAVITY_CONFIG.scope,
            createdAt: nowISO(),
        });

        return { auth_url: `${ANTIGRAVITY_CONFIG.authorizeUrl}?${params.toString()}`, session_id: sessionId, state };
    }

    async antigravityExchangeCode(sessionId: string, state: string, code: string, proxyId?: number): Promise<Record<string, unknown>> {
        const session = await this.#getSession("antigravity", sessionId);
        if (!session) throw new AdminOAuthError(400, "SESSION_EXPIRED", "OAuth session expired or not found");
        if (session.state !== state) throw new AdminOAuthError(400, "STATE_MISMATCH", "State parameter does not match");
        await this.#deleteSession("antigravity", sessionId);

        const tokenData = await this.#exchangeToken(ANTIGRAVITY_CONFIG, {
            grant_type: "authorization_code",
            code,
            redirect_uri: session.redirectUri,
            client_id: session.clientId,
            code_verifier: session.codeVerifier,
        });

        const expiresIn = Number(tokenData.expires_in) || 0;
        return {
            access_token: tokenData.access_token || "",
            refresh_token: tokenData.refresh_token || "",
            expires_in: expiresIn,
            expires_at: expiresIn > 0 ? unixNow() + expiresIn : 0,
            token_type: tokenData.token_type || "Bearer",
        };
    }

    async antigravityRefreshToken(refreshToken: string, proxyId?: number): Promise<Record<string, unknown>> {
        const tokenData = await this.#exchangeToken(ANTIGRAVITY_CONFIG, {
            grant_type: "refresh_token",
            refresh_token: refreshToken,
            client_id: ANTIGRAVITY_CONFIG.clientId,
        });
        const expiresIn = Number(tokenData.expires_in) || 0;
        return {
            access_token: tokenData.access_token || "",
            refresh_token: tokenData.refresh_token || refreshToken,
            expires_in: expiresIn,
            expires_at: expiresIn > 0 ? unixNow() + expiresIn : 0,
            token_type: tokenData.token_type || "Bearer",
        };
    }

    // --- Shared helpers ---

    #toAccountJson(a: { id: number; name: string; notes: string; platform: string; type: string; credentials: string; extra: string; proxyFallbackOriginId: number | null; concurrency: number; loadFactor: number | null; priority: number; rateMultiplier: number; status: string; errorMessage: string | null; lastUsedAt: string | null; expiresAt: string | null; autoPauseOnExpired: boolean; schedulable: boolean; rateLimitedAt: string | null; rateLimitResetAt: string | null; overloadUntil: string | null; tempUnschedulableUntil: string | null; tempUnschedulableReason: string | null; sessionWindowStart: string | null; sessionWindowEnd: string | null; sessionWindowStatus: string | null; quotaDimension: string; proxyId: number | null; parentAccountId: number | null; createdAt: string; updatedAt: string; deletedAt: string | null }): Record<string, unknown> {
        return {
            id: a.id,
            name: a.name,
            notes: a.notes,
            platform: a.platform,
            type: a.type,
            credentials: JSON.parse(a.credentials),
            extra: JSON.parse(a.extra),
            proxy_fallback_origin_id: a.proxyFallbackOriginId,
            concurrency: a.concurrency,
            load_factor: a.loadFactor,
            priority: a.priority,
            rate_multiplier: a.rateMultiplier,
            status: a.status,
            error_message: a.errorMessage,
            last_used_at: a.lastUsedAt,
            expires_at: a.expiresAt,
            auto_pause_on_expired: a.autoPauseOnExpired,
            schedulable: a.schedulable,
            proxy_id: a.proxyId,
            parent_account_id: a.parentAccountId,
            created_at: a.createdAt,
            updated_at: a.updatedAt,
        };
    }

    async route(provider: OAuthProvider, action: string, params: Record<string, unknown>): Promise<unknown> {
        const p = (key: string) => params[key];
        switch (provider) {
            case "grok":
                switch (action) {
                    case "generate-auth-url": return this.grokGenerateAuthURL(p("proxy_id") as number | undefined);
                    case "exchange-code": return this.grokExchangeCode(
                        p("session_id") as string, p("code") as string, p("state") as string,
                        p("redirect_uri") as string | undefined, p("proxy_id") as number | undefined
                    );
                    case "refresh-token": return this.grokRefreshToken(
                        (p("refresh_token") || p("rt")) as string, p("proxy_id") as number | undefined, p("client_id") as string | undefined
                    );
                    case "refresh-account-token": return this.grokRefreshAccountToken(p("accountId") as number);
                    case "create-from-oauth": return this.grokCreateAccountFromOAuth({
                        sessionId: p("session_id") as string, code: p("code") as string, state: p("state") as string,
                        redirectUri: p("redirect_uri") as string | undefined, proxyId: p("proxy_id") as number | undefined,
                        name: p("name") as string | undefined, concurrency: p("concurrency") as number | undefined,
                        priority: p("priority") as number | undefined, groupIds: p("group_ids") as number[] | undefined,
                    });
                    case "sso-to-oauth": return this.grokCreateAccountsFromSSO(params as Parameters<typeof this.grokCreateAccountsFromSSO>[0]);
                    case "query-quota": return this.#grokQueryQuota(p("accountId") as number);
                    case "reset-quota": return this.#grokResetQuota(p("accountId") as number);
                    case "runtime-sanity": return this.grokRuntimeSanity();
                    default: throw new AdminOAuthError(404, "NOT_FOUND", "Unknown action");
                }
            case "openai":
                switch (action) {
                    case "generate-auth-url": return this.openaiGenerateAuthURL(p("proxy_id") as number | undefined, p("redirect_uri") as string | undefined);
                    case "exchange-code": return this.openaiExchangeCode(
                        p("session_id") as string, p("code") as string, p("state") as string,
                        p("redirect_uri") as string | undefined, p("proxy_id") as number | undefined
                    );
                    case "refresh-token": return this.openaiRefreshToken(
                        (p("refresh_token") || p("rt")) as string, p("proxy_id") as number | undefined, p("client_id") as string | undefined
                    );
                    case "refresh-account-token": return this.openaiRefreshAccountToken(p("accountId") as number);
                    case "create-from-oauth": return this.openaiCreateAccountFromOAuth({
                        sessionId: p("session_id") as string, code: p("code") as string, state: p("state") as string,
                        redirectUri: p("redirect_uri") as string | undefined, proxyId: p("proxy_id") as number | undefined,
                        name: p("name") as string | undefined, concurrency: p("concurrency") as number | undefined,
                        priority: p("priority") as number | undefined, groupIds: p("group_ids") as number[] | undefined,
                    });
                    case "create-from-codex-pat": return this.openaiCreateFromCodexPAT({
                        accessToken: p("access_token") as string, name: p("name") as string | undefined,
                        proxyId: p("proxy_id") as number | undefined, concurrency: p("concurrency") as number | undefined,
                        priority: p("priority") as number | undefined, groupIds: p("group_ids") as number[] | undefined,
                        notes: p("notes") as string | undefined, rateMultiplier: p("rate_multiplier") as number | undefined,
                        loadFactor: p("load_factor") as number | undefined, expiresAt: p("expires_at") as number | undefined,
                        autoPauseOnExpired: p("auto_pause_on_expired") as boolean | undefined,
                    });
                    case "query-quota": return this.#openaiQueryQuota(p("accountId") as number);
                    case "reset-quota": return this.#openaiResetQuota(p("accountId") as number);
                    default: throw new AdminOAuthError(404, "NOT_FOUND", "Unknown action");
                }
            case "gemini":
                switch (action) {
                    case "get-capabilities": return this.geminiGetCapabilities();
                    case "generate-auth-url": return this.geminiGenerateAuthURL(
                        p("proxy_id") as number | undefined, undefined,
                        p("project_id") as string | undefined, p("oauth_type") as string | undefined, p("tier_id") as string | undefined
                    );
                    case "exchange-code": return this.geminiExchangeCode(
                        p("session_id") as string, p("state") as string, p("code") as string,
                        p("proxy_id") as number | undefined, p("oauth_type") as string | undefined, p("tier_id") as string | undefined
                    );
                    default: throw new AdminOAuthError(404, "NOT_FOUND", "Unknown action");
                }
            case "antigravity":
                switch (action) {
                    case "generate-auth-url": return this.antigravityGenerateAuthURL(p("proxy_id") as number | undefined);
                    case "exchange-code": return this.antigravityExchangeCode(
                        p("session_id") as string, p("state") as string, p("code") as string, p("proxy_id") as number | undefined
                    );
                    case "refresh-token": return this.antigravityRefreshToken(
                        p("refresh_token") as string, p("proxy_id") as number | undefined
                    );
                    default: throw new AdminOAuthError(404, "NOT_FOUND", "Unknown action");
                }
        }
    }
}
