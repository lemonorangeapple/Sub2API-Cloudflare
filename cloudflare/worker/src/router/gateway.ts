import type { D1Database, D1Value } from "../types/d1.ts";
import { classifyBackendRoute } from "../routes.ts";
import { firstRow, runStatement } from "../repositories/d1.ts";
import { routerError } from "./responses.ts";

interface GatewayEnv {
    DB?: D1Database;
}

interface GatewayKeyRow {
    id: number;
    user_id: number;
    group_id: number | null;
    status: string;
    quota: number;
    quota_used: number;
    expires_at: string | null;
    user_status: string;
}

interface GatewayAccountRow {
    id: number;
    platform: string;
    credentials: string;
    extra: string;
}

const GATEWAY_FAMILIES = new Set([
    "v1", "v1beta", "responses", "alpha-search", "images", "videos",
    "chat-completions", "embeddings", "antigravity"
]);

export async function routeGateway(request: Request, env: GatewayEnv): Promise<Response | null> {
    const url = new URL(request.url);
    const family = classifyBackendRoute(url.pathname);
    if (family === null || !GATEWAY_FAMILIES.has(family)) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    const rawKey = readApiKey(request);
    if (rawKey === "") return openAIError(401, "invalid_api_key", "Missing API key");

    const key = await firstRow<GatewayKeyRow>(env.DB, `
        SELECT k.id, k.user_id, k.group_id, k.status, k.quota, k.quota_used, k.expires_at,
               u.status AS user_status
        FROM api_keys k
        JOIN users u ON u.id = k.user_id AND u.deleted_at IS NULL
        WHERE k.key = ? AND k.deleted_at IS NULL
        LIMIT 1
    `, [rawKey]);
    const rejection = validateKey(key);
    if (rejection !== null) return rejection;

    const account = await selectAccount(env.DB, key!.group_id);
    if (account === null) return openAIError(503, "no_available_account", "No schedulable upstream account is available");

    let upstream: { url: URL; headers: Headers };
    try {
        upstream = buildUpstream(request, url, account);
    } catch (error) {
        return openAIError(503, "account_configuration_error", error instanceof Error ? error.message : "Invalid account configuration");
    }

    const startedAt = Date.now();
    try {
        const response = await fetch(upstream.url, {
            method: request.method,
            headers: upstream.headers,
            body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
            redirect: "manual"
        });
        const now = new Date().toISOString();
        await Promise.all([
            runStatement(env.DB, "UPDATE api_keys SET last_used_at = ?, updated_at = ? WHERE id = ?", [now, now, key!.id]),
            runStatement(env.DB, "UPDATE accounts SET last_used_at = ?, updated_at = ?, error_message = NULL WHERE id = ?", [now, now, account.id])
        ]);
        const headers = new Headers(response.headers);
        headers.set("x-sub2api-account-id", String(account.id));
        headers.set("x-sub2api-upstream-latency-ms", String(Date.now() - startedAt));
        return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
    } catch (error) {
        const message = error instanceof Error ? error.message : "Upstream request failed";
        await runStatement(env.DB, "UPDATE accounts SET error_message = ?, updated_at = ? WHERE id = ?", [message, new Date().toISOString(), account.id]);
        return openAIError(502, "upstream_error", message);
    }
}

function readApiKey(request: Request): string {
    const authorization = request.headers.get("authorization")?.trim() ?? "";
    if (authorization.toLowerCase().startsWith("bearer ")) return authorization.slice(7).trim();
    return (request.headers.get("x-api-key") ?? request.headers.get("api-key") ?? "").trim();
}

function validateKey(key: GatewayKeyRow | null): Response | null {
    if (key === null) return openAIError(401, "invalid_api_key", "Invalid API key");
    if (key.status !== "active" || key.user_status !== "active") return openAIError(403, "account_inactive", "API key or user is inactive");
    if (key.expires_at !== null && Date.parse(key.expires_at) <= Date.now()) return openAIError(401, "api_key_expired", "API key has expired");
    if (key.quota > 0 && key.quota_used >= key.quota) return openAIError(429, "quota_exceeded", "API key quota has been exhausted");
    return null;
}

async function selectAccount(db: D1Database, groupId: number | null): Promise<GatewayAccountRow | null> {
    const now = new Date().toISOString();
    const values: D1Value[] = [now, now, now];
    let groupClause = "";
    if (groupId !== null) {
        groupClause = "AND EXISTS (SELECT 1 FROM account_groups ag WHERE ag.account_id = a.id AND ag.group_id = ?)";
        values.push(groupId);
    }
    return firstRow<GatewayAccountRow>(db, `
        SELECT a.id, a.platform, a.credentials, a.extra
        FROM accounts a
        WHERE a.deleted_at IS NULL AND a.status = 'active' AND a.schedulable = 1
          AND (a.expires_at IS NULL OR a.expires_at > ?)
          AND (a.rate_limit_reset_at IS NULL OR a.rate_limit_reset_at <= ?)
          AND (a.temp_unschedulable_until IS NULL OR a.temp_unschedulable_until <= ?)
          ${groupClause}
        ORDER BY a.priority ASC, COALESCE(a.last_used_at, a.created_at) ASC, a.id ASC
        LIMIT 1
    `, values);
}

function buildUpstream(request: Request, incoming: URL, account: GatewayAccountRow): { url: URL; headers: Headers } {
    const credentials = parseObject(account.credentials);
    const extra = parseObject(account.extra);
    const platform = account.platform.toLowerCase();
    const defaultBase = platform === "anthropic" || platform === "antigravity"
        ? "https://api.anthropic.com"
        : platform === "gemini"
            ? "https://generativelanguage.googleapis.com"
            : platform === "grok"
                ? "https://api.x.ai"
                : "https://api.openai.com";
    const base = stringValue(credentials.base_url, credentials.baseUrl, extra.base_url, extra.baseUrl) || defaultBase;
    const upstream = new URL(base);
    upstream.pathname = joinPath(upstream.pathname, incoming.pathname);
    upstream.search = incoming.search;

    const headers = new Headers(request.headers);
    headers.delete("host");
    headers.delete("content-length");
    headers.delete("cf-connecting-ip");
    headers.delete("x-forwarded-for");
    headers.delete("x-real-ip");
    const token = stringValue(credentials.api_key, credentials.apiKey, credentials.access_token, credentials.accessToken, credentials.token);
    if (token === "") throw new Error(`Account ${account.id} has no upstream credential`);
    if (platform === "anthropic" || platform === "antigravity") {
        headers.set("x-api-key", token);
        headers.delete("authorization");
        if (!headers.has("anthropic-version")) headers.set("anthropic-version", "2023-06-01");
    } else if (platform === "gemini" && !headers.has("authorization")) {
        upstream.searchParams.set("key", token);
        headers.delete("x-api-key");
    } else {
        headers.set("authorization", `Bearer ${token}`);
        headers.delete("x-api-key");
        headers.delete("api-key");
    }
    return { url: upstream, headers };
}

function parseObject(value: string): Record<string, unknown> {
    try {
        const parsed = JSON.parse(value);
        return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {};
    } catch {
        return {};
    }
}

function stringValue(...values: unknown[]): string {
    for (const value of values) if (typeof value === "string" && value.trim() !== "") return value.trim();
    return "";
}

function joinPath(base: string, path: string): string {
    const prefix = base === "/" ? "" : base.replace(/\/$/, "");
    const normalizedPath = path.replace(/^\//, "");
    const normalizedPrefix = prefix.replace(/^\//, "");
    if (normalizedPrefix !== "" && (normalizedPath === normalizedPrefix || normalizedPath.startsWith(`${normalizedPrefix}/`))) {
        return `/${normalizedPath}`;
    }
    const prefixSegment = normalizedPrefix.split("/").filter(Boolean).pop();
    if (prefixSegment && (normalizedPath === prefixSegment || normalizedPath.startsWith(`${prefixSegment}/`))) {
        return `${prefix}/${normalizedPath.slice(prefixSegment.length).replace(/^\//, "")}`;
    }
    return `${prefix}/${normalizedPath}`;
}

function openAIError(status: number, code: string, message: string): Response {
    return new Response(JSON.stringify({ error: { message, type: code, code } }), {
        status,
        headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }
    });
}
