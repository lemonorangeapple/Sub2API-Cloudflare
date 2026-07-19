import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement, runBatchTransaction } from "./d1.ts";

export interface ProxyRecord {
    id: number;
    createdAt: string;
    updatedAt: string;
    deletedAt: string | null;
    name: string;
    protocol: string;
    host: string;
    port: number;
    username: string;
    password: string;
    status: string;
    expiresAt: string | null;
    fallbackMode: string;
    expiryWarnDays: number;
    backupProxyId: number | null;
}

interface ProxyRow {
    id: number;
    created_at: string;
    updated_at: string;
    deleted_at: string | null;
    name: string;
    protocol: string;
    host: string;
    port: number;
    username: string | null;
    password: string | null;
    status: string;
    expires_at: string | null;
    fallback_mode: string;
    expiry_warn_days: number;
    backup_proxy_id: number | null;
}

function rowToRecord(row: ProxyRow): ProxyRecord {
    return {
        id: row.id,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        deletedAt: row.deleted_at,
        name: row.name,
        protocol: row.protocol,
        host: row.host,
        port: row.port,
        username: row.username ?? "",
        password: row.password ?? "",
        status: row.status,
        expiresAt: row.expires_at,
        fallbackMode: row.fallback_mode,
        expiryWarnDays: row.expiry_warn_days,
        backupProxyId: row.backup_proxy_id
    };
}

export interface CreateProxyInput {
    name: string;
    protocol: string;
    host: string;
    port: number;
    username?: string;
    password?: string;
    expiresAt?: string | null;
    fallbackMode?: string;
    backupProxyId?: number | null;
    expiryWarnDays?: number;
}

export interface UpdateProxyInput {
    name?: string;
    protocol?: string;
    host?: string;
    port?: number;
    username?: string;
    password?: string;
    status?: string;
    expiresAt?: string | null;
    fallbackMode?: string;
    backupProxyId?: number | null;
    expiryWarnDays?: number;
}

export interface ListProxiesOptions {
    page: number;
    pageSize: number;
    protocol?: string;
    status?: string;
    search?: string;
    sortBy?: string;
    sortDir?: string;
}

export interface BatchDeleteResult {
    deletedIds: number[];
    skipped: Array<{ id: number; reason: string }>;
}

const ALLOWED_SORT = new Set(["id", "name", "protocol", "host", "port", "status", "created_at", "updated_at", "expires_at"]);
const ALLOWED_DIR = new Set(["asc", "desc"]);

export class D1ProxyRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async list(options: ListProxiesOptions): Promise<{ items: ProxyRecord[]; total: number }> {
        const conditions: string[] = ["deleted_at IS NULL"];
        const values: D1Value[] = [];

        if (options.protocol) {
            conditions.push("protocol = ?");
            values.push(options.protocol);
        }
        if (options.status) {
            conditions.push("status = ?");
            values.push(options.status);
        }
        if (options.search) {
            conditions.push("(name LIKE ? OR host LIKE ?)");
            const pattern = `%${options.search.trim()}%`;
            values.push(pattern, pattern);
        }

        const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

        const countRow = await firstRow<{ count: number }>(
            this.#db,
            `SELECT COUNT(*) AS count FROM proxies ${where}`,
            values
        );
        const total = countRow?.count ?? 0;

        const safeOrder = ALLOWED_SORT.has(options.sortBy ?? "id") ? options.sortBy ?? "id" : "id";
        const safeDir = ALLOWED_DIR.has(options.sortDir ?? "desc") ? options.sortDir ?? "desc" : "desc";
        const offset = (options.page - 1) * options.pageSize;

        const rows = await allRows<ProxyRow>(
            this.#db,
            `SELECT * FROM proxies ${where} ORDER BY ${safeOrder} ${safeDir} LIMIT ? OFFSET ?`,
            [...values, options.pageSize, offset]
        );

        return { items: rows.map(rowToRecord), total };
    }

    async listAll(): Promise<ProxyRecord[]> {
        const rows = await allRows<ProxyRow>(
            this.#db,
            "SELECT * FROM proxies WHERE deleted_at IS NULL ORDER BY id DESC"
        );
        return rows.map(rowToRecord);
    }

    async findById(id: number): Promise<ProxyRecord | null> {
        const row = await firstRow<ProxyRow>(
            this.#db,
            "SELECT * FROM proxies WHERE id = ? AND deleted_at IS NULL",
            [id]
        );
        return row === null ? null : rowToRecord(row);
    }

    async findByHostPortAuth(host: string, port: number, username: string, password: string): Promise<ProxyRecord | null> {
        const row = await firstRow<ProxyRow>(
            this.#db,
            "SELECT * FROM proxies WHERE host = ? AND port = ? AND username = ? AND password = ? AND deleted_at IS NULL LIMIT 1",
            [host, port, username || "", password || ""]
        );
        return row === null ? null : rowToRecord(row);
    }

    async create(input: CreateProxyInput): Promise<ProxyRecord> {
        const now = new Date().toISOString();
        const result = await runStatement(
            this.#db,
            `INSERT INTO proxies (
                created_at, updated_at, name, protocol, host, port,
                username, password, status, expires_at, fallback_mode,
                expiry_warn_days, backup_proxy_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)`,
            [
                now, now,
                input.name,
                input.protocol,
                input.host,
                input.port,
                input.username ?? null,
                input.password ?? null,
                input.expiresAt ?? null,
                input.fallbackMode ?? "none",
                input.expiryWarnDays ?? 7,
                input.backupProxyId ?? null
            ]
        );
        const id = Number(result.meta?.last_row_id);
        return (await this.findById(id))!;
    }

    async update(id: number, input: UpdateProxyInput): Promise<ProxyRecord | null> {
        const existing = await this.findById(id);
        if (existing === null) return null;

        const now = new Date().toISOString();
        const sets: string[] = ["updated_at = ?"];
        const values: D1Value[] = [now];

        if (input.name !== undefined) {
            sets.push("name = ?");
            values.push(input.name);
        }
        if (input.protocol !== undefined) {
            sets.push("protocol = ?");
            values.push(input.protocol);
        }
        if (input.host !== undefined) {
            sets.push("host = ?");
            values.push(input.host);
        }
        if (input.port !== undefined) {
            sets.push("port = ?");
            values.push(input.port);
        }
        if (input.username !== undefined) {
            sets.push("username = ?");
            values.push(input.username || null);
        }
        if (input.password !== undefined) {
            sets.push("password = ?");
            values.push(input.password || null);
        }
        if (input.status !== undefined) {
            sets.push("status = ?");
            values.push(input.status);
        }
        if (input.expiresAt !== undefined) {
            sets.push("expires_at = ?");
            values.push(input.expiresAt);
        }
        if (input.fallbackMode !== undefined) {
            sets.push("fallback_mode = ?");
            values.push(input.fallbackMode);
        }
        if (input.backupProxyId !== undefined) {
            sets.push("backup_proxy_id = ?");
            values.push(input.backupProxyId);
        }
        if (input.expiryWarnDays !== undefined) {
            sets.push("expiry_warn_days = ?");
            values.push(input.expiryWarnDays);
        }

        if (sets.length === 1) return existing;

        values.push(id);
        await runStatement(
            this.#db,
            `UPDATE proxies SET ${sets.join(", ")} WHERE id = ? AND deleted_at IS NULL`,
            values
        );

        return this.findById(id);
    }

    async delete(id: number): Promise<boolean> {
        const now = new Date().toISOString();
        const result = await runStatement(
            this.#db,
            "UPDATE proxies SET deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL",
            [now, now, id]
        );
        return (result.meta?.changes ?? 0) > 0;
    }

    async batchDelete(ids: number[]): Promise<BatchDeleteResult> {
        const now = new Date().toISOString();
        const deletedIds: number[] = [];
        const skipped: Array<{ id: number; reason: string }> = [];

        for (const id of ids) {
            const existing = await this.findById(id);
            if (existing === null) {
                skipped.push({ id, reason: "not_found" });
                continue;
            }
            const result = await runStatement(
                this.#db,
                "UPDATE proxies SET deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL",
                [now, now, id]
            );
            if ((result.meta?.changes ?? 0) > 0) {
                deletedIds.push(id);
            } else {
                skipped.push({ id, reason: "delete_failed" });
            }
        }

        return { deletedIds, skipped };
    }

    async batchCreate(items: Array<{ protocol: string; host: string; port: number; username?: string; password?: string }>): Promise<{ created: number; skipped: number }> {
        let created = 0;
        let skipped = 0;

        for (const item of items) {
            const host = item.host.trim();
            const protocol = item.protocol.trim();
            const username = (item.username ?? "").trim();
            const password = (item.password ?? "").trim();

            const existing = await this.findByHostPortAuth(host, item.port, username, password);
            if (existing !== null) {
                skipped++;
                continue;
            }

            try {
                await this.create({
                    name: "default",
                    protocol,
                    host,
                    port: item.port,
                    username,
                    password
                });
                created++;
            } catch (_e) {
                skipped++;
            }
        }

        return { created, skipped };
    }
}
