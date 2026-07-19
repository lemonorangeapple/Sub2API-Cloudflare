import type { D1Database } from "../types/d1.ts";
import { firstRow, runStatement } from "../repositories/d1.ts";

export class AdminBackupError extends Error {
    readonly status: number;
    readonly code: string;
    constructor(status: number, code: string, message: string) {
        super(message);
        this.status = status;
        this.code = code;
    }
}

interface BackupRecord {
    id: number;
    status: string;
    type: string;
    file_name: string;
    file_size: number;
    created_at: string;
    completed_at: string | null;
    error_message: string | null;
    expire_days: number;
    expire_at: string | null;
}

interface S3Config {
    enabled: boolean;
    endpoint?: string;
    bucket?: string;
    region?: string;
    access_key_id?: string;
    secret_access_key?: string;
    force_path_style?: boolean;
    prefix?: string;
}

interface BackupSchedule {
    enabled: boolean;
    cron_expr?: string;
    retain_days?: number;
    retain_count?: number;
}

function nowISO(): string {
    return new Date().toISOString();
}

async function readJsonSetting<T>(db: D1Database, key: string): Promise<T | null> {
    const row = await firstRow<{ value: string }>(db, `SELECT value FROM settings WHERE key = ?`, [key]);
    return row ? JSON.parse(row.value) as T : null;
}

async function writeJsonSetting(db: D1Database, key: string, value: unknown): Promise<void> {
    const ts = nowISO();
    await runStatement(db, `INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)`, [key, JSON.stringify(value), ts]);
}

function maskSecret(secret: string | undefined): string {
    if (!secret || secret.length < 8) return "****";
    return secret.slice(0, 4) + "****" + secret.slice(-4);
}

function hex(bytes: ArrayBuffer): string {
    return Array.from(new Uint8Array(bytes)).map((value) => value.toString(16).padStart(2, "0")).join("");
}

async function sha256(value: string | ArrayBuffer): Promise<string> {
    return hex(await crypto.subtle.digest("SHA-256", typeof value === "string" ? new TextEncoder().encode(value) : value));
}

async function hmac(key: ArrayBuffer | string, value: string): Promise<ArrayBuffer> {
    const raw = typeof key === "string" ? new TextEncoder().encode(key) : key;
    const cryptoKey = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(value));
}

function encodePath(path: string): string {
    return path.split("/").map((part) => encodeURIComponent(part)).join("/");
}

function canonicalQueryString(params: URLSearchParams): string {
    return params.toString().split("&").filter(Boolean).sort().join("&");
}

function s3ObjectURL(config: S3Config, key = ""): URL {
    if (!config.endpoint || !config.bucket) throw new AdminBackupError(400, "S3_NOT_CONFIGURED", "S3 endpoint and bucket are required");
    const endpoint = new URL(config.endpoint);
    const prefix = config.prefix?.trim().replace(/^\/+|\/+$/gu, "") ?? "";
    const fullKey = [prefix, key.replace(/^\/+/, "")].filter(Boolean).join("/");
    if (config.force_path_style !== false) {
        endpoint.pathname = `${endpoint.pathname.replace(/\/+$/u, "")}/${encodePath(config.bucket)}${fullKey ? `/${encodePath(fullKey)}` : ""}`;
    } else {
        endpoint.hostname = `${config.bucket}.${endpoint.hostname}`;
        endpoint.pathname = `${endpoint.pathname.replace(/\/+$/u, "")}${fullKey ? `/${encodePath(fullKey)}` : "/"}`;
    }
    return endpoint;
}

async function signedS3Request(config: S3Config, method: string, key = "", body?: string, query?: Record<string, string>, presign = false): Promise<{ response?: Response; url: string }> {
    const url = s3ObjectURL(config, key);
    const region = config.region?.trim() || "us-east-1";
    const service = "s3";
    const now = new Date();
    const amzDate = now.toISOString().replace(/[-:]/gu, "").replace(/\.\d{3}Z$/u, "Z");
    const shortDate = amzDate.slice(0, 8);
    const accessKey = config.access_key_id?.trim() ?? "";
    const secretKey = config.secret_access_key?.trim() ?? "";
    if (!accessKey || !secretKey) throw new AdminBackupError(400, "S3_NOT_CONFIGURED", "S3 credentials are required");
    const params = new URLSearchParams(query);
    const payloadHash = await sha256(body ?? "");
    const host = url.host;
    let signedHeaders = "host";
    let canonicalHeaders = `host:${host}\n`;
    if (!presign) {
        signedHeaders = "host;x-amz-content-sha256;x-amz-date";
        canonicalHeaders += `x-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
    }
    if (presign) {
        params.set("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
        params.set("X-Amz-Credential", `${accessKey}/${shortDate}/${region}/${service}/aws4_request`);
        params.set("X-Amz-Date", amzDate);
        params.set("X-Amz-Expires", "300");
        params.set("X-Amz-SignedHeaders", signedHeaders);
    }
    const canonicalQuery = canonicalQueryString(params);
    const canonicalRequest = [method, url.pathname || "/", canonicalQuery, canonicalHeaders, signedHeaders, payloadHash].join("\n");
    const scope = `${shortDate}/${region}/${service}/aws4_request`;
    const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${scope}\n${await sha256(canonicalRequest)}`;
    const kDate = await hmac(`AWS4${secretKey}`, shortDate);
    const kRegion = await hmac(kDate, region);
    const kService = await hmac(kRegion, service);
    const kSigning = await hmac(kService, "aws4_request");
    const signature = hex(await hmac(kSigning, stringToSign));
    if (presign) {
        params.set("X-Amz-Signature", signature);
        return { url: `${url.origin}${url.pathname}?${canonicalQueryString(params)}` };
    }
    const headers = new Headers({ host, "x-amz-content-sha256": payloadHash, "x-amz-date": amzDate, authorization: `AWS4-HMAC-SHA256 Credential=${accessKey}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}` });
    return { response: await fetch(url, { method, headers, body }), url: url.toString() };
}

export class D1AdminBackupsService {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    // === S3 Config ===

    async getS3Config(): Promise<Record<string, unknown>> {
        const config = await readJsonSetting<S3Config>(this.#db, "backup_s3_config");
        if (!config) return { enabled: false };
        return {
            enabled: config.enabled,
            endpoint: config.endpoint || "",
            bucket: config.bucket || "",
            region: config.region || "",
            access_key_id: config.access_key_id || "",
            secret_access_key: config.secret_access_key ? maskSecret(config.secret_access_key) : "",
            force_path_style: config.force_path_style ?? false,
        };
    }

    async updateS3Config(input: {
        enabled?: boolean; endpoint?: string; bucket?: string; region?: string;
        access_key_id?: string; secret_access_key?: string; force_path_style?: boolean;
    }): Promise<Record<string, unknown>> {
        const existing = await readJsonSetting<S3Config>(this.#db, "backup_s3_config");
        const config: S3Config = {
            enabled: input.enabled ?? existing?.enabled ?? false,
            endpoint: input.endpoint ?? existing?.endpoint ?? "",
            bucket: input.bucket ?? existing?.bucket ?? "",
            region: input.region ?? existing?.region ?? "",
            access_key_id: input.access_key_id ?? existing?.access_key_id ?? "",
            secret_access_key: input.secret_access_key && !input.secret_access_key.includes("****") ? input.secret_access_key : (existing?.secret_access_key ?? ""),
            force_path_style: input.force_path_style ?? existing?.force_path_style ?? false,
            prefix: existing?.prefix ?? "",
        };
        await writeJsonSetting(this.#db, "backup_s3_config", config);
        return this.getS3Config();
    }

    async testS3Connection(): Promise<Record<string, unknown>> {
        const config = await readJsonSetting<S3Config>(this.#db, "backup_s3_config");
        if (!config || !config.enabled) {
            return { success: false, message: "S3 backup storage is not configured or disabled" };
        }
        try {
            const result = await signedS3Request(config, "HEAD");
            if (!result.response?.ok) return { success: false, message: `S3 returned HTTP ${result.response?.status ?? 0}`, endpoint: config.endpoint, bucket: config.bucket };
            return { success: true, message: "S3 connection succeeded", endpoint: config.endpoint, bucket: config.bucket };
        } catch (error) {
            return { success: false, message: error instanceof Error ? error.message : "S3 connection failed", endpoint: config.endpoint, bucket: config.bucket };
        }
    }

    // === Backup Schedule ===

    async getSchedule(): Promise<Record<string, unknown>> {
        const schedule = await readJsonSetting<BackupSchedule>(this.#db, "backup_schedule");
        if (!schedule) return { enabled: false, cron_expr: "", retain_days: 14, retain_count: 0 };
        return {
            enabled: schedule.enabled,
            cron_expr: schedule.cron_expr || "",
            retain_days: schedule.retain_days ?? 14,
            retain_count: schedule.retain_count ?? 0,
        };
    }

    async updateSchedule(input: { enabled?: boolean; cron_expr?: string; retain_days?: number; retain_count?: number }): Promise<Record<string, unknown>> {
        const existing = await readJsonSetting<BackupSchedule>(this.#db, "backup_schedule");
        const schedule: BackupSchedule = {
            enabled: input.enabled ?? existing?.enabled ?? false,
            cron_expr: input.cron_expr ?? existing?.cron_expr ?? "",
            retain_days: input.retain_days ?? existing?.retain_days ?? 14,
            retain_count: input.retain_count ?? existing?.retain_count ?? 0,
        };
        if (schedule.cron_expr && !this.#isValidCron(schedule.cron_expr)) {
            throw new AdminBackupError(400, "INVALID_CRON", "Invalid cron expression");
        }
        await writeJsonSetting(this.#db, "backup_schedule", schedule);
        return this.getSchedule();
    }

    #isValidCron(expr: string): boolean {
        const parts = expr.trim().split(/\s+/);
        return parts.length === 5 || parts.length === 6;
    }

    // === Backup Records ===

    async #getRecords(): Promise<BackupRecord[]> {
        return (await readJsonSetting<BackupRecord[]>(this.#db, "backup_records")) ?? [];
    }

    async #saveRecords(records: BackupRecord[]): Promise<void> {
        await writeJsonSetting(this.#db, "backup_records", records);
    }

    async listBackups(): Promise<{ items: Record<string, unknown>[]; total: number }> {
        const records = await this.#getRecords();
        const sorted = [...records].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
        return { items: sorted.slice(0, 100) as unknown as Record<string, unknown>[], total: sorted.length };
    }

    async getBackup(id: number): Promise<Record<string, unknown>> {
        const records = await this.#getRecords();
        const record = records.find((r) => r.id === id);
        if (!record) throw new AdminBackupError(404, "NOT_FOUND", "Backup record not found");
        return record as unknown as Record<string, unknown>;
    }

    async createBackup(expireDays = 14): Promise<Record<string, unknown>> {
        const records = await this.#getRecords();
        const maxId = records.reduce((max, r) => Math.max(max, r.id), 0);
        const now = new Date();
        const expireAt = new Date(now.getTime() + expireDays * 86400000).toISOString();
        const record: BackupRecord = {
            id: maxId + 1,
            status: "running",
            type: "manual",
            file_name: `backup_${now.toISOString().replace(/[:.]/g, "-")}.sql.gz`,
            file_size: 0,
            created_at: nowISO(),
            completed_at: null,
            error_message: null,
            expire_days: expireDays,
            expire_at: expireAt,
        };
        records.push(record);
        await this.#saveRecords(records);
        const config = await readJsonSetting<S3Config>(this.#db, "backup_s3_config");
        if (!config?.enabled) return record as unknown as Record<string, unknown>;
        try {
            const snapshot = await this.#snapshotDatabase();
            const content = JSON.stringify(snapshot);
            const uploaded = await signedS3Request(config, "PUT", record.file_name, content);
            if (!uploaded.response?.ok) throw new Error(`S3 upload failed with HTTP ${uploaded.response?.status ?? 0}`);
            record.status = "completed";
            record.file_size = new TextEncoder().encode(content).byteLength;
            record.completed_at = nowISO();
            record.expire_at = expireAt;
            await this.#saveRecords(records);
            return record as unknown as Record<string, unknown>;
        } catch (error) {
            record.status = "failed";
            record.error_message = error instanceof Error ? error.message : "Backup upload failed";
            record.completed_at = nowISO();
            await this.#saveRecords(records);
            return record as unknown as Record<string, unknown>;
        }
    }

    async deleteBackup(id: number): Promise<void> {
        const records = await this.#getRecords();
        const idx = records.findIndex((r) => r.id === id);
        if (idx === -1) throw new AdminBackupError(404, "NOT_FOUND", "Backup record not found");
        records.splice(idx, 1);
        await this.#saveRecords(records);
    }

    async getDownloadUrl(id: number): Promise<Record<string, unknown>> {
        const records = await this.#getRecords();
        const record = records.find((r) => r.id === id);
        if (!record) throw new AdminBackupError(404, "NOT_FOUND", "Backup record not found");
        const config = await readJsonSetting<S3Config>(this.#db, "backup_s3_config");
        if (!config?.enabled) return { url: "", expires_at: null, message: "Pre-signed download URLs are not available in serverless mode" };
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
        const signed = await signedS3Request(config, "GET", record.file_name, undefined, undefined, true);
        return { url: signed.url, expires_at: expiresAt };
    }

    async restoreBackup(id: number, password?: string): Promise<Record<string, unknown>> {
        const records = await this.#getRecords();
        const record = records.find((r) => r.id === id);
        if (!record) throw new AdminBackupError(404, "NOT_FOUND", "Backup record not found");
        const config = await readJsonSetting<S3Config>(this.#db, "backup_s3_config");
        if (!config?.enabled) return { success: false, message: "S3 backup storage is not configured or disabled", backup_id: id };
        if (record.status !== "completed") return { success: false, message: "Only completed backups can be restored", backup_id: id };
        const signed = await signedS3Request(config, "GET", record.file_name);
        if (!signed.response?.ok) return { success: false, message: `S3 download failed with HTTP ${signed.response?.status ?? 0}`, backup_id: id };
        const snapshot = await signed.response.json() as { tables?: Array<{ name: string; rows: Array<Record<string, unknown>> }> };
        if (!snapshot || !Array.isArray(snapshot.tables)) return { success: false, message: "Backup payload is invalid", backup_id: id };
        const statements = [];
        for (const table of snapshot.tables) {
            if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(table.name) || table.name.startsWith("sqlite_")) continue;
            for (const row of table.rows ?? []) {
                const columns = Object.keys(row).filter((column) => /^[A-Za-z_][A-Za-z0-9_]*$/u.test(column));
                if (columns.length === 0) continue;
                const placeholders = columns.map(() => "?").join(",");
                statements.push(this.#db.prepare(`INSERT OR REPLACE INTO "${table.name}" (${columns.map((column) => `"${column}"`).join(",")}) VALUES (${placeholders})`).bind(...columns.map((column) => {
                    const value = row[column];
                    return value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean" ? value : JSON.stringify(value);
                })));
            }
        }
        if (statements.length > 0) await this.#db.batch(statements);
        return { success: true, message: "Backup restored successfully", backup_id: id, restored_at: nowISO(), password_supplied: Boolean(password) };
    }

    async #snapshotDatabase(): Promise<{ format: string; created_at: string; tables: Array<{ name: string; rows: Record<string, unknown>[] }> }> {
        const tablesResult = await this.#db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all<{ name: string }>();
        const tables: Array<{ name: string; rows: Record<string, unknown>[] }> = [];
        for (const table of tablesResult.results ?? []) {
            if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(table.name)) continue;
            const result = await this.#db.prepare(`SELECT * FROM "${table.name}"`).all<Record<string, unknown>>();
            tables.push({ name: table.name, rows: result.results ?? [] });
        }
        return { format: "sub2api-d1-json-v1", created_at: nowISO(), tables };
    }
}
