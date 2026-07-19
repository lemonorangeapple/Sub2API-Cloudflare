import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement, runBatchTransaction } from "./d1.ts";

export interface AnnouncementRecord {
    id: number;
    title: string;
    content: string;
    status: string;
    notifyMode: string;
    targeting: string | null;
    startsAt: string | null;
    endsAt: string | null;
    createdBy: number | null;
    updatedBy: number | null;
    createdAt: string;
    updatedAt: string;
}

export interface AnnouncementReadRecord {
    id: number;
    readAt: string;
    createdAt: string;
    announcementId: number;
    userId: number;
}

interface AnnouncementRow {
    id: number;
    title: string;
    content: string;
    status: string;
    notify_mode: string;
    targeting: string | null;
    starts_at: string | null;
    ends_at: string | null;
    created_by: number | null;
    updated_by: number | null;
    created_at: string;
    updated_at: string;
}

interface ReadStatusRow {
    user_id: number;
    email: string;
    username: string;
    read_at: string | null;
}

function rowToRecord(row: AnnouncementRow): AnnouncementRecord {
    return {
        id: row.id,
        title: row.title,
        content: row.content,
        status: row.status,
        notifyMode: row.notify_mode,
        targeting: row.targeting,
        startsAt: row.starts_at,
        endsAt: row.ends_at,
        createdBy: row.created_by,
        updatedBy: row.updated_by,
        createdAt: row.created_at,
        updatedAt: row.updated_at
    };
}

export interface CreateAnnouncementInput {
    title: string;
    content: string;
    status?: string;
    notifyMode?: string;
    targeting?: string | null;
    startsAt?: string | null;
    endsAt?: string | null;
    createdBy?: number | null;
}

export interface UpdateAnnouncementInput {
    title?: string;
    content?: string;
    status?: string;
    notifyMode?: string;
    targeting?: string | null;
    startsAt?: string | null;
    endsAt?: string | null;
    updatedBy?: number | null;
}

export interface ListAnnouncementsOptions {
    page: number;
    pageSize: number;
    status?: string;
    search?: string;
    sortBy?: string;
    sortDir?: string;
}

const ALLOWED_SORT = new Set(["id", "title", "status", "created_at", "updated_at", "starts_at", "ends_at"]);
const ALLOWED_DIR = new Set(["asc", "desc"]);

export class D1AnnouncementRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async list(options: ListAnnouncementsOptions): Promise<{ items: AnnouncementRecord[]; total: number }> {
        const conditions: string[] = [];
        const values: D1Value[] = [];

        if (options.status) {
            conditions.push("status = ?");
            values.push(options.status);
        }
        if (options.search) {
            conditions.push("(title LIKE ? OR content LIKE ?)");
            const pattern = `%${options.search.trim()}%`;
            values.push(pattern, pattern);
        }

        const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
        const countRow = await firstRow<{ count: number }>(
            this.#db,
            `SELECT COUNT(*) AS count FROM announcements ${where}`,
            values
        );
        const total = countRow?.count ?? 0;

        const safeOrder = ALLOWED_SORT.has(options.sortBy ?? "created_at") ? options.sortBy ?? "created_at" : "created_at";
        const safeDir = ALLOWED_DIR.has(options.sortDir ?? "desc") ? options.sortDir ?? "desc" : "desc";
        const offset = (options.page - 1) * options.pageSize;

        const rows = await allRows<AnnouncementRow>(
            this.#db,
            `SELECT * FROM announcements ${where} ORDER BY ${safeOrder} ${safeDir} LIMIT ? OFFSET ?`,
            [...values, options.pageSize, offset]
        );

        return { items: rows.map(rowToRecord), total };
    }

    async findById(id: number): Promise<AnnouncementRecord | null> {
        const row = await firstRow<AnnouncementRow>(
            this.#db,
            "SELECT * FROM announcements WHERE id = ?",
            [id]
        );
        return row === null ? null : rowToRecord(row);
    }

    async create(input: CreateAnnouncementInput): Promise<AnnouncementRecord> {
        const now = new Date().toISOString();
        const result = await runStatement(
            this.#db,
            `INSERT INTO announcements (
                created_at, updated_at, title, content, status, notify_mode,
                targeting, starts_at, ends_at, created_by, updated_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                now, now,
                input.title,
                input.content,
                input.status ?? "draft",
                input.notifyMode ?? "silent",
                input.targeting ?? null,
                input.startsAt ?? null,
                input.endsAt ?? null,
                input.createdBy ?? null,
                null
            ]
        );
        const id = Number(result.meta?.last_row_id);
        return (await this.findById(id))!;
    }

    async update(id: number, input: UpdateAnnouncementInput): Promise<AnnouncementRecord | null> {
        const existing = await this.findById(id);
        if (existing === null) return null;

        const now = new Date().toISOString();
        const sets: string[] = ["updated_at = ?"];
        const values: D1Value[] = [now];

        if (input.title !== undefined) { sets.push("title = ?"); values.push(input.title); }
        if (input.content !== undefined) { sets.push("content = ?"); values.push(input.content); }
        if (input.status !== undefined) { sets.push("status = ?"); values.push(input.status); }
        if (input.notifyMode !== undefined) { sets.push("notify_mode = ?"); values.push(input.notifyMode); }
        if (input.targeting !== undefined) { sets.push("targeting = ?"); values.push(input.targeting); }
        if (input.startsAt !== undefined) { sets.push("starts_at = ?"); values.push(input.startsAt); }
        if (input.endsAt !== undefined) { sets.push("ends_at = ?"); values.push(input.endsAt); }
        if (input.updatedBy !== undefined) { sets.push("updated_by = ?"); values.push(input.updatedBy); }

        if (sets.length === 1) return existing;

        values.push(id);
        await runStatement(
            this.#db,
            `UPDATE announcements SET ${sets.join(", ")} WHERE id = ?`,
            values
        );

        return this.findById(id);
    }

    async delete(id: number): Promise<boolean> {
        await runBatchTransaction(this.#db, [
            { sql: "DELETE FROM announcement_reads WHERE announcement_id = ?", values: [id] },
            { sql: "DELETE FROM announcements WHERE id = ?", values: [id] }
        ]);
        return true;
    }

    async countReadByAnnouncementId(id: number): Promise<number> {
        const row = await firstRow<{ count: number }>(
            this.#db,
            "SELECT COUNT(*) AS count FROM announcement_reads WHERE announcement_id = ?",
            [id]
        );
        return row?.count ?? 0;
    }

    async listActive(now: string): Promise<AnnouncementRecord[]> {
        const rows = await allRows<AnnouncementRow>(
            this.#db,
            `SELECT * FROM announcements
             WHERE status = 'active'
               AND (starts_at IS NULL OR starts_at <= ?)
               AND (ends_at IS NULL OR ends_at > ?)
             ORDER BY id DESC`,
            [now, now]
        );
        return rows.map(rowToRecord);
    }

    async markRead(announcementId: number, userId: number, readAt: string): Promise<void> {
        await runStatement(
            this.#db,
            `INSERT INTO announcement_reads (read_at, created_at, announcement_id, user_id) VALUES (?, ?, ?, ?)
             ON CONFLICT (announcement_id, user_id) DO NOTHING`,
            [readAt, readAt, announcementId, userId]
        );
    }

    async getReadMapByUser(userId: number, announcementIds: number[]): Promise<Map<number, string>> {
        if (announcementIds.length === 0) return new Map();
        const placeholders = announcementIds.map(() => "?").join(",");
        const rows = await allRows<{ announcement_id: number; read_at: string }>(
            this.#db,
            `SELECT announcement_id, read_at FROM announcement_reads WHERE user_id = ? AND announcement_id IN (${placeholders})`,
            [userId, ...announcementIds]
        );
        return new Map(rows.map(r => [r.announcement_id, r.read_at]));
    }

    async listReadStatus(id: number, page: number, pageSize: number, search?: string): Promise<{ items: ReadStatusRow[]; total: number }> {
        const conditions: string[] = ["ar.announcement_id = ?"];
        const values: D1Value[] = [id];

        if (search) {
            conditions.push("(u.email LIKE ? OR u.username LIKE ?)");
            const pattern = `%${search.trim()}%`;
            values.push(pattern, pattern);
        }

        const where = conditions.join(" AND ");
        const countRow = await firstRow<{ count: number }>(
            this.#db,
            `SELECT COUNT(*) AS count FROM announcement_reads ar JOIN users u ON ar.user_id = u.id WHERE ${where}`,
            values
        );
        const total = countRow?.count ?? 0;

        const offset = (page - 1) * pageSize;
        const rows = await allRows<ReadStatusRow>(
            this.#db,
            `SELECT ar.user_id, u.email, u.username, ar.read_at AS read_at
             FROM announcement_reads ar JOIN users u ON ar.user_id = u.id
             WHERE ${where} ORDER BY u.email ASC LIMIT ? OFFSET ?`,
            [...values, pageSize, offset]
        );

        return { items: rows, total };
    }
}
