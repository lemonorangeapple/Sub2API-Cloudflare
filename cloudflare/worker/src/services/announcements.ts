import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { D1SubscriptionRepository } from "../repositories/subscriptions.ts";
import type { D1AnnouncementRepository, AnnouncementRecord, CreateAnnouncementInput, UpdateAnnouncementInput, ListAnnouncementsOptions } from "../repositories/announcements.ts";
import type { D1Database } from "../types/d1.ts";

export class AnnouncementError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "AnnouncementError";
        this.code = code;
        this.status = status;
    }
}

const VALID_STATUSES = new Set(["draft", "active", "archived"]);
const VALID_NOTIFY_MODES = new Set(["silent", "popup"]);
const MAX_TITLE_LENGTH = 200;
const MAX_CONTENT_LENGTH = 10000;

interface AnnouncementCondition {
    type: string;
    operator: string;
    value: unknown;
}

interface AnnouncementConditionGroup {
    allOf: AnnouncementCondition[];
}

interface AnnouncementTargeting {
    anyOf: AnnouncementConditionGroup[];
}

function evaluateTargeting(targeting: AnnouncementTargeting | null, balance: number, activeGroupIds: Set<number>): boolean {
    if (!targeting || !targeting.anyOf || targeting.anyOf.length === 0) return true;
    return targeting.anyOf.some(group => {
        if (!group.allOf || group.allOf.length === 0) return true;
        return group.allOf.every(cond => {
            if (cond.type === "subscription" && cond.operator === "in" && Array.isArray(cond.value)) {
                return cond.value.some((v: unknown) => activeGroupIds.has(Number(v)));
            }
            if (cond.type === "balance") {
                const val = Number(cond.value);
                switch (cond.operator) {
                    case "gt": return balance > val;
                    case "gte": return balance >= val;
                    case "lt": return balance < val;
                    case "lte": return balance <= val;
                    case "eq": return balance === val;
                }
            }
            return false;
        });
    });
}

export class D1AnnouncementService {
    readonly #repository: D1AnnouncementRepository;
    readonly #db?: D1Database;

    constructor(repository: D1AnnouncementRepository, db?: D1Database) {
        this.#repository = repository;
        this.#db = db;
    }

    async list(options: ListAnnouncementsOptions): Promise<{ items: AnnouncementRecord[]; total: number }> {
        return this.#repository.list(options);
    }

    async getById(id: number): Promise<AnnouncementRecord> {
        const item = await this.#repository.findById(id);
        if (item === null) {
            throw new AnnouncementError("announcement_not_found", 404, "Announcement not found");
        }
        return item;
    }

    async create(input: {
        title: string;
        content: string;
        status?: string;
        notify_mode?: string;
        targeting?: string | null;
        starts_at?: string | null;
        ends_at?: string | null;
        created_by?: number | null;
    }): Promise<AnnouncementRecord> {
        const title = input.title.trim();
        if (title.length === 0) {
            throw new AnnouncementError("title_required", 400, "Title is required");
        }
        if (title.length > MAX_TITLE_LENGTH) {
            throw new AnnouncementError("title_too_long", 400, `Title must be at most ${MAX_TITLE_LENGTH} characters`);
        }

        const content = input.content.trim();
        if (content.length === 0) {
            throw new AnnouncementError("content_required", 400, "Content is required");
        }
        if (content.length > MAX_CONTENT_LENGTH) {
            throw new AnnouncementError("content_too_long", 400, `Content must be at most ${MAX_CONTENT_LENGTH} characters`);
        }

        if (input.status !== undefined && !VALID_STATUSES.has(input.status)) {
            throw new AnnouncementError("invalid_status", 400, `Status must be one of: ${[...VALID_STATUSES].join(", ")}`);
        }

        if (input.notify_mode !== undefined && !VALID_NOTIFY_MODES.has(input.notify_mode)) {
            throw new AnnouncementError("invalid_notify_mode", 400, `Notify mode must be one of: ${[...VALID_NOTIFY_MODES].join(", ")}`);
        }

        const createInput: CreateAnnouncementInput = {
            title,
            content,
            status: input.status,
            notifyMode: input.notify_mode,
            targeting: input.targeting ?? null,
            startsAt: input.starts_at ?? null,
            endsAt: input.ends_at ?? null,
            createdBy: input.created_by ?? null
        };

        return this.#repository.create(createInput);
    }

    async update(id: number, input: {
        title?: string;
        content?: string;
        status?: string;
        notify_mode?: string;
        targeting?: string | null;
        starts_at?: string | null;
        ends_at?: string | null;
        updated_by?: number | null;
    }): Promise<AnnouncementRecord> {
        if (input.title !== undefined) {
            const title = input.title.trim();
            if (title.length === 0) throw new AnnouncementError("title_required", 400, "Title is required");
            if (title.length > MAX_TITLE_LENGTH) throw new AnnouncementError("title_too_long", 400, `Title must be at most ${MAX_TITLE_LENGTH} characters`);
        }

        if (input.content !== undefined) {
            const content = input.content.trim();
            if (content.length === 0) throw new AnnouncementError("content_required", 400, "Content is required");
            if (content.length > MAX_CONTENT_LENGTH) throw new AnnouncementError("content_too_long", 400, `Content must be at most ${MAX_CONTENT_LENGTH} characters`);
        }

        if (input.status !== undefined && !VALID_STATUSES.has(input.status)) {
            throw new AnnouncementError("invalid_status", 400, `Status must be one of: ${[...VALID_STATUSES].join(", ")}`);
        }

        if (input.notify_mode !== undefined && !VALID_NOTIFY_MODES.has(input.notify_mode)) {
            throw new AnnouncementError("invalid_notify_mode", 400, `Notify mode must be one of: ${[...VALID_NOTIFY_MODES].join(", ")}`);
        }

        const updateInput: UpdateAnnouncementInput = {
            title: input.title?.trim(),
            content: input.content?.trim(),
            status: input.status,
            notifyMode: input.notify_mode,
            targeting: input.targeting,
            startsAt: input.starts_at,
            endsAt: input.ends_at,
            updatedBy: input.updated_by
        };

        const updated = await this.#repository.update(id, updateInput);
        if (updated === null) {
            throw new AnnouncementError("announcement_not_found", 404, "Announcement not found");
        }
        return updated;
    }

    async delete(id: number): Promise<void> {
        const existing = await this.#repository.findById(id);
        if (existing === null) {
            throw new AnnouncementError("announcement_not_found", 404, "Announcement not found");
        }
        await this.#repository.delete(id);
    }

    async listReadStatus(id: number, page: number, pageSize: number, search?: string): Promise<{ items: Array<{ userId: number; email: string; username: string; readAt: string | null }>; total: number; readCount: number }> {
        const existing = await this.#repository.findById(id);
        if (existing === null) {
            throw new AnnouncementError("announcement_not_found", 404, "Announcement not found");
        }

        const result = await this.#repository.listReadStatus(id, page, pageSize, search);
        const readCount = await this.#repository.countReadByAnnouncementId(id);

        return {
            items: result.items.map((row) => ({
                userId: row.user_id,
                email: row.email,
                username: row.username,
                readAt: row.read_at
            })),
            total: result.total,
            readCount
        };
    }

    async listForUser(userId: number, unreadOnly: boolean, now: string): Promise<Array<{
        id: number;
        title: string;
        content: string;
        notifyMode: string;
        startsAt: string | null;
        endsAt: string | null;
        createdAt: string;
        updatedAt: string;
        readAt: string | null;
    }>> {
        if (!this.#db) throw new AnnouncementError("service_not_configured", 500, "Database not available for user announcement queries");

        const userRepo = new D1AuthUserRepository(this.#db);
        const subRepo = new D1SubscriptionRepository(this.#db);

        const user = await userRepo.findById(userId);
        if (!user) throw new AnnouncementError("user_not_found", 404, "User not found");

        const subscriptions = await subRepo.listActiveByUser(userId);
        const activeGroupIds = new Set(subscriptions.map(s => s.groupId));

        const announcements = await this.#repository.listActive(now);
        const visible = announcements.filter(a => {
            const targeting: AnnouncementTargeting | null = a.targeting ? JSON.parse(a.targeting) : null;
            return evaluateTargeting(targeting, user.balance, activeGroupIds);
        });

        const ids = visible.map(a => a.id);
        const readMap = await this.#repository.getReadMapByUser(userId, ids);

        const result = visible.map(a => ({
            id: a.id,
            title: a.title,
            content: a.content,
            notifyMode: a.notifyMode,
            startsAt: a.startsAt,
            endsAt: a.endsAt,
            createdAt: a.createdAt,
            updatedAt: a.updatedAt,
            readAt: readMap.get(a.id) ?? null,
        }));

        result.sort((a, b) => {
            const aUnread = a.readAt === null ? 0 : 1;
            const bUnread = b.readAt === null ? 0 : 1;
            if (aUnread !== bUnread) return aUnread - bUnread;
            return b.id - a.id;
        });

        if (unreadOnly) {
            return result.filter(a => a.readAt === null);
        }

        return result;
    }

    async markRead(userId: number, announcementId: number, now: string): Promise<void> {
        if (!this.#db) throw new AnnouncementError("service_not_configured", 500, "Database not available for user announcement queries");

        const userRepo = new D1AuthUserRepository(this.#db);
        const subRepo = new D1SubscriptionRepository(this.#db);

        const user = await userRepo.findById(userId);
        if (!user) throw new AnnouncementError("user_not_found", 404, "User not found");

        const announcement = await this.#repository.findById(announcementId);
        if (!announcement) throw new AnnouncementError("announcement_not_found", 404, "Announcement not found");

        if (announcement.status !== "active") throw new AnnouncementError("announcement_not_active", 404, "Announcement is not active");

        const aStarts = announcement.startsAt ? new Date(announcement.startsAt).getTime() : 0;
        const aEnds = announcement.endsAt ? new Date(announcement.endsAt).getTime() : Infinity;
        const nowMs = new Date(now).getTime();
        if (nowMs < aStarts || nowMs >= aEnds) {
            throw new AnnouncementError("announcement_not_active", 404, "Announcement is not active at this time");
        }

        const subscriptions = await subRepo.listActiveByUser(userId);
        const activeGroupIds = new Set(subscriptions.map(s => s.groupId));

        const targeting: AnnouncementTargeting | null = announcement.targeting ? JSON.parse(announcement.targeting) : null;
        if (!evaluateTargeting(targeting, user.balance, activeGroupIds)) {
            throw new AnnouncementError("announcement_not_found", 404, "Announcement not found");
        }

        await this.#repository.markRead(announcementId, userId, now);
    }
}
