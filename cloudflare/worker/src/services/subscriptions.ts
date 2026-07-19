import type { SubscriptionRecord, SubscriptionWithUserRecord } from "../repositories/subscriptions.ts";
import { D1SubscriptionRepository } from "../repositories/subscriptions.ts";
import type { D1Database, D1Value } from "../types/d1.ts";

export class SubscriptionError extends Error {
    status: number;
    code: string;
    constructor(status: number, message: string, code: string) {
        super(message);
        this.name = "SubscriptionError";
        this.status = status;
        this.code = code;
    }
}

export function errNotFound(): SubscriptionError {
    return new SubscriptionError(404, "Subscription not found", "SUBSCRIPTION_NOT_FOUND");
}

export function errBadRequest(msg: string): SubscriptionError {
    return new SubscriptionError(400, msg, "BAD_REQUEST");
}

export interface AssignSubscriptionInput {
    userId: number;
    groupId: number;
    validityDays: number;
    assignedBy: number;
    notes?: string;
}

export interface BulkAssignSubscriptionInput {
    userIds: number[];
    groupId: number;
    validityDays: number;
    assignedBy: number;
    notes?: string;
}

export interface BulkAssignResult {
    successCount: number;
    createdCount: number;
    reusedCount: number;
    failedCount: number;
    subscriptions: Record<string, unknown>[];
    errors: string[];
}

export interface UsageWindowProgress {
    limitUsd: number | null;
    usedUsd: number;
    remainingUsd: number | null;
    percentage: number;
    windowStart: string | null;
    resetsAt: string | null;
    resetsInSeconds: number | null;
}

export interface SubscriptionProgress {
    id: number;
    groupName: string;
    expiresAt: string;
    expiresInDays: number;
    daily: UsageWindowProgress | null;
    weekly: UsageWindowProgress | null;
    monthly: UsageWindowProgress | null;
}

function nowISO(): string {
    return new Date().toISOString();
}

function addDays(dateStr: string, days: number): string {
    const d = new Date(dateStr);
    d.setUTCDate(d.getUTCDate() + days);
    return d.toISOString();
}

function daysBetween(from: string, to: string): number {
    const diff = new Date(to).getTime() - new Date(from).getTime();
    return Math.max(0, Math.floor(diff / (1000 * 60 * 60 * 24)));
}

export class D1SubscriptionService {
    private repo: D1SubscriptionRepository;

    constructor(db: D1Database) {
        this.repo = new D1SubscriptionRepository(db);
    }

    private toJson(r: SubscriptionWithUserRecord): Record<string, unknown> {
        return {
            id: r.id,
            user_id: r.userId,
            group_id: r.groupId,
            starts_at: r.startsAt,
            expires_at: r.expiresAt,
            status: r.status,
            daily_window_start: r.dailyWindowStart,
            weekly_window_start: r.weeklyWindowStart,
            monthly_window_start: r.monthlyWindowStart,
            daily_usage_usd: r.dailyUsageUsd,
            weekly_usage_usd: r.weeklyUsageUsd,
            monthly_usage_usd: r.monthlyUsageUsd,
            assigned_at: r.assignedAt,
            assigned_by: r.assignedBy,
            notes: r.notes,
            created_at: r.createdAt,
            updated_at: r.updatedAt,
            user_name: r.userName,
            user_email: r.userEmail,
            group_name: r.groupName,
            group_platform: r.groupPlatform,
            assigned_by_name: r.assignedByName,
        };
    }

    private toJsonSimple(r: SubscriptionRecord): Record<string, unknown> {
        return {
            id: r.id,
            user_id: r.userId,
            group_id: r.groupId,
            starts_at: r.startsAt,
            expires_at: r.expiresAt,
            status: r.status,
            daily_window_start: r.dailyWindowStart,
            weekly_window_start: r.weeklyWindowStart,
            monthly_window_start: r.monthlyWindowStart,
            daily_usage_usd: r.dailyUsageUsd,
            weekly_usage_usd: r.weeklyUsageUsd,
            monthly_usage_usd: r.monthlyUsageUsd,
            assigned_at: r.assignedAt,
            assigned_by: r.assignedBy,
            notes: r.notes,
            created_at: r.createdAt,
            updated_at: r.updatedAt,
        };
    }

    async list(params: {
        page: number; pageSize: number; userId?: number; groupId?: number;
        status?: string; platform?: string; sortBy?: string; sortOrder?: string;
    }): Promise<{ items: Record<string, unknown>[]; total: number }> {
        const result = await this.repo.list(params);
        return { items: result.items.map(r => this.toJson(r)), total: result.total };
    }

    async getById(id: number): Promise<Record<string, unknown>> {
        const sub = await this.repo.getById(id);
        if (!sub) throw errNotFound();
        return this.toJson(sub);
    }

    async assign(input: AssignSubscriptionInput): Promise<Record<string, unknown>> {
        if (input.validityDays < 1 || input.validityDays > 36500) {
            throw errBadRequest("validity_days must be between 1 and 36500");
        }
        const userExists = await this.repo.userExists(input.userId);
        if (!userExists) throw errBadRequest("User not found");
        const groupExists = await this.repo.groupExists(input.groupId);
        if (!groupExists) throw errBadRequest("Group not found");

        const now = nowISO();
        const expiresAt = addDays(now, input.validityDays);
        const created = await this.repo.create({
            user_id: input.userId,
            group_id: input.groupId,
            starts_at: now,
            expires_at: expiresAt,
            assigned_by: input.assignedBy,
            notes: input.notes ?? null,
            daily_window_start: now,
            weekly_window_start: now,
            monthly_window_start: now,
        });
        const full = await this.repo.getById(created.id);
        return this.toJson(full!);
    }

    async bulkAssign(input: BulkAssignSubscriptionInput): Promise<BulkAssignResult> {
        if (input.validityDays < 1 || input.validityDays > 36500) {
            throw errBadRequest("validity_days must be between 1 and 36500");
        }
        const groupExists = await this.repo.groupExists(input.groupId);
        if (!groupExists) throw errBadRequest("Group not found");

        const result: BulkAssignResult = {
            successCount: 0, createdCount: 0, reusedCount: 0,
            failedCount: 0, subscriptions: [], errors: [],
        };
        const now = nowISO();
        const expiresAt = addDays(now, input.validityDays);

        for (const userId of input.userIds) {
            const userExists = await this.repo.userExists(userId);
            if (!userExists) {
                result.failedCount++;
                result.errors.push(`User ${userId} not found`);
                continue;
            }
            try {
                const created = await this.repo.create({
                    user_id: userId,
                    group_id: input.groupId,
                    starts_at: now,
                    expires_at: expiresAt,
                    assigned_by: input.assignedBy,
                    notes: input.notes ?? null,
                    daily_window_start: now,
                    weekly_window_start: now,
                    monthly_window_start: now,
                });
                const full = await this.repo.getById(created.id);
                result.successCount++;
                result.createdCount++;
                result.subscriptions.push(this.toJson(full!));
            } catch (e) {
                result.failedCount++;
                result.errors.push(`User ${userId}: ${e instanceof Error ? e.message : String(e)}`);
            }
        }
        return result;
    }

    async extend(id: number, days: number): Promise<Record<string, unknown>> {
        if (days < -36500 || days > 36500) {
            throw errBadRequest("days must be between -36500 and 36500");
        }
        const sub = await this.repo.getById(id);
        if (!sub) throw errNotFound();

        const newExpiresAt = days >= 0
            ? addDays(sub.expiresAt, days)
            : addDays(sub.expiresAt, days);

        const updated = await this.repo.update(id, { expires_at: newExpiresAt });
        const full = await this.repo.getById(updated!.id);
        return this.toJson(full!);
    }

    async resetQuota(id: number, daily: boolean, weekly: boolean, monthly: boolean): Promise<Record<string, unknown>> {
        const sub = await this.repo.getById(id);
        if (!sub) throw errNotFound();

        const updates: Record<string, unknown> = {};
        const now = nowISO();
        if (daily) {
            updates.daily_usage_usd = 0;
            updates.daily_window_start = now;
        }
        if (weekly) {
            updates.weekly_usage_usd = 0;
            updates.weekly_window_start = now;
        }
        if (monthly) {
            updates.monthly_usage_usd = 0;
            updates.monthly_window_start = now;
        }
        const updated = await this.repo.update(id, updates as Record<string, D1Value>);
        const full = await this.repo.getById(updated!.id);
        return this.toJson(full!);
    }

    async revoke(id: number): Promise<void> {
        const sub = await this.repo.getById(id);
        if (!sub) throw errNotFound();
        await this.repo.update(id, { status: "revoked" });
        await this.repo.delete(id);
    }

    async restore(id: number): Promise<Record<string, unknown>> {
        const updated = await this.repo.restore(id);
        if (!updated) throw errNotFound();
        await this.repo.update(id, { status: "active" });
        const full = await this.repo.getById(updated.id);
        return this.toJson(full!);
    }

    async listByGroup(groupId: number, page: number, pageSize: number): Promise<{ items: Record<string, unknown>[]; total: number }> {
        const result = await this.repo.listByGroup(groupId, page, pageSize);
        return { items: result.items.map(r => this.toJson(r)), total: result.total };
    }

    async listByUser(userId: number): Promise<Record<string, unknown>[]> {
        const subs = await this.repo.listByUser(userId);
        return subs.map(r => this.toJson(r));
    }

    async getProgress(id: number): Promise<SubscriptionProgress> {
        const sub = await this.repo.getById(id);
        if (!sub) throw errNotFound();

        const expiresInDays = daysBetween(nowISO(), sub.expiresAt);

        const makeWindow = (
            windowStart: string | null,
            usedUsd: number
        ): UsageWindowProgress => ({
            limitUsd: null,
            usedUsd: usedUsd,
            remainingUsd: null,
            percentage: 0,
            windowStart: windowStart,
            resetsAt: null,
            resetsInSeconds: null,
        });

        return {
            id: sub.id,
            groupName: sub.groupName,
            expiresAt: sub.expiresAt,
            expiresInDays,
            daily: sub.dailyWindowStart ? makeWindow(sub.dailyWindowStart, sub.dailyUsageUsd) : null,
            weekly: sub.weeklyWindowStart ? makeWindow(sub.weeklyWindowStart, sub.weeklyUsageUsd) : null,
            monthly: sub.monthlyWindowStart ? makeWindow(sub.monthlyWindowStart, sub.monthlyUsageUsd) : null,
        };
    }
}
