import type {
    D1AdminUserRoutesRepository,
    UserDetail,
    BalanceHistoryItem,
    PlatformQuota,
    APIKeyItem,
    AuthIdentityItem,
    ReplaceGroupResult,
    UserListFilter,
    UserListResult,
} from "../repositories/admin-user-routes.ts";
import type { PasswordHasher } from "./password.ts";

const ALLOWED_PLATFORMS = ["openai", "anthropic", "gemini", "grok"];
const ALLOWED_WINDOWS = ["daily", "weekly", "monthly"];

export class AdminUserRoutesError extends Error {
    readonly status: number;
    readonly code: string;

    constructor(status: number, code: string, message: string) {
        super(message);
        this.name = "AdminUserRoutesError";
        this.status = status;
        this.code = code;
    }
}

export class D1AdminUserRoutesService {
    readonly #repo: D1AdminUserRoutesRepository;

    constructor(repo: D1AdminUserRoutesRepository) {
        this.#repo = repo;
    }

    async listUsers(filter: UserListFilter): Promise<UserListResult> {
        return this.#repo.listUsers(filter);
    }

    async getUserById(id: number, includeDeleted = false): Promise<UserDetail> {
        if (id <= 0) throw new AdminUserRoutesError(400, "INVALID_USER_ID", "user_id must be positive");
        const user = await this.#repo.findUserById(id, includeDeleted);
        if (user === null) throw new AdminUserRoutesError(404, "USER_NOT_FOUND", "user not found");
        return user;
    }

    async updateBalance(id: number, balance: number, operation: string, notes: string): Promise<UserDetail> {
        if (id <= 0) throw new AdminUserRoutesError(400, "INVALID_USER_ID", "user_id must be positive");
        if (!Number.isFinite(balance)) throw new AdminUserRoutesError(400, "INVALID_BALANCE", "balance must be a finite number");
        if (!["set", "add", "subtract"].includes(operation)) throw new AdminUserRoutesError(400, "INVALID_OPERATION", "operation must be set, add, or subtract");

        const user = await this.#repo.findUserById(id);
        if (user === null) throw new AdminUserRoutesError(404, "USER_NOT_FOUND", "user not found");

        let newBalance: number;
        if (operation === "set") newBalance = balance;
        else if (operation === "add") newBalance = user.balance + balance;
        else newBalance = user.balance - balance;

        if (newBalance < 0) throw new AdminUserRoutesError(400, "INSUFFICIENT_BALANCE", "resulting balance would be negative");

        const now = new Date().toISOString();
        const code = `adj_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
        const ok = await this.#repo.updateUserBalance(id, newBalance, code, notes, now);
        if (!ok) throw new AdminUserRoutesError(404, "USER_NOT_FOUND", "user not found");

        return (await this.#repo.findUserById(id))!;
    }

    async getUserUsage(id: number, period: string): Promise<{ period: string; totalRequests: number; totalCost: number; totalTokens: number; avgDurationMs: number }> {
        if (id <= 0) throw new AdminUserRoutesError(400, "INVALID_USER_ID", "user_id must be positive");
        const user = await this.#repo.findUserById(id);
        if (user === null) throw new AdminUserRoutesError(404, "USER_NOT_FOUND", "user not found");
        return { period: period || "month", totalRequests: 0, totalCost: 0, totalTokens: 0, avgDurationMs: 0 };
    }

    async getBalanceHistory(id: number, page: number, pageSize: number, type?: string): Promise<{ items: BalanceHistoryItem[]; total: number; page: number; pageSize: number; pages: number; totalRecharged: number }> {
        if (id <= 0) throw new AdminUserRoutesError(400, "INVALID_USER_ID", "user_id must be positive");
        const user = await this.#repo.findUserById(id);
        if (user === null) throw new AdminUserRoutesError(404, "USER_NOT_FOUND", "user not found");

        const p = Math.max(1, page);
        const ps = Math.min(100, Math.max(1, pageSize));
        let result: { items: BalanceHistoryItem[]; total: number };

        if (type === "affiliate_balance") {
            result = await this.#repo.getAffiliateBalanceHistory(id, p, ps);
        } else {
            result = await this.#repo.listBalanceHistory(id, p, ps, type);
        }

        const totalRecharged = await this.#repo.getTotalRecharged(id);
        const pages = Math.max(1, Math.ceil(result.total / ps));
        return { ...result, page: p, pageSize: ps, pages, totalRecharged };
    }

    async batchConcurrency(userIds: number[], all: boolean, concurrency: number, mode: string): Promise<{ affected: number }> {
        if (!Number.isInteger(concurrency) || concurrency < 0) throw new AdminUserRoutesError(400, "INVALID_CONCURRENCY", "concurrency must be a non-negative integer");
        if (!["set", "add"].includes(mode)) throw new AdminUserRoutesError(400, "INVALID_MODE", "mode must be set or add");

        let ids = userIds.filter((id) => id > 0);
        if (all) {
            ids = await this.#repo.getAllUserIds();
        }
        if (ids.length === 0) throw new AdminUserRoutesError(400, "EMPTY_USER_IDS", "user_ids cannot be empty");

        const affected = mode === "set"
            ? await this.#repo.batchSetConcurrency(ids, concurrency)
            : await this.#repo.batchAddConcurrency(ids, concurrency);
        return { affected };
    }

    async getPlatformQuotas(id: number): Promise<PlatformQuota[]> {
        if (id <= 0) throw new AdminUserRoutesError(400, "INVALID_USER_ID", "user_id must be positive");
        const user = await this.#repo.findUserById(id);
        if (user === null) throw new AdminUserRoutesError(404, "USER_NOT_FOUND", "user not found");
        return this.#repo.listPlatformQuotas(id);
    }

    async updatePlatformQuotas(id: number, quotas: { platform: string; dailyLimitUsd: number | null; weeklyLimitUsd: number | null; monthlyLimitUsd: number | null }[]): Promise<PlatformQuota[]> {
        if (id <= 0) throw new AdminUserRoutesError(400, "INVALID_USER_ID", "user_id must be positive");
        const user = await this.#repo.findUserById(id);
        if (user === null) throw new AdminUserRoutesError(404, "USER_NOT_FOUND", "user not found");

        for (const q of quotas) {
            if (!ALLOWED_PLATFORMS.includes(q.platform)) throw new AdminUserRoutesError(400, "INVALID_PLATFORM", `platform must be one of ${ALLOWED_PLATFORMS.join(", ")}`);
            for (const val of [q.dailyLimitUsd, q.weeklyLimitUsd, q.monthlyLimitUsd]) {
                if (val !== null && (!Number.isFinite(val) || val < 0)) throw new AdminUserRoutesError(400, "INVALID_LIMIT", "limits must be non-negative or null");
            }
        }

        await this.#repo.upsertPlatformQuotas(id, quotas);
        return this.#repo.listPlatformQuotas(id);
    }

    async resetPlatformQuotaWindow(id: number, platform: string, window: string): Promise<PlatformQuota[]> {
        if (id <= 0) throw new AdminUserRoutesError(400, "INVALID_USER_ID", "user_id must be positive");
        if (!ALLOWED_PLATFORMS.includes(platform)) throw new AdminUserRoutesError(400, "INVALID_PLATFORM", `platform must be one of ${ALLOWED_PLATFORMS.join(", ")}`);
        if (!ALLOWED_WINDOWS.includes(window)) throw new AdminUserRoutesError(400, "INVALID_WINDOW", `window must be one of ${ALLOWED_WINDOWS.join(", ")}`);

        const user = await this.#repo.findUserById(id);
        if (user === null) throw new AdminUserRoutesError(404, "USER_NOT_FOUND", "user not found");

        await this.#repo.resetPlatformQuotaWindow(id, platform, window);
        return this.#repo.listPlatformQuotas(id);
    }

    async createUser(input: {
        email: string; password: string; username: string; notes: string; role: string;
        balance: number | null; concurrency: number; rpmLimit: number; allowedGroups: number[];
    }, passwords: PasswordHasher): Promise<UserDetail> {
        if (!input.email || !input.email.includes("@")) throw new AdminUserRoutesError(400, "INVALID_EMAIL", "email is required and must be valid");
        if (!input.password || input.password.length < 6) throw new AdminUserRoutesError(400, "INVALID_PASSWORD", "password must be at least 6 characters");
        const role = input.role === "admin" ? "admin" : "user";
        const balance = input.balance ?? 0;
        const passwordHash = await passwords.hash(input.password);
        const userId = await this.#repo.createUser({
            email: input.email, passwordHash, username: input.username ?? "", notes: input.notes ?? "",
            role, balance, concurrency: input.concurrency ?? 0, rpmLimit: input.rpmLimit ?? 0,
            allowedGroups: input.allowedGroups ?? [],
        });
        return this.getUserById(userId);
    }

    async updateUser(id: number, input: {
        email?: string; password?: string; username?: string | null; notes?: string | null;
        role?: string; status?: string; balance?: number | null; concurrency?: number | null;
        rpmLimit?: number | null; allowedGroups?: number[] | null; groupRates?: Record<string, number | null>;
    }, passwords: PasswordHasher, adminUserId: number): Promise<UserDetail> {
        if (id <= 0) throw new AdminUserRoutesError(400, "INVALID_USER_ID", "user_id must be positive");
        const user = await this.#repo.findUserById(id, true);
        if (user === null) throw new AdminUserRoutesError(404, "USER_NOT_FOUND", "user not found");

        if (input.status === "disabled" && user.role === "admin") {
            throw new AdminUserRoutesError(400, "CANNOT_DISABLE_ADMIN", "cannot disable admin user");
        }

        if (input.role === "user" && user.role === "admin" && id === adminUserId) {
            throw new AdminUserRoutesError(400, "CANNOT_DEMOTE_SELF", "cannot demote yourself from admin");
        }

        if (input.role === "user" && user.role === "admin") {
            const isLast = await this.#repo.isLastAdmin(id);
            if (isLast) throw new AdminUserRoutesError(400, "CANNOT_DEMOTE_LAST_ADMIN", "cannot demote the last admin user");
        }

        const updateInput: {
            email?: string; passwordHash?: string; username?: string; notes?: string;
            role?: string; status?: string; balance?: number; concurrency?: number;
            rpmLimit?: number; allowedGroups?: number[]; groupRates?: Record<string, number | null>;
        } = {};

        if (input.email !== undefined && input.email !== "") updateInput.email = input.email;
        if (input.password !== undefined && input.password !== "") {
            updateInput.passwordHash = await passwords.hash(input.password);
        }
        if (input.username !== undefined) updateInput.username = input.username ?? "";
        if (input.notes !== undefined) updateInput.notes = input.notes ?? "";
        if (input.role !== undefined && input.role !== "") updateInput.role = input.role;
        if (input.status !== undefined && input.status !== "") updateInput.status = input.status;
        if (input.balance !== undefined) updateInput.balance = input.balance ?? undefined;
        if (input.concurrency !== undefined) updateInput.concurrency = input.concurrency ?? undefined;
        if (input.rpmLimit !== undefined) updateInput.rpmLimit = input.rpmLimit ?? undefined;
        if (input.allowedGroups !== undefined) updateInput.allowedGroups = input.allowedGroups ?? undefined;
        if (input.groupRates !== undefined) {
            for (const [gid, rate] of Object.entries(input.groupRates)) {
                if (rate !== null && rate <= 0) throw new AdminUserRoutesError(400, "INVALID_RATE", `rate_multiplier must be > 0 (group_id=${gid})`);
            }
            updateInput.groupRates = input.groupRates;
        }

        const ok = await this.#repo.updateUser(id, updateInput);
        if (!ok) throw new AdminUserRoutesError(404, "USER_NOT_FOUND", "user not found");
        return this.getUserById(id, true);
    }

    async deleteUser(id: number): Promise<void> {
        if (id <= 0) throw new AdminUserRoutesError(400, "INVALID_USER_ID", "user_id must be positive");
        const user = await this.#repo.findUserById(id);
        if (user === null) throw new AdminUserRoutesError(404, "USER_NOT_FOUND", "user not found");
        if (user.role === "admin") throw new AdminUserRoutesError(400, "CANNOT_DELETE_ADMIN", "cannot delete admin user");
        const ok = await this.#repo.deleteUser(id);
        if (!ok) throw new AdminUserRoutesError(404, "USER_NOT_FOUND", "user not found");
    }

    async bindAuthIdentity(userId: number, input: {
        providerType: string; providerKey: string; providerSubject: string;
        issuer: string | null; metadata: Record<string, unknown>;
        channel: { channel: string; channelAppId: string; channelSubject: string; metadata: Record<string, unknown> } | null;
    }): Promise<AuthIdentityItem> {
        if (userId <= 0) throw new AdminUserRoutesError(400, "INVALID_USER_ID", "user_id must be positive");
        const user = await this.#repo.findUserById(userId);
        if (user === null) throw new AdminUserRoutesError(404, "USER_NOT_FOUND", "user not found");
        if (!input.providerType || !input.providerKey || !input.providerSubject) {
            throw new AdminUserRoutesError(400, "INVALID_INPUT", "provider_type, provider_key, and provider_subject are required");
        }
        const allowedTypes = ["email", "linuxdo", "oidc", "wechat", "dingtalk"];
        if (!allowedTypes.includes(input.providerType)) {
            throw new AdminUserRoutesError(400, "INVALID_PROVIDER_TYPE", `provider_type must be one of ${allowedTypes.join(", ")}`);
        }
        if (input.channel !== null) {
            if (!input.channel.channel || !input.channel.channelAppId || !input.channel.channelSubject) {
                throw new AdminUserRoutesError(400, "INVALID_CHANNEL", "channel, channel_app_id, and channel_subject are required when channel binding is provided");
            }
        }
        return this.#repo.bindAuthIdentity(userId, input);
    }

    async getUserAPIKeys(userId: number, page: number, pageSize: number, sortBy: string, sortOrder: string): Promise<{ items: APIKeyItem[]; total: number; page: number; pageSize: number }> {
        if (userId <= 0) throw new AdminUserRoutesError(400, "INVALID_USER_ID", "user_id must be positive");
        const user = await this.#repo.findUserById(userId);
        if (user === null) throw new AdminUserRoutesError(404, "USER_NOT_FOUND", "user not found");
        const p = Math.max(1, page);
        const ps = Math.min(100, Math.max(1, pageSize));
        const result = await this.#repo.listUserAPIKeys(userId, p, ps, sortBy, sortOrder);
        return { ...result, page: p, pageSize: ps };
    }

    async replaceUserGroup(userId: number, oldGroupId: number, newGroupId: number): Promise<ReplaceGroupResult> {
        if (userId <= 0) throw new AdminUserRoutesError(400, "INVALID_USER_ID", "user_id must be positive");
        if (oldGroupId === newGroupId) throw new AdminUserRoutesError(400, "SAME_GROUP", "old and new group must be different");
        const user = await this.#repo.findUserById(userId);
        if (user === null) throw new AdminUserRoutesError(404, "USER_NOT_FOUND", "user not found");
        const newGroup = await this.#repo.findGroupById(newGroupId);
        if (newGroup === null) throw new AdminUserRoutesError(404, "GROUP_NOT_FOUND", "target group not found");
        if (newGroup.status !== "active") throw new AdminUserRoutesError(400, "GROUP_NOT_ACTIVE", "target group is not active");
        if (newGroup.isExclusive !== 1) throw new AdminUserRoutesError(400, "GROUP_NOT_EXCLUSIVE", "target group is not exclusive");
        const migratedKeys = await this.#repo.replaceUserGroup(userId, oldGroupId, newGroupId);
        return { migratedKeys };
    }

    async getUserRPMStatus(userId: number): Promise<{ userRpmUsed: number; userRpmLimit: number; perGroup: unknown[] }> {
        if (userId <= 0) throw new AdminUserRoutesError(400, "INVALID_USER_ID", "user_id must be positive");
        const user = await this.#repo.findUserById(userId);
        if (user === null) throw new AdminUserRoutesError(404, "USER_NOT_FOUND", "user not found");
        return { userRpmUsed: 0, userRpmLimit: user.rpmLimit, perGroup: [] };
    }
}
