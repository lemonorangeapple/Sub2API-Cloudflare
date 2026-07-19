import type {
    D1UsageCleanupRepository,
    CleanupTaskRecord,
    SearchUserResult,
    SearchApiKeyResult,
} from "../repositories/usage-cleanup.ts";

export class UsageCleanupError extends Error {
    readonly status: number;
    readonly code: string;

    constructor(status: number, code: string, message: string) {
        super(message);
        this.name = "UsageCleanupError";
        this.status = status;
        this.code = code;
    }
}

export class D1UsageCleanupService {
    readonly #repo: D1UsageCleanupRepository;

    constructor(repo: D1UsageCleanupRepository) {
        this.#repo = repo;
    }

    async listTasks(page: number, pageSize: number): Promise<{ items: CleanupTaskRecord[]; total: number; page: number; pageSize: number; pages: number }> {
        const p = Math.max(1, page);
        const ps = Math.min(100, Math.max(1, pageSize));
        const result = await this.#repo.listTasks(p, ps);
        const pages = Math.max(1, Math.ceil(result.total / ps));
        return { ...result, page: p, pageSize: ps, pages };
    }

    async createTask(filters: Record<string, unknown>, createdBy: number): Promise<CleanupTaskRecord> {
        if (!filters.start_date || !filters.end_date) {
            throw new UsageCleanupError(400, "CLEANUP_DATE_REQUIRED", "start_date and end_date are required");
        }
        return this.#repo.createTask(filters, createdBy);
    }

    async cancelTask(id: number, canceledBy: number): Promise<{ id: number; status: string }> {
        if (id <= 0) throw new UsageCleanupError(400, "INVALID_TASK_ID", "task id must be positive");
        const existing = await this.#repo.getTask(id);
        if (existing === null) throw new UsageCleanupError(404, "CLEANUP_TASK_NOT_FOUND", "cleanup task not found");
        if (existing.status === "succeeded" || existing.status === "failed") {
            throw new UsageCleanupError(409, "CLEANUP_TASK_TERMINAL", "task is in a terminal state and cannot be canceled");
        }
        if (existing.status === "canceled") {
            return { id, status: "canceled" };
        }
        const ok = await this.#repo.cancelTask(id, canceledBy);
        return { id, status: ok ? "canceled" : existing.status };
    }

    async searchUsers(keyword: string): Promise<SearchUserResult[]> {
        return this.#repo.searchUsers(keyword);
    }

    async searchApiKeys(userId: number | null, keyword: string): Promise<SearchApiKeyResult[]> {
        return this.#repo.searchApiKeys(userId, keyword);
    }
}
