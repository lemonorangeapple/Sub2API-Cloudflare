import type {
    D1AffiliateRepository,
    AffiliateUserRecord,
    AffiliateUserLookup,
    AffiliateUserOverview,
    AffiliateInviteRecord,
    AffiliateRebateRecord,
    AffiliateTransferRecord,
    AffiliateAdminFilter,
    AffiliateRecordFilter,
    AffiliateDetailRecord,
} from "../repositories/affiliates.ts";

const AFFILIATE_CODE_REGEX = /^[A-Z0-9_-]{4,32}$/;

export class AffiliateError extends Error {
    readonly status: number;
    readonly code: string;

    constructor(status: number, code: string, message: string) {
        super(message);
        this.name = "AffiliateError";
        this.status = status;
        this.code = code;
    }
}

function validateAffiliateCode(code: string): void {
    if (!AFFILIATE_CODE_REGEX.test(code)) {
        throw new AffiliateError(400, "AFFILIATE_CODE_INVALID", "affiliate code must be 4-32 characters, uppercase letters, digits, underscore, or hyphen");
    }
}

function validateRate(rate: number): void {
    if (!Number.isFinite(rate) || rate < 0 || rate > 100) {
        throw new AffiliateError(400, "AFFILIATE_RATE_INVALID", "rebate rate must be between 0 and 100");
    }
}

export class D1AffiliateService {
    readonly #repo: D1AffiliateRepository;

    constructor(repo: D1AffiliateRepository) {
        this.#repo = repo;
    }

    async listUsers(filter: AffiliateAdminFilter): Promise<{ items: AffiliateUserRecord[]; total: number; page: number; pageSize: number; pages: number }> {
        const page = Math.max(1, filter.page ?? 1);
        const pageSize = Math.min(200, Math.max(1, filter.pageSize ?? 20));
        const result = await this.#repo.listUsersWithCustomSettings({ ...filter, page, pageSize });
        const pages = Math.max(1, Math.ceil(result.total / pageSize));
        return { ...result, page, pageSize, pages };
    }

    async lookupUsers(keyword: string): Promise<AffiliateUserLookup[]> {
        return this.#repo.lookupUsers(keyword);
    }

    async getUserOverview(userId: number): Promise<AffiliateUserOverview> {
        if (userId <= 0) throw new AffiliateError(400, "INVALID_USER_ID", "user_id must be positive");
        const overview = await this.#repo.getUserOverview(userId);
        if (overview === null) throw new AffiliateError(404, "AFFILIATE_PROFILE_NOT_FOUND", "affiliate profile not found");
        return overview;
    }

    async updateUserSettings(userId: number, input: { affCode?: string; affRebateRatePercent?: number | null; clearRebateRate?: boolean }): Promise<{ userId: number }> {
        if (userId <= 0) throw new AffiliateError(400, "INVALID_USER_ID", "user_id must be positive");

        if (input.affCode !== undefined) {
            const code = input.affCode.trim().toUpperCase();
            validateAffiliateCode(code);
            const ok = await this.#repo.updateUserAffCode(userId, code);
            if (!ok) throw new AffiliateError(404, "AFFILIATE_PROFILE_NOT_FOUND", "affiliate profile not found");
        }

        if (input.clearRebateRate === true) {
            await this.#repo.setUserRebateRate(userId, null);
        } else if (input.affRebateRatePercent !== undefined && input.affRebateRatePercent !== null) {
            validateRate(input.affRebateRatePercent);
            await this.#repo.setUserRebateRate(userId, input.affRebateRatePercent);
        }

        return { userId };
    }

    async clearUserSettings(userId: number): Promise<{ userId: number }> {
        if (userId <= 0) throw new AffiliateError(400, "INVALID_USER_ID", "user_id must be positive");
        await this.#repo.setUserRebateRate(userId, null);
        await this.#repo.resetUserAffCode(userId);
        return { userId };
    }

    async batchSetRate(userIds: number[], ratePercent: number | null, clear: boolean): Promise<{ affected: number }> {
        const validIds = userIds.filter((id) => id > 0);
        if (validIds.length === 0) throw new AffiliateError(400, "AFFILIATE_BATCH_EMPTY", "user_ids cannot be empty");
        if (!clear && ratePercent === null) throw new AffiliateError(400, "AFFILIATE_RATE_REQUIRED", "aff_rebate_rate_percent is required unless clear=true");
        if (ratePercent !== null) validateRate(ratePercent);
        const affected = await this.#repo.batchSetUserRebateRate(validIds, clear ? null : ratePercent);
        return { affected };
    }

    async listInviteRecords(filter: AffiliateRecordFilter): Promise<{ items: AffiliateInviteRecord[]; total: number; page: number; pageSize: number; pages: number }> {
        const page = Math.max(1, filter.page ?? 1);
        const pageSize = Math.min(100, Math.max(1, filter.pageSize ?? 20));
        const result = await this.#repo.listInviteRecords({ ...filter, page, pageSize });
        const pages = Math.max(1, Math.ceil(result.total / pageSize));
        return { ...result, page, pageSize, pages };
    }

    async listRebateRecords(filter: AffiliateRecordFilter): Promise<{ items: AffiliateRebateRecord[]; total: number; page: number; pageSize: number; pages: number }> {
        const page = Math.max(1, filter.page ?? 1);
        const pageSize = Math.min(100, Math.max(1, filter.pageSize ?? 20));
        const result = await this.#repo.listRebateRecords({ ...filter, page, pageSize });
        const pages = Math.max(1, Math.ceil(result.total / pageSize));
        return { ...result, page, pageSize, pages };
    }

    async listTransferRecords(filter: AffiliateRecordFilter): Promise<{ items: AffiliateTransferRecord[]; total: number; page: number; pageSize: number; pages: number }> {
        const page = Math.max(1, filter.page ?? 1);
        const pageSize = Math.min(100, Math.max(1, filter.pageSize ?? 20));
        const result = await this.#repo.listTransferRecords({ ...filter, page, pageSize });
        const pages = Math.max(1, Math.ceil(result.total / pageSize));
        return { ...result, page, pageSize, pages };
    }

    async getAffiliateDetail(userId: number): Promise<AffiliateDetailRecord> {
        if (userId <= 0) throw new AffiliateError(400, "INVALID_USER_ID", "user_id must be positive");
        await this.#repo.thawFrozenQuota(userId);
        await this.#repo.ensureUserAffiliate(userId);
        const detail = await this.#repo.getAffiliateDetail(userId);
        if (!detail) throw new AffiliateError(404, "AFFILIATE_PROFILE_NOT_FOUND", "affiliate profile not found");
        return detail;
    }

    async transferAffiliateQuota(userId: number): Promise<{ transferredQuota: number; balance: number }> {
        if (userId <= 0) throw new AffiliateError(400, "INVALID_USER_ID", "user_id must be positive");
        const result = await this.#repo.transferQuotaToBalance(userId);
        return { transferredQuota: result.transferred, balance: result.balance };
    }
}
