import type { D1Database, D1Value } from "../types/d1.ts";
import {
    D1ChannelRepository,
    type ChannelRecord,
    type ChannelWithRelationsRecord,
    type ChannelModelPricingRecord,
    type AccountStatsPricingRuleRecord,
} from "../repositories/channels.ts";

export class ChannelError extends Error {
    status: number;
    code: string;
    constructor(status: number, message: string, code: string) {
        super(message);
        this.name = "ChannelError";
        this.status = status;
        this.code = code;
    }
}

function errNotFound(): ChannelError {
    return new ChannelError(404, "Channel not found", "CHANNEL_NOT_FOUND");
}

function errConflict(msg: string): ChannelError {
    return new ChannelError(409, msg, "CONFLICT");
}

function errBadRequest(msg: string): ChannelError {
    return new ChannelError(400, msg, "BAD_REQUEST");
}

export interface ModelPricingInput {
    platform?: string; models: string[]; billingMode?: string;
    inputPrice?: number | null; outputPrice?: number | null; cacheWritePrice?: number | null;
    cacheReadPrice?: number | null; imageOutputPrice?: number | null; perRequestPrice?: number | null;
    intervals?: Array<{
        minTokens?: number; maxTokens?: number | null; tierLabel?: string | null;
        inputPrice?: number | null; outputPrice?: number | null; cacheWritePrice?: number | null;
        cacheReadPrice?: number | null; perRequestPrice?: number | null; sortOrder?: number;
    }>;
}

export interface AccountStatsPricingRuleInput {
    name?: string; groupIds?: number[]; accountIds?: number[];
    pricing?: ModelPricingInput[];
}

function normalizePricingInput(p: ModelPricingInput): {
    platform: string; models: string[]; billingMode: string;
    inputPrice: number | null; outputPrice: number | null; cacheWritePrice: number | null;
    cacheReadPrice: number | null; imageOutputPrice: number | null; perRequestPrice: number | null;
    intervals: Array<{
        minTokens: number; maxTokens: number | null; tierLabel: string | null;
        inputPrice: number | null; outputPrice: number | null; cacheWritePrice: number | null;
        cacheReadPrice: number | null; perRequestPrice: number | null; sortOrder: number;
    }>;
} {
    return {
        platform: p.platform ?? "anthropic",
        models: p.models,
        billingMode: p.billingMode ?? "token",
        inputPrice: p.inputPrice ?? null,
        outputPrice: p.outputPrice ?? null,
        cacheWritePrice: p.cacheWritePrice ?? null,
        cacheReadPrice: p.cacheReadPrice ?? null,
        imageOutputPrice: p.imageOutputPrice ?? null,
        perRequestPrice: p.perRequestPrice ?? null,
        intervals: (p.intervals ?? []).map((iv, idx) => ({
            minTokens: iv.minTokens ?? 0,
            maxTokens: iv.maxTokens ?? null,
            tierLabel: iv.tierLabel ?? null,
            inputPrice: iv.inputPrice ?? null,
            outputPrice: iv.outputPrice ?? null,
            cacheWritePrice: iv.cacheWritePrice ?? null,
            cacheReadPrice: iv.cacheReadPrice ?? null,
            perRequestPrice: iv.perRequestPrice ?? null,
            sortOrder: iv.sortOrder ?? idx,
        })),
    };
}

export class D1ChannelService {
    private repo: D1ChannelRepository;
    constructor(db: D1Database) {
        this.repo = new D1ChannelRepository(db);
    }

    async list(params: {
        page: number; pageSize: number; status?: string;
        search?: string; sortBy?: string; sortOrder?: string;
    }): Promise<{ items: ChannelWithRelationsRecord[]; total: number }> {
        return this.repo.list(params);
    }

    async getById(id: number): Promise<ChannelWithRelationsRecord> {
        const record = await this.repo.getById(id);
        if (!record) throw errNotFound();
        return record;
    }

    async create(input: {
        name: string; description?: string; groupIds?: number[];
        modelPricing?: ModelPricingInput[]; modelMapping?: Record<string, Record<string, string>>;
        billingModelSource?: string; restrictModels?: boolean; features?: string;
        featuresConfig?: Record<string, unknown>; applyPricingToAccountStats?: boolean;
        accountStatsPricingRules?: AccountStatsPricingRuleInput[];
    }): Promise<ChannelWithRelationsRecord> {
        const name = input.name.trim();
        if (name === "" || name.length > 100) throw errBadRequest("Name is required and must be 100 characters or less");
        if (await this.repo.existsByName(name)) throw errConflict("Channel name already exists");

        const channel = await this.repo.create({
            name,
            description: input.description,
            modelMapping: input.modelMapping,
            billingModelSource: input.billingModelSource,
            restrictModels: input.restrictModels,
            features: input.features,
            featuresConfig: input.featuresConfig,
            applyPricingToAccountStats: input.applyPricingToAccountStats,
        });

        if (input.groupIds && input.groupIds.length > 0) {
            await this.repo.setGroupIds(channel.id, input.groupIds);
        }
        if (input.modelPricing && input.modelPricing.length > 0) {
            await this.repo.replaceModelPricing(channel.id, input.modelPricing.map(normalizePricingInput));
        }
        if (input.accountStatsPricingRules && input.accountStatsPricingRules.length > 0) {
            const rules = input.accountStatsPricingRules.map((r, idx) => ({
                name: r.name ?? "",
                groupIds: r.groupIds ?? [],
                accountIds: r.accountIds ?? [],
                sortOrder: idx,
                pricing: (r.pricing ?? []).map(normalizePricingInput),
            }));
            await this.repo.replaceAccountStatsRules(channel.id, rules);
        }

        return (await this.repo.getById(channel.id))!;
    }

    async update(id: number, input: {
        name?: string; description?: string | null; status?: string;
        groupIds?: number[] | null; modelPricing?: ModelPricingInput[] | null;
        modelMapping?: Record<string, Record<string, string>>;
        billingModelSource?: string; restrictModels?: boolean | null;
        features?: string | null; featuresConfig?: Record<string, unknown>;
        applyPricingToAccountStats?: boolean | null;
        accountStatsPricingRules?: AccountStatsPricingRuleInput[] | null;
    }): Promise<ChannelWithRelationsRecord> {
        const existing = await this.repo.getById(id);
        if (!existing) throw errNotFound();

        const updates: Record<string, D1Value> = {};
        if (input.name !== undefined) {
            const name = input.name.trim();
            if (name === "" || name.length > 100) throw errBadRequest("Name must be 100 characters or less");
            if (await this.repo.existsByNameExcluding(name, id)) throw errConflict("Channel name already exists");
            updates.name = name;
        }
        if (input.description !== undefined) updates.description = input.description;
        if (input.status !== undefined) {
            if (!["active", "disabled"].includes(input.status)) throw errBadRequest("Status must be 'active' or 'disabled'");
            updates.status = input.status;
        }
        if (input.modelMapping !== undefined) updates.model_mapping = JSON.stringify(input.modelMapping);
        if (input.billingModelSource !== undefined) updates.billing_model_source = input.billingModelSource;
        if (input.restrictModels !== undefined) updates.restrict_models = input.restrictModels ? 1 : 0;
        if (input.features !== undefined) updates.features = input.features;
        if (input.featuresConfig !== undefined) updates.features_config = JSON.stringify(input.featuresConfig);
        if (input.applyPricingToAccountStats !== undefined) updates.apply_pricing_to_account_stats = input.applyPricingToAccountStats ? 1 : 0;

        if (Object.keys(updates).length > 0) {
            await this.repo.update(id, updates);
        }

        if (input.groupIds !== undefined && input.groupIds !== null) {
            await this.repo.setGroupIds(id, input.groupIds);
        }
        if (input.modelPricing !== undefined && input.modelPricing !== null) {
            await this.repo.replaceModelPricing(id, input.modelPricing.map(normalizePricingInput));
        }
        if (input.accountStatsPricingRules !== undefined) {
            const rules = (input.accountStatsPricingRules ?? []).map((r, idx) => ({
                name: r.name ?? "",
                groupIds: r.groupIds ?? [],
                accountIds: r.accountIds ?? [],
                sortOrder: idx,
                pricing: (r.pricing ?? []).map(normalizePricingInput),
            }));
            await this.repo.replaceAccountStatsRules(id, rules);
        }

        return (await this.repo.getById(id))!;
    }

    async delete(id: number): Promise<void> {
        const existing = await this.repo.getById(id);
        if (!existing) throw errNotFound();
        await this.repo.delete(id);
    }
}
