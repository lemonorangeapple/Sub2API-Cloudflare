import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement } from "./d1.ts";

export interface PricingIntervalRecord {
    id: number;
    pricingId: number;
    minTokens: number;
    maxTokens: number | null;
    tierLabel: string | null;
    inputPrice: number | null;
    outputPrice: number | null;
    cacheWritePrice: number | null;
    cacheReadPrice: number | null;
    perRequestPrice: number | null;
    sortOrder: number;
}

export interface ChannelModelPricingRecord {
    id: number;
    channelId: number;
    platform: string;
    models: string[];
    billingMode: string;
    inputPrice: number | null;
    outputPrice: number | null;
    cacheWritePrice: number | null;
    cacheReadPrice: number | null;
    imageOutputPrice: number | null;
    perRequestPrice: number | null;
    intervals: PricingIntervalRecord[];
}

export interface AccountStatsPricingRuleRecord {
    id: number;
    channelId: number;
    name: string;
    groupIds: number[];
    accountIds: number[];
    sortOrder: number;
    pricing: ChannelModelPricingRecord[];
}

export interface ChannelRecord {
    id: number;
    name: string;
    description: string;
    status: string;
    modelMapping: Record<string, Record<string, string>>;
    billingModelSource: string;
    restrictModels: boolean;
    features: string;
    featuresConfig: Record<string, unknown>;
    applyPricingToAccountStats: boolean;
    createdAt: string;
    updatedAt: string;
}

export interface ChannelWithRelationsRecord extends ChannelRecord {
    groupIds: number[];
    modelPricing: ChannelModelPricingRecord[];
    accountStatsPricingRules: AccountStatsPricingRuleRecord[];
}

interface ChannelRow {
    id: number;
    name: string;
    description: string;
    status: string;
    model_mapping: string;
    billing_model_source: string;
    restrict_models: number;
    features: string;
    features_config: string;
    apply_pricing_to_account_stats: number;
    created_at: string;
    updated_at: string;
}

function nowISO(): string {
    return new Date().toISOString();
}

function parseJson<T>(s: string, fallback: T): T {
    try { return JSON.parse(s) as T; } catch { return fallback; }
}

function channelRowToRecord(row: ChannelRow): ChannelRecord {
    return {
        id: row.id,
        name: row.name,
        description: row.description,
        status: row.status,
        modelMapping: parseJson(row.model_mapping, {}),
        billingModelSource: row.billing_model_source,
        restrictModels: row.restrict_models === 1,
        features: row.features,
        featuresConfig: parseJson(row.features_config, {}),
        applyPricingToAccountStats: row.apply_pricing_to_account_stats === 1,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    };
}

export class D1ChannelRepository {
    private db: D1Database;
    constructor(db: D1Database) {
        this.db = db;
    }

    async create(input: {
        name: string; description?: string; modelMapping?: Record<string, Record<string, string>>;
        billingModelSource?: string; restrictModels?: boolean; features?: string;
        featuresConfig?: Record<string, unknown>; applyPricingToAccountStats?: boolean;
    }): Promise<ChannelRecord> {
        const ts = nowISO();
        const sql = `INSERT INTO channels (name, description, status, model_mapping, billing_model_source, restrict_models, features, features_config, apply_pricing_to_account_stats, created_at, updated_at) VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`;
        const vals: D1Value[] = [
            input.name,
            input.description ?? "",
            JSON.stringify(input.modelMapping ?? {}),
            input.billingModelSource ?? "channel_mapped",
            input.restrictModels ? 1 : 0,
            input.features ?? "",
            JSON.stringify(input.featuresConfig ?? {}),
            input.applyPricingToAccountStats ? 1 : 0,
            ts, ts,
        ];
        const row = await firstRow<ChannelRow>(this.db, sql, vals);
        return channelRowToRecord(row!);
    }

    async getById(id: number): Promise<ChannelWithRelationsRecord | null> {
        const chRow = await firstRow<ChannelRow>(this.db, `SELECT * FROM channels WHERE id = ?`, [id]);
        if (!chRow) return null;
        const record = channelRowToRecord(chRow);
        const groupIds = await this.getGroupIds(id);
        const modelPricing = await this.listModelPricing(id);
        const accountStatsPricingRules = await this.listAccountStatsRules(id);
        return { ...record, groupIds, modelPricing, accountStatsPricingRules };
    }

    async existsByName(name: string): Promise<boolean> {
        const row = await firstRow<{ c: number }>(this.db, `SELECT COUNT(*) as c FROM channels WHERE name = ?`, [name]);
        return row !== null && row.c > 0;
    }

    async existsByNameExcluding(name: string, excludeId: number): Promise<boolean> {
        const row = await firstRow<{ c: number }>(this.db, `SELECT COUNT(*) as c FROM channels WHERE name = ? AND id != ?`, [name, excludeId]);
        return row !== null && row.c > 0;
    }

    async update(id: number, input: Record<string, D1Value>): Promise<ChannelRecord | null> {
        const setClauses: string[] = [];
        const values: D1Value[] = [];
        for (const [key, value] of Object.entries(input)) {
            if (key === "id" || key === "created_at") continue;
            setClauses.push(`${key} = ?`);
            values.push(value ?? null);
        }
        if (setClauses.length === 0) return (await this.getById(id)) ?? null;
        setClauses.push("updated_at = ?");
        values.push(nowISO());
        values.push(id);
        const sql = `UPDATE channels SET ${setClauses.join(", ")} WHERE id = ? RETURNING *`;
        const row = await firstRow<ChannelRow>(this.db, sql, values);
        return row ? channelRowToRecord(row) : null;
    }

    async delete(id: number): Promise<boolean> {
        const result = await runStatement(this.db, `DELETE FROM channels WHERE id = ?`, [id]);
        return result.success && (result.meta?.changes ?? 0) > 0;
    }

    async listAll(): Promise<ChannelWithRelationsRecord[]> {
        const rows = await allRows<ChannelRow>(this.db, `SELECT * FROM channels ORDER BY name ASC`);
        const items: ChannelWithRelationsRecord[] = [];
        for (const row of rows) {
            const record = channelRowToRecord(row);
            const groupIds = await this.getGroupIds(record.id);
            const modelPricing = await this.listModelPricing(record.id);
            const accountStatsPricingRules = await this.listAccountStatsRules(record.id);
            items.push({ ...record, groupIds, modelPricing, accountStatsPricingRules });
        }
        return items;
    }

    async list(params: {
        page: number; pageSize: number; status?: string; search?: string;
        sortBy?: string; sortOrder?: string;
    }): Promise<{ items: ChannelWithRelationsRecord[]; total: number }> {
        const where: string[] = [];
        const values: D1Value[] = [];
        if (params.status) { where.push("c.status = ?"); values.push(params.status); }
        if (params.search) { where.push("(c.name LIKE ? OR c.description LIKE ?)"); values.push(`%${params.search}%`, `%${params.search}%`); }
        const whereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
        const sortBy = params.sortBy ?? "created_at";
        const sortOrder = params.sortOrder ?? "desc";
        const safeSortBy = ["id", "name", "status", "created_at", "updated_at"].includes(sortBy) ? `c.${sortBy}` : "c.created_at";
        const safeSortOrder = sortOrder === "asc" ? "ASC" : "DESC";

        const countRow = await firstRow<{ c: number }>(this.db, `SELECT COUNT(*) as c FROM channels c ${whereClause}`, values);
        const total = countRow?.c ?? 0;
        const offset = (params.page - 1) * params.pageSize;
        const rows = await allRows<ChannelRow>(this.db, `SELECT c.* FROM channels c ${whereClause} ORDER BY ${safeSortBy} ${safeSortOrder}, c.id DESC LIMIT ? OFFSET ?`, [...values, params.pageSize, offset]);
        const items: ChannelWithRelationsRecord[] = [];
        for (const row of rows) {
            const record = channelRowToRecord(row);
            const groupIds = await this.getGroupIds(record.id);
            const modelPricing = await this.listModelPricing(record.id);
            const accountStatsPricingRules = await this.listAccountStatsRules(record.id);
            items.push({ ...record, groupIds, modelPricing, accountStatsPricingRules });
        }
        return { items, total };
    }

    async setGroupIds(channelId: number, groupIds: number[]): Promise<void> {
        await runStatement(this.db, `DELETE FROM channel_groups WHERE channel_id = ?`, [channelId]);
        for (const gid of groupIds) {
            await runStatement(this.db, `INSERT INTO channel_groups (channel_id, group_id) VALUES (?, ?)`, [channelId, gid]);
        }
    }

    async getGroupIds(channelId: number): Promise<number[]> {
        const rows = await allRows<{ group_id: number }>(this.db, `SELECT group_id FROM channel_groups WHERE channel_id = ? ORDER BY group_id`, [channelId]);
        return rows.map((r) => r.group_id);
    }

    async replaceModelPricing(channelId: number, pricing: Array<{
        platform: string; models: string[]; billingMode: string;
        inputPrice: number | null; outputPrice: number | null; cacheWritePrice: number | null;
        cacheReadPrice: number | null; imageOutputPrice: number | null; perRequestPrice: number | null;
        intervals: Array<{
            minTokens: number; maxTokens: number | null; tierLabel: string | null;
            inputPrice: number | null; outputPrice: number | null; cacheWritePrice: number | null;
            cacheReadPrice: number | null; perRequestPrice: number | null; sortOrder: number;
        }>;
    }>): Promise<void> {
        await runStatement(this.db, `DELETE FROM channel_model_pricing WHERE channel_id = ?`, [channelId]);
        for (const p of pricing) {
            const sql = `INSERT INTO channel_model_pricing (channel_id, platform, models, billing_mode, input_price, output_price, cache_write_price, cache_read_price, image_output_price, per_request_price) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`;
            const vals: D1Value[] = [channelId, p.platform, JSON.stringify(p.models), p.billingMode, p.inputPrice, p.outputPrice, p.cacheWritePrice, p.cacheReadPrice, p.imageOutputPrice, p.perRequestPrice];
            const row = await firstRow<{ id: number }>(this.db, sql, vals);
            const pricingId = row!.id;
            for (const iv of p.intervals) {
                await runStatement(this.db, `INSERT INTO channel_pricing_intervals (pricing_id, min_tokens, max_tokens, tier_label, input_price, output_price, cache_write_price, cache_read_price, per_request_price, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [pricingId, iv.minTokens, iv.maxTokens, iv.tierLabel, iv.inputPrice, iv.outputPrice, iv.cacheWritePrice, iv.cacheReadPrice, iv.perRequestPrice, iv.sortOrder]);
            }
        }
    }

    async listModelPricing(channelId: number): Promise<ChannelModelPricingRecord[]> {
        const rows = await allRows<{ id: number; channel_id: number; platform: string; models: string; billing_mode: string; input_price: number | null; output_price: number | null; cache_write_price: number | null; cache_read_price: number | null; image_output_price: number | null; per_request_price: number | null }>(this.db, `SELECT * FROM channel_model_pricing WHERE channel_id = ? ORDER BY id`, [channelId]);
        const result: ChannelModelPricingRecord[] = [];
        for (const r of rows) {
            const intervals = await allRows<{ id: number; pricing_id: number; min_tokens: number; max_tokens: number | null; tier_label: string | null; input_price: number | null; output_price: number | null; cache_write_price: number | null; cache_read_price: number | null; per_request_price: number | null; sort_order: number }>(this.db, `SELECT * FROM channel_pricing_intervals WHERE pricing_id = ? ORDER BY sort_order, id`, [r.id]);
            result.push({
                id: r.id, channelId: r.channel_id, platform: r.platform,
                models: parseJson(r.models, []), billingMode: r.billing_mode,
                inputPrice: r.input_price, outputPrice: r.output_price,
                cacheWritePrice: r.cache_write_price, cacheReadPrice: r.cache_read_price,
                imageOutputPrice: r.image_output_price, perRequestPrice: r.per_request_price,
                intervals: intervals.map((iv) => ({
                    id: iv.id, pricingId: iv.pricing_id, minTokens: iv.min_tokens,
                    maxTokens: iv.max_tokens, tierLabel: iv.tier_label,
                    inputPrice: iv.input_price, outputPrice: iv.output_price,
                    cacheWritePrice: iv.cache_write_price, cacheReadPrice: iv.cache_read_price,
                    perRequestPrice: iv.per_request_price, sortOrder: iv.sort_order,
                })),
            });
        }
        return result;
    }

    async replaceAccountStatsRules(channelId: number, rules: Array<{
        name: string; groupIds: number[]; accountIds: number[]; sortOrder: number;
        pricing: Array<{
            platform: string; models: string[]; billingMode: string;
            inputPrice: number | null; outputPrice: number | null; cacheWritePrice: number | null;
            cacheReadPrice: number | null; imageOutputPrice: number | null; perRequestPrice: number | null;
            intervals: Array<{
                minTokens: number; maxTokens: number | null; tierLabel: string | null;
                inputPrice: number | null; outputPrice: number | null; cacheWritePrice: number | null;
                cacheReadPrice: number | null; perRequestPrice: number | null; sortOrder: number;
            }>;
        }>;
    }>): Promise<void> {
        await runStatement(this.db, `DELETE FROM channel_account_stats_pricing_rules WHERE channel_id = ?`, [channelId]);
        for (const rule of rules) {
            const sql = `INSERT INTO channel_account_stats_pricing_rules (channel_id, name, group_ids, account_ids, sort_order) VALUES (?, ?, ?, ?, ?) RETURNING id`;
            const vals: D1Value[] = [channelId, rule.name, JSON.stringify(rule.groupIds), JSON.stringify(rule.accountIds), rule.sortOrder];
            const row = await firstRow<{ id: number }>(this.db, sql, vals);
            const ruleId = row!.id;
            for (const p of rule.pricing) {
                const psql = `INSERT INTO channel_account_stats_model_pricing (rule_id, platform, models, billing_mode, input_price, output_price, cache_write_price, cache_read_price, image_output_price, per_request_price) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`;
                const pvals: D1Value[] = [ruleId, p.platform, JSON.stringify(p.models), p.billingMode, p.inputPrice, p.outputPrice, p.cacheWritePrice, p.cacheReadPrice, p.imageOutputPrice, p.perRequestPrice];
                const prow = await firstRow<{ id: number }>(this.db, psql, pvals);
                const pricingId = prow!.id;
                for (const iv of p.intervals) {
                    await runStatement(this.db, `INSERT INTO channel_account_stats_pricing_intervals (pricing_id, min_tokens, max_tokens, tier_label, input_price, output_price, cache_write_price, cache_read_price, per_request_price, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [pricingId, iv.minTokens, iv.maxTokens, iv.tierLabel, iv.inputPrice, iv.outputPrice, iv.cacheWritePrice, iv.cacheReadPrice, iv.perRequestPrice, iv.sortOrder]);
                }
            }
        }
    }

    async listAccountStatsRules(channelId: number): Promise<AccountStatsPricingRuleRecord[]> {
        const rows = await allRows<{ id: number; channel_id: number; name: string; group_ids: string; account_ids: string; sort_order: number }>(this.db, `SELECT * FROM channel_account_stats_pricing_rules WHERE channel_id = ? ORDER BY sort_order, id`, [channelId]);
        const result: AccountStatsPricingRuleRecord[] = [];
        for (const r of rows) {
            const pricingRows = await allRows<{ id: number; rule_id: number; platform: string; models: string; billing_mode: string; input_price: number | null; output_price: number | null; cache_write_price: number | null; cache_read_price: number | null; image_output_price: number | null; per_request_price: number | null }>(this.db, `SELECT * FROM channel_account_stats_model_pricing WHERE rule_id = ? ORDER BY id`, [r.id]);
            const pricing: ChannelModelPricingRecord[] = [];
            for (const pr of pricingRows) {
                const intervals = await allRows<{ id: number; pricing_id: number; min_tokens: number; max_tokens: number | null; tier_label: string | null; input_price: number | null; output_price: number | null; cache_write_price: number | null; cache_read_price: number | null; per_request_price: number | null; sort_order: number }>(this.db, `SELECT * FROM channel_account_stats_pricing_intervals WHERE pricing_id = ? ORDER BY sort_order, id`, [pr.id]);
                pricing.push({
                    id: pr.id, channelId: r.channel_id, platform: pr.platform,
                    models: parseJson(pr.models, []), billingMode: pr.billing_mode,
                    inputPrice: pr.input_price, outputPrice: pr.output_price,
                    cacheWritePrice: pr.cache_write_price, cacheReadPrice: pr.cache_read_price,
                    imageOutputPrice: pr.image_output_price, perRequestPrice: pr.per_request_price,
                    intervals: intervals.map((iv) => ({
                        id: iv.id, pricingId: iv.pricing_id, minTokens: iv.min_tokens,
                        maxTokens: iv.max_tokens, tierLabel: iv.tier_label,
                        inputPrice: iv.input_price, outputPrice: iv.output_price,
                        cacheWritePrice: iv.cache_write_price, cacheReadPrice: iv.cache_read_price,
                        perRequestPrice: iv.per_request_price, sortOrder: iv.sort_order,
                    })),
                });
            }
            result.push({
                id: r.id, channelId: r.channel_id, name: r.name,
                groupIds: parseJson(r.group_ids, []), accountIds: parseJson(r.account_ids, []),
                sortOrder: r.sort_order, pricing,
            });
        }
        return result;
    }
}
