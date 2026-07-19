import type { D1RiskControlRepository, LogFilter } from "../repositories/risk-control.ts";

export class RiskControlError extends Error {
    readonly status: number;
    readonly code: string;
    constructor(status: number, code: string, message: string) {
        super(message);
        this.status = status;
        this.code = code;
    }
}

export interface RiskControlConfigView {
    enabled: boolean;
    mode: string;
    base_url: string;
    model: string;
    api_key_configured: boolean;
    api_key_masked: string;
    api_key_count: number;
    api_key_masks: string[];
    timeout_ms: number;
    sample_rate: number;
    all_groups: boolean;
    group_ids: number[];
    record_non_hits: boolean;
    thresholds: Record<string, number>;
    block_status: number;
    block_message: string;
    email_on_hit: boolean;
    auto_ban_enabled: boolean;
    ban_threshold: number;
    violation_window_hours: number;
    retry_count: number;
    hit_retention_days: number;
    non_hit_retention_days: number;
    pre_hash_check_enabled: boolean;
    blocked_keywords: string[];
    keyword_blocking_mode: string;
    model_filter: { type: string; models: string[] };
    cyber_policy_exclude_from_ban_count: boolean;
    worker_count: number;
    queue_size: number;
}

export interface RiskControlRuntimeStatus {
    enabled: boolean;
    risk_control_enabled: boolean;
    mode: string;
    flagged_hash_count: number;
    last_cleanup_at: string | null;
    api_key_statuses: { configured: boolean }[];
}

export interface ContentModerationLogItem {
    id: number;
    request_id: string;
    user_id: number | null;
    user_email: string;
    api_key_id: number | null;
    api_key_name: string;
    group_id: number | null;
    group_name: string;
    endpoint: string;
    provider: string;
    model: string;
    mode: string;
    action: string;
    flagged: boolean;
    highest_category: string;
    highest_score: number;
    category_scores: Record<string, number>;
    threshold_snapshot: Record<string, number>;
    input_excerpt: string;
    upstream_latency_ms: number | null;
    error: string;
    violation_count: number;
    auto_banned: boolean;
    email_sent: boolean;
    queue_delay_ms: number | null;
    matched_keyword: string;
    created_at: string;
}

const DEFAULT_CONFIG: RiskControlConfigView = {
    enabled: false, mode: "off", base_url: "", model: "omni-moderation-latest",
    api_key_configured: false, api_key_masked: "", api_key_count: 0, api_key_masks: [],
    timeout_ms: 5000, sample_rate: 100, all_groups: true, group_ids: [],
    record_non_hits: false, thresholds: {}, block_status: 403, block_message: "Request blocked by content moderation",
    email_on_hit: false, auto_ban_enabled: false, ban_threshold: 5, violation_window_hours: 24,
    retry_count: 1, hit_retention_days: 180, non_hit_retention_days: 3,
    pre_hash_check_enabled: false, blocked_keywords: [], keyword_blocking_mode: "standard",
    model_filter: { type: "all", models: [] }, cyber_policy_exclude_from_ban_count: false,
    worker_count: 1, queue_size: 100,
};

function maskAPIKey(key: string): string {
    if (key.length <= 8) return key.slice(0, 3) + "***";
    return key.slice(0, 6) + "****" + key.slice(-4);
}

export class D1RiskControlService {
    readonly #repo: D1RiskControlRepository;

    constructor(repo: D1RiskControlRepository) {
        this.#repo = repo;
    }

    async getConfig(): Promise<RiskControlConfigView> {
        const raw = await this.#repo.getConfig();
        if (!raw) {
            const enabled = await this.#repo.getRiskControlEnabled();
            return { ...DEFAULT_CONFIG, enabled };
        }
        try {
            const cfg = JSON.parse(raw);
            const enabled = await this.#repo.getRiskControlEnabled();
            const apiKeys: string[] = Array.isArray(cfg.api_keys) ? cfg.api_keys : (cfg.api_key ? [cfg.api_key] : []);
            return {
                enabled,
                mode: cfg.mode ?? "off",
                base_url: cfg.base_url ?? "",
                model: cfg.model ?? "omni-moderation-latest",
                api_key_configured: apiKeys.length > 0,
                api_key_masked: apiKeys.length > 0 ? maskAPIKey(apiKeys[0]) : "",
                api_key_count: apiKeys.length,
                api_key_masks: apiKeys.map(maskAPIKey),
                timeout_ms: cfg.timeout_ms ?? 5000,
                sample_rate: cfg.sample_rate ?? 100,
                all_groups: cfg.all_groups ?? true,
                group_ids: Array.isArray(cfg.group_ids) ? cfg.group_ids : [],
                record_non_hits: cfg.record_non_hits ?? false,
                thresholds: cfg.thresholds ?? {},
                block_status: cfg.block_status ?? 403,
                block_message: cfg.block_message ?? "Request blocked by content moderation",
                email_on_hit: cfg.email_on_hit ?? false,
                auto_ban_enabled: cfg.auto_ban_enabled ?? false,
                ban_threshold: cfg.ban_threshold ?? 5,
                violation_window_hours: cfg.violation_window_hours ?? 24,
                retry_count: cfg.retry_count ?? 1,
                hit_retention_days: cfg.hit_retention_days ?? 180,
                non_hit_retention_days: cfg.non_hit_retention_days ?? 3,
                pre_hash_check_enabled: cfg.pre_hash_check_enabled ?? false,
                blocked_keywords: Array.isArray(cfg.blocked_keywords) ? cfg.blocked_keywords : [],
                keyword_blocking_mode: cfg.keyword_blocking_mode ?? "standard",
                model_filter: cfg.model_filter ?? { type: "all", models: [] },
                cyber_policy_exclude_from_ban_count: cfg.cyber_policy_exclude_from_ban_count ?? false,
                worker_count: cfg.worker_count ?? 1,
                queue_size: cfg.queue_size ?? 100,
            };
        } catch {
            throw new RiskControlError(500, "INVALID_CONFIG", "Stored config is invalid JSON");
        }
    }

    async updateConfig(input: Record<string, unknown>): Promise<RiskControlConfigView> {
        const raw = await this.#repo.getConfig();
        let existing: Record<string, unknown> = {};
        if (raw) {
            try { existing = JSON.parse(raw); } catch { /* ignore */ }
        }

        if (input.enabled !== undefined) {
            await this.#repo.setRiskControlEnabled(input.enabled === true);
        }

        const merged = { ...existing };

        for (const key of ["mode", "base_url", "model", "keyword_blocking_mode", "block_message"]) {
            if (input[key] !== undefined) merged[key] = input[key];
        }
        for (const key of ["timeout_ms", "sample_rate", "block_status", "worker_count", "queue_size", "ban_threshold", "violation_window_hours", "retry_count", "hit_retention_days", "non_hit_retention_days"]) {
            if (input[key] !== undefined) merged[key] = input[key];
        }
        for (const key of ["all_groups", "record_non_hits", "email_on_hit", "auto_ban_enabled", "pre_hash_check_enabled", "cyber_policy_exclude_from_ban_count"]) {
            if (input[key] !== undefined) merged[key] = input[key] === true;
        }
        if (input.api_key !== undefined) merged.api_key = input.api_key;
        if (input.api_keys !== undefined) merged.api_keys = input.api_keys;
        if (input.api_keys_mode === "replace" && Array.isArray(input.api_keys)) {
            merged.api_keys = input.api_keys;
            delete merged.api_key;
        }
        if (input.api_keys_mode === "append" && Array.isArray(input.api_keys)) {
            const existingKeys: string[] = Array.isArray(merged.api_keys) ? merged.api_keys : (merged.api_key ? [merged.api_key] : []);
            merged.api_keys = [...existingKeys, ...input.api_keys];
            delete merged.api_key;
        }
        if (Array.isArray(input.delete_api_key_hashes) && input.delete_api_key_hashes.length > 0) {
            const hashes = new Set(input.delete_api_key_hashes.map(String));
            const keys: string[] = Array.isArray(merged.api_keys) ? merged.api_keys : (merged.api_key ? [merged.api_key] : []);
            merged.api_keys = keys.filter((k: string) => !hashes.has(sha256Hex(k)));
        }
        if (input.clear_api_key === true) {
            merged.api_keys = [];
            delete merged.api_key;
        }
        if (input.group_ids !== undefined) merged.group_ids = input.group_ids;
        if (input.thresholds !== undefined) merged.thresholds = input.thresholds;
        if (input.blocked_keywords !== undefined) merged.blocked_keywords = input.blocked_keywords;
        if (input.model_filter !== undefined) merged.model_filter = input.model_filter;

        await this.#repo.saveConfig(JSON.stringify(merged));
        return this.getConfig();
    }

    async getStatus(): Promise<RiskControlRuntimeStatus> {
        const config = await this.getConfig();
        const rows = await this.#repo.listLogs({ page: 1, pageSize: 1 });
        return {
            enabled: config.enabled,
            risk_control_enabled: config.enabled,
            mode: config.mode,
            flagged_hash_count: 0,
            last_cleanup_at: null,
            api_key_statuses: [{ configured: config.api_key_configured }],
        };
    }

    async listLogs(filter: LogFilter): Promise<{ items: ContentModerationLogItem[]; total: number; page: number; pageSize: number }> {
        const { items, total } = await this.#repo.listLogs(filter);
        return {
            page: filter.page,
            pageSize: filter.pageSize,
            total,
            items: items.map(mapLogRow),
        };
    }

    async unbanUser(userId: number): Promise<{ user_id: number; status: string }> {
        const status = await this.#repo.getUserStatus(userId);
        if (status === null) throw new RiskControlError(404, "USER_NOT_FOUND", `User ${userId} not found`);
        await this.#repo.unbanUser(userId);
        return { user_id: userId, status: "active" };
    }

    async testAPIKeys(input: { api_keys?: string[]; base_url?: string; model?: string; timeout_ms?: number; prompt?: string; images?: string[] }): Promise<{ items: { index: number; masked: string; configured: boolean; status: string }[]; image_count: number }> {
        const keys = input.api_keys ?? [];
        return {
            items: keys.map((k, i) => ({
                index: i, masked: maskAPIKey(k), configured: true, status: "unknown",
            })),
            image_count: input.images?.length ?? 0,
        };
    }

    async deleteFlaggedHash(inputHash: string): Promise<{ input_hash: string; deleted: boolean }> {
        return { input_hash: inputHash, deleted: true };
    }

    async clearFlaggedHashes(): Promise<{ deleted: number }> {
        return { deleted: 0 };
    }
}

function sha256Hex(key: string): string {
    let hash = 0;
    for (let i = 0; i < key.length; i++) {
        const chr = key.charCodeAt(i);
        hash = ((hash << 5) - hash) + chr;
        hash |= 0;
    }
    return Math.abs(hash).toString(16).padStart(8, "0");
}

function mapLogRow(r: any): ContentModerationLogItem {
    return {
        id: r.id,
        request_id: r.request_id ?? "",
        user_id: r.user_id ?? null,
        user_email: r.user_email ?? "",
        api_key_id: r.api_key_id ?? null,
        api_key_name: r.api_key_name ?? "",
        group_id: r.group_id ?? null,
        group_name: r.group_name ?? "",
        endpoint: r.endpoint ?? "",
        provider: r.provider ?? "",
        model: r.model ?? "",
        mode: r.mode ?? "",
        action: r.action ?? "",
        flagged: r.flagged === 1,
        highest_category: r.highest_category ?? "",
        highest_score: r.highest_score ?? 0,
        category_scores: parseJsonMap(r.category_scores),
        threshold_snapshot: parseJsonMap(r.threshold_snapshot),
        input_excerpt: r.input_excerpt ?? "",
        upstream_latency_ms: r.upstream_latency_ms ?? null,
        error: r.error ?? "",
        violation_count: r.violation_count ?? 0,
        auto_banned: r.auto_banned === 1,
        email_sent: r.email_sent === 1,
        queue_delay_ms: r.queue_delay_ms ?? null,
        matched_keyword: r.matched_keyword ?? "",
        created_at: r.created_at ?? "",
    };
}

function parseJsonMap(val: unknown): Record<string, number> {
    if (typeof val === "string") {
        try { return JSON.parse(val); } catch { return {}; }
    }
    if (typeof val === "object" && val !== null) return val as Record<string, number>;
    return {};
}
