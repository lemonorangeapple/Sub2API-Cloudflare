import type { D1ChannelMonitorRepository, ChannelMonitorRecord, ChannelMonitorHistoryRecord, CreateMonitorInput, UpdateMonitorInput, ListMonitorsOptions } from "../repositories/channel-monitors.ts";

export class ChannelMonitorError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "ChannelMonitorError";
        this.code = code;
        this.status = status;
    }
}

const VALID_PROVIDERS = ["openai", "anthropic", "gemini", "grok"];
const VALID_API_MODES = ["chat_completions", "responses"];
const VALID_BODY_OVERRIDE_MODES = ["off", "merge", "replace"];
const MASK_PREFIX_LEN = 4;

function maskApiKey(key: string): string {
    if (key.length <= MASK_PREFIX_LEN) return "***";
    return key.slice(0, MASK_PREFIX_LEN) + "***";
}

function normalizeCreateInput(input: {
    name: string; provider: string; apiMode?: string; endpoint: string; apiKey: string;
    primaryModel?: string; extraModels?: string[]; groupName?: string; enabled?: boolean;
    intervalSeconds: number; jitterSeconds?: number; templateId?: number | null;
    extraHeaders?: Record<string, string>; bodyOverrideMode?: string; bodyOverride?: Record<string, unknown> | null;
    createdBy: number;
}): CreateMonitorInput {
    const provider = input.provider.trim().toLowerCase();
    if (!VALID_PROVIDERS.includes(provider)) {
        throw new ChannelMonitorError("CHANNEL_MONITOR_INVALID_PROVIDER", 400, `provider must be one of ${VALID_PROVIDERS.join(", ")}`);
    }

    const apiMode = (input.apiMode ?? "chat_completions").trim();
    if (!VALID_API_MODES.includes(apiMode)) {
        throw new ChannelMonitorError("CHANNEL_MONITOR_INVALID_API_MODE", 400, "api_mode must be chat_completions or responses");
    }
    if (apiMode === "responses" && provider !== "openai") {
        throw new ChannelMonitorError("CHANNEL_MONITOR_INVALID_API_MODE", 400, "responses mode is only supported for openai");
    }

    const intervalSeconds = input.intervalSeconds;
    if (!Number.isInteger(intervalSeconds) || intervalSeconds < 15 || intervalSeconds > 3600) {
        throw new ChannelMonitorError("CHANNEL_MONITOR_INVALID_INTERVAL", 400, "interval_seconds must be in [15, 3600]");
    }

    const jitterSeconds = input.jitterSeconds ?? 0;
    if (jitterSeconds < 0 || intervalSeconds - jitterSeconds < 15) {
        throw new ChannelMonitorError("CHANNEL_MONITOR_INVALID_JITTER", 400, "jitter_seconds must be >= 0 and interval - jitter >= 15");
    }

    if (!input.apiKey || input.apiKey.trim().length === 0) {
        throw new ChannelMonitorError("CHANNEL_MONITOR_MISSING_API_KEY", 400, "api_key is required");
    }

    let primaryModel = (input.primaryModel ?? "").trim();
    if (!primaryModel) {
        if (provider === "grok") {
            primaryModel = "grok-4.5";
        } else {
            throw new ChannelMonitorError("CHANNEL_MONITOR_MISSING_PRIMARY_MODEL", 400, "primary_model is required");
        }
    }

    const bodyOverrideMode = (input.bodyOverrideMode ?? "off").trim();
    if (!VALID_BODY_OVERRIDE_MODES.includes(bodyOverrideMode)) {
        throw new ChannelMonitorError("CHANNEL_MONITOR_INVALID_BODY_OVERRIDE_MODE", 400, "body_override_mode must be off, merge, or replace");
    }
    if ((bodyOverrideMode === "merge" || bodyOverrideMode === "replace") && (!input.bodyOverride || Object.keys(input.bodyOverride).length === 0)) {
        throw new ChannelMonitorError("CHANNEL_MONITOR_INVALID_REQUEST_BODY", 400, "body_override is required when mode is merge or replace");
    }

    const extraModels = (input.extraModels ?? []).map((m) => m.trim()).filter((m) => m.length > 0);
    const uniqueExtra = [...new Set(extraModels)];
    const groupName = (input.groupName ?? "").trim();

    return {
        name: input.name.trim(),
        provider,
        apiMode,
        endpoint: input.endpoint.trim().replace(/\/+$/, ""),
        apiKeyEncrypted: input.apiKey,
        primaryModel,
        extraModels: uniqueExtra,
        groupName,
        enabled: input.enabled ?? true,
        intervalSeconds,
        jitterSeconds,
        createdBy: input.createdBy,
        extraHeaders: input.extraHeaders ?? {},
        bodyOverrideMode,
        bodyOverride: input.bodyOverride ?? null,
        templateId: input.templateId ?? null,
    };
}

export interface ChannelMonitorResponse extends ChannelMonitorRecord {
    apiKeyMasked: string;
    primaryStatus: string;
    primaryLatencyMs: number | null;
}

function toResponse(record: ChannelMonitorRecord): ChannelMonitorResponse {
    return {
        ...record,
        apiKeyMasked: "***",
        primaryStatus: "",
        primaryLatencyMs: null,
    };
}

export class D1ChannelMonitorService {
    readonly #repo: D1ChannelMonitorRepository;

    constructor(repo: D1ChannelMonitorRepository) {
        this.#repo = repo;
    }

    async list(opts: ListMonitorsOptions): Promise<{ items: ChannelMonitorResponse[]; total: number }> {
        const result = await this.#repo.list(opts);
        return {
            items: result.items.map(toResponse),
            total: result.total,
        };
    }

    async getById(id: number): Promise<ChannelMonitorResponse> {
        const monitor = await this.#repo.findById(id);
        if (monitor === null) throw new ChannelMonitorError("CHANNEL_MONITOR_NOT_FOUND", 404, "Channel monitor not found");
        return toResponse(monitor);
    }

    async create(input: {
        name: string; provider: string; apiMode?: string; endpoint: string; apiKey: string;
        primaryModel?: string; extraModels?: string[]; groupName?: string; enabled?: boolean;
        intervalSeconds: number; jitterSeconds?: number; templateId?: number | null;
        extraHeaders?: Record<string, string>; bodyOverrideMode?: string; bodyOverride?: Record<string, unknown> | null;
        createdBy: number;
    }): Promise<ChannelMonitorResponse> {
        const normalized = normalizeCreateInput(input);
        const created = await this.#repo.create(normalized);
        return toResponse(created);
    }

    async update(id: number, input: {
        name?: string; provider?: string; apiMode?: string; endpoint?: string; apiKey?: string;
        primaryModel?: string; extraModels?: string[]; groupName?: string; enabled?: boolean;
        intervalSeconds?: number; jitterSeconds?: number; templateId?: number | null;
        clearTemplate?: boolean; extraHeaders?: Record<string, string>;
        bodyOverrideMode?: string; bodyOverride?: Record<string, unknown> | null;
    }): Promise<ChannelMonitorResponse> {
        const existing = await this.#repo.findById(id);
        if (existing === null) throw new ChannelMonitorError("CHANNEL_MONITOR_NOT_FOUND", 404, "Channel monitor not found");

        if (input.provider !== undefined) {
            const p = input.provider.trim().toLowerCase();
            if (!VALID_PROVIDERS.includes(p)) {
                throw new ChannelMonitorError("CHANNEL_MONITOR_INVALID_PROVIDER", 400, `provider must be one of ${VALID_PROVIDERS.join(", ")}`);
            }
        }

        if (input.apiMode !== undefined) {
            const mode = input.apiMode.trim();
            if (!VALID_API_MODES.includes(mode)) {
                throw new ChannelMonitorError("CHANNEL_MONITOR_INVALID_API_MODE", 400, "api_mode must be chat_completions or responses");
            }
            const provider = (input.provider ?? existing.provider).trim().toLowerCase();
            if (mode === "responses" && provider !== "openai") {
                throw new ChannelMonitorError("CHANNEL_MONITOR_INVALID_API_MODE", 400, "responses mode is only supported for openai");
            }
        }

        if (input.intervalSeconds !== undefined) {
            const interval = input.intervalSeconds;
            if (!Number.isInteger(interval) || interval < 15 || interval > 3600) {
                throw new ChannelMonitorError("CHANNEL_MONITOR_INVALID_INTERVAL", 400, "interval_seconds must be in [15, 3600]");
            }
            const jitter = input.jitterSeconds ?? existing.jitterSeconds;
            if (jitter < 0 || interval - jitter < 15) {
                throw new ChannelMonitorError("CHANNEL_MONITOR_INVALID_JITTER", 400, "jitter_seconds must be >= 0 and interval - jitter >= 15");
            }
        }

        if (input.jitterSeconds !== undefined && input.intervalSeconds === undefined) {
            const interval = existing.intervalSeconds;
            const jitter = input.jitterSeconds;
            if (jitter < 0 || interval - jitter < 15) {
                throw new ChannelMonitorError("CHANNEL_MONITOR_INVALID_JITTER", 400, "jitter_seconds must be >= 0 and interval - jitter >= 15");
            }
        }

        const updateInput: UpdateMonitorInput = {};
        if (input.name !== undefined) updateInput.name = input.name.trim();
        if (input.provider !== undefined) updateInput.provider = input.provider.trim().toLowerCase();
        if (input.apiMode !== undefined) updateInput.apiMode = input.apiMode.trim();
        if (input.endpoint !== undefined) updateInput.endpoint = input.endpoint.trim().replace(/\/+$/, "");
        if (input.apiKey !== undefined && input.apiKey.trim().length > 0) updateInput.apiKeyEncrypted = input.apiKey;
        if (input.primaryModel !== undefined) updateInput.primaryModel = input.primaryModel.trim();
        if (input.extraModels !== undefined) updateInput.extraModels = [...new Set(input.extraModels.map((m) => m.trim()).filter((m) => m.length > 0))];
        if (input.groupName !== undefined) updateInput.groupName = input.groupName.trim();
        if (input.enabled !== undefined) updateInput.enabled = input.enabled;
        if (input.intervalSeconds !== undefined) updateInput.intervalSeconds = input.intervalSeconds;
        if (input.jitterSeconds !== undefined) updateInput.jitterSeconds = input.jitterSeconds;
        if (input.extraHeaders !== undefined) updateInput.extraHeaders = input.extraHeaders;
        if (input.bodyOverrideMode !== undefined) updateInput.bodyOverrideMode = input.bodyOverrideMode;
        if (input.bodyOverride !== undefined) updateInput.bodyOverride = input.bodyOverride;
        if (input.clearTemplate) {
            updateInput.templateId = null;
        } else if (input.templateId !== undefined) {
            updateInput.templateId = input.templateId;
        }

        const updated = await this.#repo.update(id, updateInput);
        return toResponse(updated!);
    }

    async delete(id: number): Promise<void> {
        const deleted = await this.#repo.delete(id);
        if (!deleted) throw new ChannelMonitorError("CHANNEL_MONITOR_NOT_FOUND", 404, "Channel monitor not found");
    }

    async listHistory(monitorId: number, limit: number, model?: string): Promise<{ items: ChannelMonitorHistoryRecord[] }> {
        await this.getById(monitorId);
        return { items: await this.#repo.listHistory(monitorId, limit, model) };
    }
}
