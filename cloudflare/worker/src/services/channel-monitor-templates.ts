import type {
    D1ChannelMonitorTemplateRepository,
    ChannelMonitorTemplateRecord,
    TemplateMonitorSummary,
    CreateTemplateInput,
    UpdateTemplateInput,
} from "../repositories/channel-monitor-templates.ts";

const VALID_PROVIDERS = ["openai", "anthropic", "gemini", "grok"];
const VALID_API_MODES = ["chat_completions", "responses"];
const VALID_BODY_OVERRIDE_MODES = ["off", "merge", "replace"];
const FORBIDDEN_HEADERS = ["host", "content-length", "content-encoding", "transfer-encoding", "connection"];
const HEADER_NAME_REGEX = /^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/;

export class ChannelMonitorTemplateError extends Error {
    readonly status: number;
    readonly code: string;

    constructor(status: number, code: string, message: string) {
        super(message);
        this.name = "ChannelMonitorTemplateError";
        this.status = status;
        this.code = code;
    }
}

function validateProvider(provider: string): void {
    if (!VALID_PROVIDERS.includes(provider)) {
        throw new ChannelMonitorTemplateError(400, "CHANNEL_MONITOR_TEMPLATE_INVALID_PROVIDER", "template provider must be one of openai/anthropic/gemini/grok");
    }
}

function validateApiMode(apiMode: string, provider: string): void {
    if (!VALID_API_MODES.includes(apiMode)) {
        throw new ChannelMonitorTemplateError(400, "CHANNEL_MONITOR_TEMPLATE_INVALID_API_MODE", "template api_mode must be chat_completions or responses; responses is only supported for openai");
    }
    if (apiMode === "responses" && provider !== "openai") {
        throw new ChannelMonitorTemplateError(400, "CHANNEL_MONITOR_TEMPLATE_INVALID_API_MODE", "template api_mode must be chat_completions or responses; responses is only supported for openai");
    }
}

function validateHeaders(headers: Record<string, string>): void {
    for (const key of Object.keys(headers)) {
        if (FORBIDDEN_HEADERS.includes(key.toLowerCase())) {
            throw new ChannelMonitorTemplateError(400, "CHANNEL_MONITOR_TEMPLATE_HEADER_FORBIDDEN", `header name is forbidden (hop-by-hop or computed by HTTP client): ${key}`);
        }
        if (!HEADER_NAME_REGEX.test(key)) {
            throw new ChannelMonitorTemplateError(400, "CHANNEL_MONITOR_TEMPLATE_HEADER_INVALID_NAME", `header name contains invalid characters: ${key}`);
        }
    }
}

function validateBodyOverride(bodyOverrideMode: string, bodyOverride: Record<string, unknown> | null, provider: string, apiMode: string): void {
    if (!VALID_BODY_OVERRIDE_MODES.includes(bodyOverrideMode)) {
        throw new ChannelMonitorTemplateError(400, "CHANNEL_MONITOR_TEMPLATE_INVALID_BODY_MODE", "body_override_mode must be one of off/merge/replace");
    }
    if (bodyOverrideMode === "merge" || bodyOverrideMode === "replace") {
        if (!bodyOverride || typeof bodyOverride !== "object") {
            throw new ChannelMonitorTemplateError(400, "CHANNEL_MONITOR_TEMPLATE_BODY_REQUIRED", "body_override is required when body_override_mode is merge or replace");
        }
    }
}

export class D1ChannelMonitorTemplateService {
    readonly #repo: D1ChannelMonitorTemplateRepository;

    constructor(repo: D1ChannelMonitorTemplateRepository) {
        this.#repo = repo;
    }

    async list(filters?: { provider?: string; apiMode?: string }): Promise<ChannelMonitorTemplateRecord[]> {
        return this.#repo.list(filters);
    }

    async getById(id: number): Promise<ChannelMonitorTemplateRecord> {
        const template = await this.#repo.findById(id);
        if (template === null) {
            throw new ChannelMonitorTemplateError(404, "CHANNEL_MONITOR_TEMPLATE_NOT_FOUND", "channel monitor request template not found");
        }
        return template;
    }

    async create(input: CreateTemplateInput): Promise<ChannelMonitorTemplateRecord> {
        if (!input.name || !input.name.trim()) {
            throw new ChannelMonitorTemplateError(400, "CHANNEL_MONITOR_TEMPLATE_MISSING_NAME", "template name is required");
        }
        validateProvider(input.provider);
        const apiMode = input.apiMode ?? "chat_completions";
        const bodyOverrideMode = input.bodyOverrideMode ?? "off";
        validateApiMode(apiMode, input.provider);
        validateBodyOverride(bodyOverrideMode, input.bodyOverride ?? null, input.provider, apiMode);
        if (input.extraHeaders) validateHeaders(input.extraHeaders);

        const existing = await this.#repo.findByNameAndProvider(input.name.trim(), input.provider);
        if (existing !== null) {
            throw new ChannelMonitorTemplateError(409, "CHANNEL_MONITOR_TEMPLATE_DUPLICATE_NAME", "a template with this name already exists for this provider");
        }

        return this.#repo.create({
            ...input,
            name: input.name.trim(),
            apiMode,
            bodyOverrideMode,
            description: input.description?.trim() ?? "",
            extraHeaders: input.extraHeaders ?? {},
        });
    }

    async update(id: number, input: UpdateTemplateInput): Promise<ChannelMonitorTemplateRecord> {
        const existing = await this.getById(id);
        if (input.name !== undefined && !input.name.trim()) {
            throw new ChannelMonitorTemplateError(400, "CHANNEL_MONITOR_TEMPLATE_MISSING_NAME", "template name is required");
        }
        const provider = existing.provider;
        const apiMode = input.apiMode ?? existing.apiMode;
        const bodyOverrideMode = input.bodyOverrideMode ?? existing.bodyOverrideMode;
        const bodyOverride = input.bodyOverride !== undefined ? input.bodyOverride : existing.bodyOverride;
        validateApiMode(apiMode, provider);
        validateBodyOverride(bodyOverrideMode, bodyOverride, provider, apiMode);
        if (input.extraHeaders) validateHeaders(input.extraHeaders);

        return (await this.#repo.update(id, {
            ...input,
            name: input.name?.trim(),
            apiMode,
            bodyOverrideMode,
            bodyOverride,
            description: input.description?.trim(),
            extraHeaders: input.extraHeaders,
        }))!;
    }

    async delete(id: number): Promise<void> {
        const template = await this.getById(id);
        await this.#repo.delete(template.id);
    }

    async listAssociatedMonitors(id: number): Promise<TemplateMonitorSummary[]> {
        const template = await this.getById(id);
        return this.#repo.listAssociatedMonitors(template.id);
    }

    async applyToMonitors(id: number, monitorIds: number[]): Promise<number> {
        if (!monitorIds.length) {
            throw new ChannelMonitorTemplateError(400, "CHANNEL_MONITOR_TEMPLATE_APPLY_EMPTY", "monitor_ids must be a non-empty array");
        }
        const template = await this.getById(id);
        return this.#repo.applyToMonitors(template.id, monitorIds, {
            apiMode: template.apiMode,
            extraHeaders: template.extraHeaders,
            bodyOverrideMode: template.bodyOverrideMode,
            bodyOverride: template.bodyOverride,
        });
    }
}
