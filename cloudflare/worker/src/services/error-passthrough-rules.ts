import type { D1ErrorPassthroughRuleRepository, ErrorPassthroughRuleRecord, CreateRuleInput, UpdateRuleInput } from "../repositories/error-passthrough-rules.ts";

export class RuleError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "RuleError";
        this.code = code;
        this.status = status;
    }
}

function validateRule(input: { name?: string; matchMode?: string; errorCodes?: number[]; keywords?: string[]; passthroughCode?: boolean; responseCode?: number | null; passthroughBody?: boolean; customMessage?: string | null }): void {
    if (input.name !== undefined && input.name.trim().length === 0) {
        throw new RuleError("name_required", 400, "name is required");
    }
    if (input.matchMode !== undefined && input.matchMode !== "any" && input.matchMode !== "all") {
        throw new RuleError("match_mode_invalid", 400, "match_mode must be 'any' or 'all'");
    }
    if (input.errorCodes !== undefined && input.keywords !== undefined) {
        if (input.errorCodes.length === 0 && input.keywords.length === 0) {
            throw new RuleError("conditions_required", 400, "at least one error_code or keyword is required");
        }
    }
    if (input.passthroughCode === false) {
        if (input.responseCode === undefined || input.responseCode === null || input.responseCode <= 0) {
            throw new RuleError("response_code_required", 400, "response_code is required when passthrough_code is false");
        }
    }
    if (input.passthroughBody === false) {
        if (input.customMessage === undefined || input.customMessage === null || input.customMessage.trim().length === 0) {
            throw new RuleError("custom_message_required", 400, "custom_message is required when passthrough_body is false");
        }
    }
}

export class D1ErrorPassthroughRuleService {
    readonly #repo: D1ErrorPassthroughRuleRepository;

    constructor(repo: D1ErrorPassthroughRuleRepository) {
        this.#repo = repo;
    }

    async list(): Promise<ErrorPassthroughRuleRecord[]> {
        return this.#repo.list();
    }

    async getById(id: number): Promise<ErrorPassthroughRuleRecord> {
        const rule = await this.#repo.findById(id);
        if (rule === null) throw new RuleError("rule_not_found", 404, "Rule not found");
        return rule;
    }

    async create(input: CreateRuleInput): Promise<ErrorPassthroughRuleRecord> {
        validateRule(input);
        return this.#repo.create(input);
    }

    async update(id: number, input: UpdateRuleInput): Promise<ErrorPassthroughRuleRecord> {
        const existing = await this.#repo.findById(id);
        if (existing === null) throw new RuleError("rule_not_found", 404, "Rule not found");

        const merged = {
            name: input.name ?? existing.name,
            enabled: input.enabled ?? existing.enabled,
            priority: input.priority ?? existing.priority,
            errorCodes: input.errorCodes ?? existing.errorCodes,
            keywords: input.keywords ?? existing.keywords,
            matchMode: input.matchMode ?? existing.matchMode,
            platforms: input.platforms ?? existing.platforms,
            passthroughCode: input.passthroughCode ?? existing.passthroughCode,
            responseCode: input.responseCode !== undefined ? input.responseCode : existing.responseCode,
            passthroughBody: input.passthroughBody ?? existing.passthroughBody,
            customMessage: input.customMessage !== undefined ? input.customMessage : existing.customMessage,
            skipMonitoring: input.skipMonitoring ?? existing.skipMonitoring,
            description: input.description !== undefined ? input.description : existing.description,
        };
        validateRule(merged);

        const updated = await this.#repo.update(id, input);
        return updated!;
    }

    async delete(id: number): Promise<void> {
        const deleted = await this.#repo.delete(id);
        if (!deleted) throw new RuleError("rule_not_found", 404, "Rule not found");
    }
}
