import type { D1SettingsRepository } from "../repositories/settings.ts";

export class AdminSettingsFeatureError extends Error {
    readonly status: number;
    readonly code: string;

    constructor(status: number, code: string, message: string) {
        super(message);
        this.name = "AdminSettingsFeatureError";
        this.status = status;
        this.code = code;
    }
}

function clamp(value: number, min: number, max: number): number {
    return Math.min(max, Math.max(min, value));
}

function parseJsonSetting(raw: string | undefined): Record<string, unknown> {
    if (!raw) return {};
    try {
        const obj = JSON.parse(raw);
        return (obj && typeof obj === "object" && !Array.isArray(obj)) ? obj : {};
    } catch { return {}; }
}

export class D1AdminSettingsFeatureService {
    readonly #repo: D1SettingsRepository;

    constructor(repo: D1SettingsRepository) {
        this.#repo = repo;
    }

    // ===== Overload Cooldown =====

    async getOverloadCooldown(): Promise<{ enabled: boolean; cooldownMinutes: number }> {
        const raw = (await this.#repo.getMany(["overload_cooldown_settings"]))["overload_cooldown_settings"];
        const obj = parseJsonSetting(raw);
        return {
            enabled: obj.enabled === true,
            cooldownMinutes: clamp(typeof obj.cooldown_minutes === "number" ? obj.cooldown_minutes : 10, 1, 120),
        };
    }

    async setOverloadCooldown(input: { enabled: boolean; cooldownMinutes: number }): Promise<{ enabled: boolean; cooldownMinutes: number }> {
        const enabled = input.enabled;
        const cooldownMinutes = enabled ? clamp(input.cooldownMinutes ?? 10, 1, 120) : 10;
        await this.#repo.upsertMany({ overload_cooldown_settings: JSON.stringify({ enabled, cooldown_minutes: cooldownMinutes }) }, new Date().toISOString());
        return this.getOverloadCooldown();
    }

    // ===== Rate Limit 429 Cooldown =====

    async getRateLimit429Cooldown(): Promise<{ enabled: boolean; cooldownSeconds: number }> {
        const raw = (await this.#repo.getMany(["rate_limit_429_cooldown_settings"]))["rate_limit_429_cooldown_settings"];
        const obj = parseJsonSetting(raw);
        return {
            enabled: obj.enabled === true,
            cooldownSeconds: clamp(typeof obj.cooldown_seconds === "number" ? obj.cooldown_seconds : 5, 1, 7200),
        };
    }

    async setRateLimit429Cooldown(input: { enabled: boolean; cooldownSeconds: number }): Promise<{ enabled: boolean; cooldownSeconds: number }> {
        const enabled = input.enabled;
        const cooldownSeconds = enabled ? clamp(input.cooldownSeconds ?? 5, 1, 7200) : 5;
        await this.#repo.upsertMany({ rate_limit_429_cooldown_settings: JSON.stringify({ enabled, cooldown_seconds: cooldownSeconds }) }, new Date().toISOString());
        return this.getRateLimit429Cooldown();
    }

    // ===== Stream Timeout =====

    async getStreamTimeout(): Promise<{ enabled: boolean; action: string; tempUnschedMinutes: number; thresholdCount: number; thresholdWindowMinutes: number }> {
        const raw = (await this.#repo.getMany(["stream_timeout_settings"]))["stream_timeout_settings"];
        const obj = parseJsonSetting(raw);
        const validActions = ["temp_unsched", "error", "none"];
        const action = typeof obj.action === "string" && validActions.includes(obj.action) ? obj.action : "temp_unsched";
        return {
            enabled: obj.enabled === true,
            action,
            tempUnschedMinutes: clamp(typeof obj.temp_unsched_minutes === "number" ? obj.temp_unsched_minutes : 10, 1, 1440),
            thresholdCount: clamp(typeof obj.threshold_count === "number" ? obj.threshold_count : 3, 1, 100),
            thresholdWindowMinutes: clamp(typeof obj.threshold_window_minutes === "number" ? obj.threshold_window_minutes : 5, 1, 1440),
        };
    }

    async setStreamTimeout(input: { enabled: boolean; action: string; tempUnschedMinutes?: number; thresholdCount?: number; thresholdWindowMinutes?: number }): Promise<Awaited<ReturnType<D1AdminSettingsFeatureService["getStreamTimeout"]>>> {
        const validActions = ["temp_unsched", "error", "none"];
        if (!validActions.includes(input.action)) {
            throw new AdminSettingsFeatureError(400, "STREAM_TIMEOUT_INVALID_ACTION", "action must be temp_unsched, error, or none");
        }
        const settings = {
            enabled: input.enabled,
            action: input.action,
            temp_unsched_minutes: clamp(input.tempUnschedMinutes ?? 10, 1, 1440),
            threshold_count: clamp(input.thresholdCount ?? 3, 1, 100),
            threshold_window_minutes: clamp(input.thresholdWindowMinutes ?? 5, 1, 1440),
        };
        await this.#repo.upsertMany({ stream_timeout_settings: JSON.stringify(settings) }, new Date().toISOString());
        return this.getStreamTimeout();
    }

    // ===== Rectifier =====

    async getRectifier(): Promise<{ enabled: boolean; thinkingSignatureEnabled: boolean; thinkingBudgetEnabled: boolean; apikeySignatureEnabled: boolean; apikeySignaturePatterns: string[] }> {
        const raw = (await this.#repo.getMany(["rectifier_settings"]))["rectifier_settings"];
        const obj = parseJsonSetting(raw);
        return {
            enabled: obj.enabled === true,
            thinkingSignatureEnabled: obj.thinking_signature_enabled === true,
            thinkingBudgetEnabled: obj.thinking_budget_enabled === true,
            apikeySignatureEnabled: obj.apikey_signature_enabled === true,
            apikeySignaturePatterns: Array.isArray(obj.apikey_signature_patterns) ? (obj.apikey_signature_patterns as string[]).filter((s) => typeof s === "string") : [],
        };
    }

    async setRectifier(input: { enabled: boolean; thinkingSignatureEnabled: boolean; thinkingBudgetEnabled: boolean; apikeySignatureEnabled: boolean; apikeySignaturePatterns?: string[] }): Promise<Awaited<ReturnType<D1AdminSettingsFeatureService["getRectifier"]>>> {
        const patterns = (input.apikeySignaturePatterns ?? []).map((p) => p.trim()).filter((p) => p.length > 0 && p.length <= 500).slice(0, 50);
        const settings = {
            enabled: input.enabled,
            thinking_signature_enabled: input.thinkingSignatureEnabled,
            thinking_budget_enabled: input.thinkingBudgetEnabled,
            apikey_signature_enabled: input.apikeySignatureEnabled,
            apikey_signature_patterns: patterns,
        };
        await this.#repo.upsertMany({ rectifier_settings: JSON.stringify(settings) }, new Date().toISOString());
        return this.getRectifier();
    }

    // ===== Beta Policy =====

    async getBetaPolicy(): Promise<{ rules: unknown[] }> {
        const raw = (await this.#repo.getMany(["beta_policy_settings"]))["beta_policy_settings"];
        const obj = parseJsonSetting(raw);
        return { rules: Array.isArray(obj.rules) ? obj.rules : [] };
    }

    async setBetaPolicy(input: { rules: unknown[] }): Promise<{ rules: unknown[] }> {
        const rules = Array.isArray(input.rules) ? input.rules : [];
        await this.#repo.upsertMany({ beta_policy_settings: JSON.stringify({ rules }) }, new Date().toISOString());
        return this.getBetaPolicy();
    }

    // ===== Admin API Key =====

    async getAdminApiKeyStatus(): Promise<{ exists: boolean; maskedKey: string | null }> {
        const raw = (await this.#repo.getMany(["admin_api_key"]))["admin_api_key"];
        if (!raw) return { exists: false, maskedKey: null };
        if (raw.length > 14) {
            return { exists: true, maskedKey: raw.slice(0, 10) + "..." + raw.slice(-4) };
        }
        return { exists: true, maskedKey: raw };
    }

    async regenerateAdminApiKey(): Promise<{ key: string }> {
        const bytes = new Uint8Array(32);
        globalThis.crypto.getRandomValues(bytes);
        const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
        const key = "admin-" + hex;
        await this.#repo.upsertMany({ admin_api_key: key }, new Date().toISOString());
        return { key };
    }

    async deleteAdminApiKey(): Promise<void> {
        await this.#repo.delete("admin_api_key");
    }

    // ===== Web Search Emulation =====

    async getWebSearchEmulation(): Promise<{ enabled: boolean; providers: unknown[] }> {
        const raw = (await this.#repo.getMany(["web_search_emulation_config"]))["web_search_emulation_config"];
        const obj = parseJsonSetting(raw);
        const providers = Array.isArray(obj.providers) ? (obj.providers as Record<string, unknown>[]).map((p) => ({
            type: p.type ?? "",
            apiKeyConfigured: typeof p.api_key === "string" && p.api_key.length > 0,
            quotaLimit: p.quota_limit ?? null,
            proxyId: p.proxy_id ?? null,
            expiresAt: p.expires_at ?? null,
        })) : [];
        return { enabled: obj.enabled === true, providers };
    }

    async setWebSearchEmulation(input: { enabled: boolean; providers: unknown[] }): Promise<{ enabled: boolean; providers: unknown[] }> {
        const settings = { enabled: input.enabled, providers: input.providers ?? [] };
        await this.#repo.upsertMany({ web_search_emulation_config: JSON.stringify(settings) }, new Date().toISOString());
        return this.getWebSearchEmulation();
    }
}
