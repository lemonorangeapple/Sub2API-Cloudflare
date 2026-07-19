import type { D1ApiKeyRepository, ApiKeyRecord, CreateApiKeyInput, UpdateApiKeyInput, ListApiKeysOptions } from "../repositories/api-keys.ts";

export class ApiKeyError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "ApiKeyError";
        this.code = code;
        this.status = status;
    }
}

const STATUS_ACTIVE = "active";
const STATUS_DISABLED = "disabled";
const STATUS_QUOTA_EXHAUSTED = "quota_exhausted";
const STATUS_EXPIRED = "expired";

const VALID_STATUSES = new Set([STATUS_ACTIVE, STATUS_DISABLED]);
const KEY_PATTERN = /^[a-zA-Z0-9_-]+$/u;
const MIN_KEY_LENGTH = 16;
const MAX_KEY_LENGTH = 128;
const MAX_NAME_LENGTH = 100;

function generateRandomKey(prefix: string): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const hex = [...array].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    return `${prefix}${hex}`;
}

function validateIpPattern(pattern: string): boolean {
    const trimmed = pattern.trim();
    if (trimmed === "") return false;
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$/u.test(trimmed)) return true;
    if (/^[a-f0-9:]+\/\d{1,3}$/u.test(trimmed)) return true;
    if (/^\*\.\w+$/u.test(trimmed)) return true;
    return false;
}

export class D1ApiKeyService {
    readonly #repository: D1ApiKeyRepository;

    constructor(repository: D1ApiKeyRepository) {
        this.#repository = repository;
    }

    async listKeys(options: ListApiKeysOptions): Promise<{ items: ApiKeyRecord[]; total: number }> {
        return this.#repository.list(options);
    }

    async getKeyById(id: number, userId: number): Promise<ApiKeyRecord> {
        const key = await this.#repository.findById(id, userId);
        if (key === null) {
            throw new ApiKeyError("key_not_found", 404, "API key not found");
        }
        return key;
    }

    async createKey(
        userId: number,
        input: {
            name?: string;
            key?: string;
            group_id?: number | null;
            ip_whitelist?: string[];
            ip_blacklist?: string[];
            quota?: number;
            expires_at?: string | null;
            rate_limit_5h?: number;
            rate_limit_1d?: number;
            rate_limit_7d?: number;
        }
    ): Promise<ApiKeyRecord> {
        const name = (input.name ?? "").trim();
        if (name.length === 0) {
            throw new ApiKeyError("name_required", 400, "API key name is required");
        }
        if (name.length > MAX_NAME_LENGTH) {
            throw new ApiKeyError("name_too_long", 400, `API key name must be at most ${MAX_NAME_LENGTH} characters`);
        }

        let keyValue: string;
        if (input.key !== undefined && input.key.trim() !== "") {
            keyValue = input.key.trim();
            if (keyValue.length < MIN_KEY_LENGTH) {
                throw new ApiKeyError("key_too_short", 400, `Custom key must be at least ${MIN_KEY_LENGTH} characters`);
            }
            if (keyValue.length > MAX_KEY_LENGTH) {
                throw new ApiKeyError("key_too_long", 400, `Custom key must be at most ${MAX_KEY_LENGTH} characters`);
            }
            if (!KEY_PATTERN.test(keyValue)) {
                throw new ApiKeyError("key_invalid_chars", 400, "Custom key may only contain alphanumeric characters, underscores, and hyphens");
            }
            const existing = await this.#repository.findByKey(keyValue);
            if (existing !== null) {
                throw new ApiKeyError("key_already_exists", 409, "This key already exists");
            }
        } else {
            let attempts = 0;
            do {
                keyValue = generateRandomKey("sk-");
                attempts++;
            } while (
                (await this.#repository.findByKey(keyValue)) !== null
                && attempts < 10
            );
            if (attempts >= 10) {
                throw new ApiKeyError("key_generation_failed", 500, "Failed to generate a unique key");
            }
        }

        if (input.ip_whitelist !== undefined) {
            for (const pattern of input.ip_whitelist) {
                if (!validateIpPattern(pattern)) {
                    throw new ApiKeyError("invalid_ip_pattern", 400, `Invalid IP pattern: ${pattern}`);
                }
            }
        }

        if (input.ip_blacklist !== undefined) {
            for (const pattern of input.ip_blacklist) {
                if (!validateIpPattern(pattern)) {
                    throw new ApiKeyError("invalid_ip_pattern", 400, `Invalid IP pattern: ${pattern}`);
                }
            }
        }

        const createInput: CreateApiKeyInput = {
            key: keyValue,
            name,
            userId,
            groupId: input.group_id ?? null,
            ipWhitelist: input.ip_whitelist ?? [],
            ipBlacklist: input.ip_blacklist ?? [],
            quota: input.quota ?? 0,
            expiresAt: input.expires_at ?? null,
            rateLimit5h: input.rate_limit_5h ?? 0,
            rateLimit1d: input.rate_limit_1d ?? 0,
            rateLimit7d: input.rate_limit_7d ?? 0
        };

        return this.#repository.create(createInput);
    }

    async updateKey(
        id: number,
        userId: number,
        input: {
            name?: string;
            group_id?: number | null;
            status?: string;
            ip_whitelist?: string[];
            ip_blacklist?: string[];
            quota?: number;
            expires_at?: string | null;
            rate_limit_5h?: number;
            rate_limit_1d?: number;
            rate_limit_7d?: number;
            reset_quota?: boolean;
            reset_rate_limits?: boolean;
        }
    ): Promise<ApiKeyRecord> {
        if (input.name !== undefined) {
            const name = input.name.trim();
            if (name.length === 0) {
                throw new ApiKeyError("name_required", 400, "API key name is required");
            }
            if (name.length > MAX_NAME_LENGTH) {
                throw new ApiKeyError("name_too_long", 400, `API key name must be at most ${MAX_NAME_LENGTH} characters`);
            }
        }

        if (input.status !== undefined && !VALID_STATUSES.has(input.status)) {
            throw new ApiKeyError("invalid_status", 400, `Status must be one of: ${[...VALID_STATUSES].join(", ")}`);
        }

        if (input.ip_whitelist !== undefined) {
            for (const pattern of input.ip_whitelist) {
                if (!validateIpPattern(pattern)) {
                    throw new ApiKeyError("invalid_ip_pattern", 400, `Invalid IP pattern: ${pattern}`);
                }
            }
        }

        if (input.ip_blacklist !== undefined) {
            for (const pattern of input.ip_blacklist) {
                if (!validateIpPattern(pattern)) {
                    throw new ApiKeyError("invalid_ip_pattern", 400, `Invalid IP pattern: ${pattern}`);
                }
            }
        }

        const updateInput: UpdateApiKeyInput = {
            name: input.name?.trim(),
            groupId: input.group_id,
            status: input.status,
            ipWhitelist: input.ip_whitelist,
            ipBlacklist: input.ip_blacklist,
            quota: input.quota,
            expiresAt: input.expires_at,
            rateLimit5h: input.rate_limit_5h,
            rateLimit1d: input.rate_limit_1d,
            rateLimit7d: input.rate_limit_7d,
            resetQuota: input.reset_quota ?? false,
            resetRateLimits: input.reset_rate_limits ?? false
        };

        const updated = await this.#repository.update(id, userId, updateInput);
        if (updated === null) {
            throw new ApiKeyError("key_not_found", 404, "API key not found");
        }
        return updated;
    }

    async deleteKey(id: number, userId: number): Promise<void> {
        const deleted = await this.#repository.deleteWithAudit(id, userId);
        if (!deleted) {
            throw new ApiKeyError("key_not_found", 404, "API key not found");
        }
    }

    async searchKeys(userId: number, query: string): Promise<{ id: number; name: string; userId: number }[]> {
        return this.#repository.searchByUserId(userId, query);
    }

    async getKeyForAuth(keyValue: string): Promise<ApiKeyRecord> {
        const key = await this.#repository.findByKey(keyValue);
        if (key === null) {
            throw new ApiKeyError("invalid_key", 401, "Invalid API key");
        }
        if (key.deletedAt !== null) {
            throw new ApiKeyError("key_deleted", 401, "API key has been deleted");
        }
        if (key.status === STATUS_DISABLED) {
            throw new ApiKeyError("key_disabled", 401, "API key is disabled");
        }
        if (key.status === STATUS_QUOTA_EXHAUSTED) {
            throw new ApiKeyError("key_quota_exhausted", 402, "API key quota has been exhausted");
        }
        if (key.status === STATUS_EXPIRED) {
            throw new ApiKeyError("key_expired", 402, "API key has expired");
        }
        if (key.expiresAt !== null) {
            const expiresAt = new Date(key.expiresAt).getTime();
            if (expiresAt <= Date.now()) {
                throw new ApiKeyError("key_expired", 402, "API key has expired");
            }
        }
        return key;
    }
}
