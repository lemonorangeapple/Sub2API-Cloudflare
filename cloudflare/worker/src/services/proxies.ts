import type { D1ProxyRepository, ProxyRecord, CreateProxyInput, UpdateProxyInput, ListProxiesOptions, BatchDeleteResult } from "../repositories/proxies.ts";

export class ProxyError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "ProxyError";
        this.code = code;
        this.status = status;
    }
}

const VALID_PROTOCOLS = new Set(["http", "https", "socks5", "socks5h"]);
const VALID_STATUSES = new Set(["active", "inactive"]);
const VALID_FALLBACK_MODES = new Set(["none", "proxy", "direct"]);
const MAX_NAME_LENGTH = 200;

export class D1ProxyService {
    readonly #repository: D1ProxyRepository;

    constructor(repository: D1ProxyRepository) {
        this.#repository = repository;
    }

    async listProxies(options: ListProxiesOptions): Promise<{ items: ProxyRecord[]; total: number }> {
        return this.#repository.list(options);
    }

    async listAll(): Promise<ProxyRecord[]> {
        return this.#repository.listAll();
    }

    async getProxyById(id: number): Promise<ProxyRecord> {
        const proxy = await this.#repository.findById(id);
        if (proxy === null) {
            throw new ProxyError("proxy_not_found", 404, "Proxy not found");
        }
        return proxy;
    }

    async createProxy(input: {
        name: string;
        protocol: string;
        host: string;
        port: number;
        username?: string;
        password?: string;
        expires_at?: string | null;
        fallback_mode?: string;
        backup_proxy_id?: number | null;
        expiry_warn_days?: number;
    }): Promise<ProxyRecord> {
        const name = input.name.trim();
        if (name.length === 0) {
            throw new ProxyError("name_required", 400, "Proxy name is required");
        }
        if (name.length > MAX_NAME_LENGTH) {
            throw new ProxyError("name_too_long", 400, `Proxy name must be at most ${MAX_NAME_LENGTH} characters`);
        }

        const protocol = input.protocol.trim();
        if (!VALID_PROTOCOLS.has(protocol)) {
            throw new ProxyError("invalid_protocol", 400, `Protocol must be one of: ${[...VALID_PROTOCOLS].join(", ")}`);
        }

        const host = input.host.trim();
        if (host.length === 0) {
            throw new ProxyError("host_required", 400, "Proxy host is required");
        }

        const port = input.port;
        if (!Number.isFinite(port) || port < 1 || port > 65535) {
            throw new ProxyError("invalid_port", 400, "Port must be between 1 and 65535");
        }

        const fallbackMode = input.fallback_mode?.trim() || "none";
        if (!VALID_FALLBACK_MODES.has(fallbackMode)) {
            throw new ProxyError("invalid_fallback_mode", 400, `Fallback mode must be one of: ${[...VALID_FALLBACK_MODES].join(", ")}`);
        }

        if (fallbackMode === "proxy" && (input.backup_proxy_id === undefined || input.backup_proxy_id === null)) {
            throw new ProxyError("backup_proxy_required", 400, "Backup proxy is required when fallback mode is 'proxy'");
        }

        if (input.backup_proxy_id !== undefined && input.backup_proxy_id !== null) {
            const backup = await this.#repository.findById(input.backup_proxy_id);
            if (backup === null) {
                throw new ProxyError("backup_proxy_not_found", 400, "Backup proxy not found");
            }
        }

        const createInput: CreateProxyInput = {
            name,
            protocol,
            host,
            port,
            username: input.username?.trim(),
            password: input.password,
            expiresAt: input.expires_at ?? null,
            fallbackMode,
            backupProxyId: input.backup_proxy_id ?? null,
            expiryWarnDays: input.expiry_warn_days ?? 7
        };

        return this.#repository.create(createInput);
    }

    async updateProxy(id: number, input: {
        name?: string;
        protocol?: string;
        host?: string;
        port?: number;
        username?: string;
        password?: string;
        status?: string;
        expires_at?: string | null;
        fallback_mode?: string;
        backup_proxy_id?: number | null;
        expiry_warn_days?: number;
    }): Promise<ProxyRecord> {
        if (input.name !== undefined) {
            const name = input.name.trim();
            if (name.length === 0) {
                throw new ProxyError("name_required", 400, "Proxy name is required");
            }
            if (name.length > MAX_NAME_LENGTH) {
                throw new ProxyError("name_too_long", 400, `Proxy name must be at most ${MAX_NAME_LENGTH} characters`);
            }
        }

        if (input.protocol !== undefined) {
            const protocol = input.protocol.trim();
            if (!VALID_PROTOCOLS.has(protocol)) {
                throw new ProxyError("invalid_protocol", 400, `Protocol must be one of: ${[...VALID_PROTOCOLS].join(", ")}`);
            }
        }

        if (input.host !== undefined && input.host.trim().length === 0) {
            throw new ProxyError("host_required", 400, "Proxy host is required");
        }

        if (input.port !== undefined) {
            if (!Number.isFinite(input.port) || input.port < 1 || input.port > 65535) {
                throw new ProxyError("invalid_port", 400, "Port must be between 1 and 65535");
            }
        }

        if (input.status !== undefined && !VALID_STATUSES.has(input.status)) {
            throw new ProxyError("invalid_status", 400, `Status must be one of: ${[...VALID_STATUSES].join(", ")}`);
        }

        if (input.fallback_mode !== undefined) {
            const fm = input.fallback_mode.trim();
            if (!VALID_FALLBACK_MODES.has(fm)) {
                throw new ProxyError("invalid_fallback_mode", 400, `Fallback mode must be one of: ${[...VALID_FALLBACK_MODES].join(", ")}`);
            }
        }

        if (input.backup_proxy_id !== undefined && input.backup_proxy_id !== null) {
            if (input.backup_proxy_id === id) {
                throw new ProxyError("backup_proxy_self_reference", 400, "Backup proxy cannot be the same as the proxy itself");
            }
            const backup = await this.#repository.findById(input.backup_proxy_id);
            if (backup === null) {
                throw new ProxyError("backup_proxy_not_found", 400, "Backup proxy not found");
            }
        }

        const updateInput: UpdateProxyInput = {
            name: input.name?.trim(),
            protocol: input.protocol?.trim(),
            host: input.host?.trim(),
            port: input.port,
            username: input.username,
            password: input.password,
            status: input.status,
            expiresAt: input.expires_at,
            fallbackMode: input.fallback_mode,
            backupProxyId: input.backup_proxy_id,
            expiryWarnDays: input.expiry_warn_days
        };

        const updated = await this.#repository.update(id, updateInput);
        if (updated === null) {
            throw new ProxyError("proxy_not_found", 404, "Proxy not found");
        }
        return updated;
    }

    async deleteProxy(id: number): Promise<void> {
        const deleted = await this.#repository.delete(id);
        if (!deleted) {
            throw new ProxyError("proxy_not_found", 404, "Proxy not found");
        }
    }

    async batchDeleteProxies(ids: number[]): Promise<BatchDeleteResult> {
        if (ids.length === 0) {
            throw new ProxyError("ids_required", 400, "At least one proxy ID is required");
        }
        return this.#repository.batchDelete(ids);
    }

    async batchCreateProxies(items: Array<{ protocol: string; host: string; port: number; username?: string; password?: string }>): Promise<{ created: number; skipped: number }> {
        if (items.length === 0) {
            throw new ProxyError("items_required", 400, "At least one proxy is required");
        }

        for (const item of items) {
            const protocol = item.protocol.trim();
            if (!VALID_PROTOCOLS.has(protocol)) {
                throw new ProxyError("invalid_protocol", 400, `Protocol must be one of: ${[...VALID_PROTOCOLS].join(", ")}`);
            }
            const host = item.host.trim();
            if (host.length === 0) {
                throw new ProxyError("host_required", 400, "Proxy host is required");
            }
            if (!Number.isFinite(item.port) || item.port < 1 || item.port > 65535) {
                throw new ProxyError("invalid_port", 400, "Port must be between 1 and 65535");
            }
        }

        return this.#repository.batchCreate(items);
    }
}
