import type { D1AuthUserRepository } from "../repositories/auth-users.ts";
import type {
    AdminAuthIdentityCandidate,
    AdminAuthIdentityChannelCandidate,
    D1AdminAuthIdentityRepository
} from "../repositories/admin-auth-identities.ts";
import type { AuthUserRecord } from "../types/auth.ts";

const PROVIDERS = new Set(["email", "linuxdo", "oidc", "wechat", "dingtalk"]);

export interface AdminBindAuthIdentityInput {
    providerType: string;
    providerKey: string;
    providerSubject: string;
    issuer?: string | null;
    metadata?: Record<string, unknown> | null;
    channel?: {
        channel: string;
        appId: string;
        subject: string;
        metadata?: Record<string, unknown> | null;
    } | null;
}

export class AdminAuthIdentityError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "AdminAuthIdentityError";
        this.code = code;
        this.status = status;
    }
}

export class D1AdminAuthIdentityService {
    readonly #users: D1AuthUserRepository;
    readonly #repository: D1AdminAuthIdentityRepository;
    readonly #clock: () => number;

    constructor(
        users: D1AuthUserRepository,
        repository: D1AdminAuthIdentityRepository,
        clock: () => number = Date.now
    ) {
        this.#users = users;
        this.#repository = repository;
        this.#clock = clock;
    }

    async bind(actor: AuthUserRecord, userId: number, input: AdminBindAuthIdentityInput) {
        if (actor.role !== "admin") throw new AdminAuthIdentityError("forbidden", 403, "Admin access is required");
        if (!Number.isSafeInteger(userId) || userId <= 0 || await this.#users.findById(userId) === null) {
            throw new AdminAuthIdentityError("user_not_found", 404, "User not found");
        }
        const providerType = input.providerType.trim().toLowerCase();
        const requestedKey = bounded(input.providerKey, 512);
        const providerSubject = bounded(input.providerSubject, 1024);
        if (!PROVIDERS.has(providerType) || requestedKey === "" || providerSubject === "") {
            throw new AdminAuthIdentityError("invalid_input", 400, "A supported provider and non-empty key/subject are required");
        }
        const compatibleKeys = providerType === "wechat"
            ? unique([requestedKey, "wechat-main", "wechat"])
            : [requestedKey];
        const candidates = await this.#repository.identityCandidates(providerType, compatibleKeys, providerSubject);
        assertNoOtherOwner(candidates, userId, "auth_identity_ownership_conflict");
        const existing = candidates.find((candidate) => candidate.userId === userId) ?? null;
        const providerKey = providerType === "wechat" && (
            requestedKey === "wechat-main"
            || existing?.providerKey === "wechat-main"
            || existing?.providerKey === "wechat"
        ) ? "wechat-main" : requestedKey;

        const channel = normalizeChannel(input.channel);
        let channelExisting: AdminAuthIdentityChannelCandidate | null = null;
        if (channel !== null) {
            const channelCandidates = await this.#repository.channelCandidates(
                providerType,
                compatibleKeys,
                channel.channel,
                channel.appId,
                channel.subject
            );
            assertNoOtherOwner(channelCandidates, userId, "auth_identity_channel_ownership_conflict");
            channelExisting = channelCandidates.find((candidate) => candidate.userId === userId) ?? null;
        }
        const metadata = input.metadata === undefined || input.metadata === null
            ? parseMetadata(existing?.metadata)
            : validatedMetadata(input.metadata);
        const issuer = input.issuer === undefined || input.issuer === null
            ? existing?.issuer ?? null
            : bounded(input.issuer, 2048) || null;
        const now = new Date(this.#clock()).toISOString();
        try {
            await this.#repository.bind({
                userId,
                providerType,
                providerKey,
                providerSubject,
                issuer,
                metadata,
                now,
                existingIdentityId: existing?.id ?? null,
                channel: channel === null ? null : {
                    ...channel,
                    metadata: input.channel?.metadata === undefined || input.channel.metadata === null
                        ? parseMetadata(channelExisting?.metadata)
                        : validatedMetadata(input.channel.metadata),
                    existingId: channelExisting?.id ?? null
                }
            });
        } catch {
            throw new AdminAuthIdentityError(
                "auth_identity_ownership_conflict",
                409,
                "Auth identity or channel changed ownership"
            );
        }
        const identity = await this.#repository.boundIdentity(userId, providerType, providerKey, providerSubject);
        if (identity === null) throw new AdminAuthIdentityError("bind_failed", 500, "Bound identity could not be loaded");
        const boundChannel = channel === null ? null
            : await this.#repository.boundChannel(identity.id, channel.channel, channel.appId, channel.subject);
        return {
            user_id: identity.userId,
            provider_type: identity.providerType,
            provider_key: identity.providerKey,
            provider_subject: identity.providerSubject,
            verified_at: identity.verifiedAt,
            issuer: identity.issuer,
            metadata: parseMetadata(identity.metadata),
            created_at: identity.createdAt,
            updated_at: identity.updatedAt,
            ...(boundChannel === null ? {} : {
                channel: {
                    channel: boundChannel.channel,
                    channel_app_id: boundChannel.appId,
                    channel_subject: boundChannel.subject,
                    metadata: parseMetadata(boundChannel.metadata),
                    created_at: boundChannel.createdAt,
                    updated_at: boundChannel.updatedAt
                }
            })
        };
    }
}

function normalizeChannel(input: AdminBindAuthIdentityInput["channel"]) {
    if (input === undefined || input === null) return null;
    const channel = bounded(input.channel, 128).toLowerCase();
    const appId = bounded(input.appId, 512);
    const subject = bounded(input.subject, 1024);
    if (channel === "" || appId === "" || subject === "") {
        throw new AdminAuthIdentityError("invalid_input", 400, "Channel, app ID, and subject are required");
    }
    return { channel, appId, subject };
}

function assertNoOtherOwner(
    candidates: readonly { userId: number }[],
    userId: number,
    code: string
): void {
    if (candidates.some((candidate) => candidate.userId !== userId)) {
        throw new AdminAuthIdentityError(code, 409, "Auth identity already belongs to another user");
    }
}

function validatedMetadata(value: Record<string, unknown>): Record<string, unknown> {
    let encoded: string;
    try { encoded = JSON.stringify(value); } catch {
        throw new AdminAuthIdentityError("invalid_input", 400, "Metadata must be JSON serializable");
    }
    if (new TextEncoder().encode(encoded).byteLength > 32 * 1024) {
        throw new AdminAuthIdentityError("invalid_input", 400, "Metadata exceeds 32 KiB");
    }
    return JSON.parse(encoded) as Record<string, unknown>;
}

function parseMetadata(value: string | undefined): Record<string, unknown> {
    if (value === undefined || value === "") return {};
    try {
        const parsed: unknown = JSON.parse(value);
        return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
            ? parsed as Record<string, unknown> : {};
    } catch { return {}; }
}

function bounded(value: string, maximum: number): string {
    const output = value.trim();
    if ([...output].length > maximum) {
        throw new AdminAuthIdentityError("invalid_input", 400, "Auth identity field is too long");
    }
    return output;
}

function unique(values: readonly string[]): string[] {
    return [...new Set(values.filter((value) => value !== ""))];
}
