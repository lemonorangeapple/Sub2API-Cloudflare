import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { D1ChannelRepository } from "../repositories/channels.ts";
import { D1GroupRepository } from "../repositories/groups.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
    routerError
} from "./responses.ts";

const CHANNELS_AVAILABLE_PATH = "/api/v1/channels/available";

export interface StagedChannelsUserEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedChannelsUserDependencies {
    clock?: () => number;
}

function boundedIntegerEnv(value: string | undefined, defaultValue: number, min: number, max: number): number {
    if (value === undefined || value.trim() === "") return defaultValue;
    const parsed = Number.parseInt(value.trim(), 10);
    if (!Number.isInteger(parsed)) return defaultValue;
    return Math.min(max, Math.max(min, parsed));
}

async function authenticateUser(
    request: Request,
    env: StagedChannelsUserEnv,
    clock: () => number
): Promise<{ userId: number }> {
    const authHeader = request.headers.get("authorization");
    if (!authHeader) throw new AccessAuthError("UNAUTHORIZED", "Missing authorization header");
    const secret = env.JWT_SECRET?.trim() ?? "";
    if (!secret) throw new AccessAuthError("UNAUTHORIZED", "JWT secret is not configured");

    const users = new D1AuthUserRepository(env.DB!);
    const sessions = new D1AuthSessionRepository(env.DB!);
    const signer = new Hs256JwtSigner(secret, boundedIntegerEnv(env.JWT_ACCESS_TOKEN_EXPIRES_SECONDS, 24 * 60 * 60, 1, 7 * 24 * 60 * 60), clock);
    const verifier = new Hs256JwtVerifier(secret, clock);
    const tokens = new AuthTokenService(sessions, signer, boundedIntegerEnv(env.JWT_REFRESH_TOKEN_EXPIRE_DAYS, 30, 1, 365), clock);
    const auth = new AccessAuthService(users, verifier, tokens, clock);
    const subject = await auth.authenticateAuthorization(authHeader);
    return { userId: subject.user.id };
}

interface UserVisibleGroup {
    id: number;
    name: string;
    platform: string;
    subscriptionType: string;
    rateMultiplier: number;
    peakRateEnabled: boolean;
    peakStart: string;
    peakEnd: string;
    peakRateMultiplier: number;
    isExclusive: boolean;
}

interface UserModelPricing {
    billingMode: string;
    inputPrice: number | null;
    outputPrice: number | null;
    cacheWritePrice: number | null;
    cacheReadPrice: number | null;
    imageOutputPrice: number | null;
    perRequestPrice: number | null;
    intervals: Array<{
        minTokens: number;
        maxTokens: number | null;
        tierLabel: string | null;
        inputPrice: number | null;
        outputPrice: number | null;
        cacheWritePrice: number | null;
        cacheReadPrice: number | null;
        perRequestPrice: number | null;
    }>;
}

interface UserSupportedModel {
    name: string;
    platform: string;
    pricing: UserModelPricing | null;
}

interface UserChannelPlatformSection {
    platform: string;
    groups: UserVisibleGroup[];
    supportedModels: UserSupportedModel[];
}

interface UserAvailableChannel {
    name: string;
    description: string;
    platforms: UserChannelPlatformSection[];
}

function toUserGroup(g: { id: number; name: string; platform: string; subscriptionType: string; rateMultiplier: number; peakRateEnabled: boolean; peakStart: string; peakEnd: string; peakRateMultiplier: number; isExclusive: boolean }): UserVisibleGroup {
    return {
        id: g.id,
        name: g.name,
        platform: g.platform,
        subscriptionType: g.subscriptionType,
        rateMultiplier: g.rateMultiplier,
        peakRateEnabled: g.peakRateEnabled,
        peakStart: g.peakStart,
        peakEnd: g.peakEnd,
        peakRateMultiplier: g.peakRateMultiplier,
        isExclusive: g.isExclusive,
    };
}

function toUserPricing(p: { billingMode: string; inputPrice: number | null; outputPrice: number | null; cacheWritePrice: number | null; cacheReadPrice: number | null; imageOutputPrice: number | null; perRequestPrice: number | null; intervals: Array<{ minTokens: number; maxTokens: number | null; tierLabel: string | null; inputPrice: number | null; outputPrice: number | null; cacheWritePrice: number | null; cacheReadPrice: number | null; perRequestPrice: number | null }> } | null): UserModelPricing | null {
    if (!p) return null;
    return {
        billingMode: p.billingMode || "token",
        inputPrice: p.inputPrice,
        outputPrice: p.outputPrice,
        cacheWritePrice: p.cacheWritePrice,
        cacheReadPrice: p.cacheReadPrice,
        imageOutputPrice: p.imageOutputPrice,
        perRequestPrice: p.perRequestPrice,
        intervals: (p.intervals || []).map(iv => ({
            minTokens: iv.minTokens,
            maxTokens: iv.maxTokens,
            tierLabel: iv.tierLabel,
            inputPrice: iv.inputPrice,
            outputPrice: iv.outputPrice,
            cacheWritePrice: iv.cacheWritePrice,
            cacheReadPrice: iv.cacheReadPrice,
            perRequestPrice: iv.perRequestPrice,
        })),
    };
}

export async function routeStagedChannelsUser(
    request: Request,
    env: StagedChannelsUserEnv,
    dependencies: StagedChannelsUserDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const isKnownPath = path === CHANNELS_AVAILABLE_PATH;
    if (!isKnownPath) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateUser(request, env, clock);
        const channelRepo = new D1ChannelRepository(env.DB);
        const groupRepo = new D1GroupRepository(env.DB);

        const allGroups = await groupRepo.listActive();
        const groupMap = new Map(allGroups.map(g => [g.id, g]));

        const userAllowedRows = await env.DB.prepare(
            `SELECT group_id FROM user_allowed_groups WHERE user_id = ?`
        ).bind(auth.userId).all() as { results?: Array<{ group_id: number }> };
        const allowedGroupIds = new Set((userAllowedRows.results ?? []).map(r => r.group_id));

        const userGroups: UserVisibleGroup[] = allGroups
            .filter(g => allowedGroupIds.size === 0 || allowedGroupIds.has(g.id))
            .map(g => toUserGroup(g));

        const allowedGroupIdSet = new Set(userGroups.map(g => g.id));

        const channels = await channelRepo.listAll();
        const out: UserAvailableChannel[] = [];

        for (const ch of channels) {
            if (ch.status !== "active") continue;

            const visibleGroupIds = ch.groupIds.filter(gid => allowedGroupIdSet.has(gid));
            if (visibleGroupIds.length === 0) continue;

            const visibleGroups = visibleGroupIds
                .map(gid => groupMap.get(gid))
                .filter((g): g is NonNullable<typeof g> => g !== undefined)
                .map(g => toUserGroup(g));

            const groupsByPlatform = new Map<string, UserVisibleGroup[]>();
            for (const g of visibleGroups) {
                const list = groupsByPlatform.get(g.platform) ?? [];
                list.push(g);
                groupsByPlatform.set(g.platform, list);
            }

            const platforms = [...groupsByPlatform.keys()].sort();
            const sections: UserChannelPlatformSection[] = [];

            for (const platform of platforms) {
                const platformGroups = groupsByPlatform.get(platform)!;
                const platformPricing = ch.modelPricing.filter(p => p.platform === platform);

                const modelNames = new Set<string>();
                const supportedModels: UserSupportedModel[] = [];

                for (const pricing of platformPricing) {
                    for (const model of pricing.models) {
                        if (modelNames.has(model)) continue;
                        modelNames.add(model);
                        supportedModels.push({
                            name: model,
                            platform,
                            pricing: toUserPricing(pricing),
                        });
                    }
                }

                supportedModels.sort((a, b) => a.name.localeCompare(b.name));

                sections.push({ platform, groups: platformGroups, supportedModels });
            }

            out.push({ name: ch.name, description: ch.description, platforms: sections });
        }

        return legacySuccess(out);
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        return legacyInternalError();
    }
}
