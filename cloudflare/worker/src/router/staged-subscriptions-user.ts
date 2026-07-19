import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { D1SubscriptionRepository } from "../repositories/subscriptions.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import { D1SubscriptionService, SubscriptionError } from "../services/subscriptions.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
    routerError,
} from "./responses.ts";

const SUBS_PATH = "/api/v1/subscriptions";
const ACTIVE_PATH = "/api/v1/subscriptions/active";
const PROGRESS_PATH = "/api/v1/subscriptions/progress";
const SUMMARY_PATH = "/api/v1/subscriptions/summary";

export interface StagedSubscriptionsUserEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedSubscriptionsUserDependencies {
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
    env: StagedSubscriptionsUserEnv,
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

function daysBetween(from: string, to: string): number {
    const diff = new Date(to).getTime() - new Date(from).getTime();
    return Math.max(0, Math.floor(diff / (1000 * 60 * 60 * 24)));
}

export async function routeStagedSubscriptionsUser(
    request: Request,
    env: StagedSubscriptionsUserEnv,
    dependencies: StagedSubscriptionsUserDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const isKnownPath = path === SUBS_PATH || path === ACTIVE_PATH || path === PROGRESS_PATH || path === SUMMARY_PATH;
    if (!isKnownPath) return null;
    if (env.DB === undefined) return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");

    try {
        const auth = await authenticateUser(request, env, clock);
        const repo = new D1SubscriptionRepository(env.DB);
        const service = new D1SubscriptionService(env.DB);

        // GET /api/v1/subscriptions — list all user subscriptions
        if (path === SUBS_PATH && request.method === "GET") {
            const subs = await service.listByUser(auth.userId);
            return legacySuccess(subs);
        }

        // GET /api/v1/subscriptions/active — list active subscriptions
        if (path === ACTIVE_PATH && request.method === "GET") {
            const activeSubs = await repo.listActiveByUser(auth.userId);
            const subsWithGroup: Record<string, unknown>[] = [];
            for (const sub of activeSubs) {
                const full = await repo.getById(sub.id);
                if (full) subsWithGroup.push({
                    id: full.id,
                    group_id: full.groupId,
                    group_name: full.groupName,
                    group_platform: full.groupPlatform,
                    status: full.status,
                    starts_at: full.startsAt,
                    expires_at: full.expiresAt,
                    daily_window_start: full.dailyWindowStart,
                    weekly_window_start: full.weeklyWindowStart,
                    monthly_window_start: full.monthlyWindowStart,
                    daily_usage_usd: full.dailyUsageUsd,
                    weekly_usage_usd: full.weeklyUsageUsd,
                    monthly_usage_usd: full.monthlyUsageUsd,
                });
            }
            return legacySuccess(subsWithGroup);
        }

        // GET /api/v1/subscriptions/progress — get subscription progress
        if (path === PROGRESS_PATH && request.method === "GET") {
            const activeSubs = await repo.listActiveByUser(auth.userId);
            const progressList = [];
            for (const sub of activeSubs) {
                try {
                    const progress = await service.getProgress(sub.id);
                    progressList.push(progress);
                } catch {
                    continue;
                }
            }
            return legacySuccess(progressList);
        }

        // GET /api/v1/subscriptions/summary — get subscription summary
        if (path === SUMMARY_PATH && request.method === "GET") {
            const activeSubs = await repo.listActiveByUser(auth.userId);
            const subscriptions = [];
            let totalUsedUsd = 0;
            for (const sub of activeSubs) {
                const full = await repo.getById(sub.id);
                if (full) {
                    totalUsedUsd += full.monthlyUsageUsd;
                    subscriptions.push({
                        id: full.id,
                        group_id: full.groupId,
                        group_name: full.groupName,
                        status: full.status,
                        daily_usage_usd: full.dailyUsageUsd,
                        daily_limit_usd: null,
                        weekly_usage_usd: full.weeklyUsageUsd,
                        weekly_limit_usd: null,
                        monthly_usage_usd: full.monthlyUsageUsd,
                        monthly_limit_usd: null,
                        expires_at: full.expiresAt,
                    });
                }
            }
            return legacySuccess({
                active_count: activeSubs.length,
                total_used_usd: totalUsedUsd,
                subscriptions,
            });
        }

        return null;
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) return middlewareAuthError(401, error.code, error.message);
        if (error instanceof SubscriptionError) return legacyError(error.status, error.message, error.code);
        return legacyInternalError();
    }
}
