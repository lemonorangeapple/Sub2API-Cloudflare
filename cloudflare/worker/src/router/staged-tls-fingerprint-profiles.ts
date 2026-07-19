import { D1TLSFingerprintProfileRepository } from "../repositories/tls-fingerprint-profiles.ts";
import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { ProfileError, D1TLSFingerprintProfileService } from "../services/tls-fingerprint-profiles.ts";
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

const PROFILE_ID_PATH = /^\/api\/v1\/admin\/tls-fingerprint-profiles\/(\d+)$/u;
const PROFILES_PATH = "/api/v1/admin/tls-fingerprint-profiles";

export interface StagedTLSFingerprintProfilesEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
}

export interface StagedTLSFingerprintProfilesDependencies {
    clock?: () => number;
}

function boundedIntegerEnv(
    value: string | undefined,
    defaultValue: number,
    min: number,
    max: number
): number {
    if (value === undefined || value.trim() === "") return defaultValue;
    const parsed = Number.parseInt(value.trim(), 10);
    if (!Number.isInteger(parsed)) return defaultValue;
    return Math.min(max, Math.max(min, parsed));
}

async function authenticateAdmin(
    request: Request,
    env: StagedTLSFingerprintProfilesEnv,
    clock: () => number
): Promise<{ userId: number; role: string }> {
    const authHeader = request.headers.get("authorization");
    if (!authHeader) {
        throw new AccessAuthError("UNAUTHORIZED", "Missing authorization header");
    }
    const secret = env.JWT_SECRET?.trim() ?? "";
    if (!secret) throw new AccessAuthError("UNAUTHORIZED", "JWT secret is not configured");

    const users = new D1AuthUserRepository(env.DB!);
    const sessions = new D1AuthSessionRepository(env.DB!);
    const signer = new Hs256JwtSigner(secret, boundedIntegerEnv(env.JWT_ACCESS_TOKEN_EXPIRES_SECONDS, 24 * 60 * 60, 1, 7 * 24 * 60 * 60), clock);
    const verifier = new Hs256JwtVerifier(secret, clock);
    const tokens = new AuthTokenService(sessions, signer, boundedIntegerEnv(env.JWT_REFRESH_TOKEN_EXPIRE_DAYS, 30, 1, 365), clock);
    const auth = new AccessAuthService(users, verifier, tokens, clock);
    const subject = await auth.authenticateAuthorization(authHeader);
    return { userId: subject.user.id, role: subject.user.role };
}

export async function routeStagedTLSFingerprintProfiles(
    request: Request,
    env: StagedTLSFingerprintProfilesEnv,
    dependencies: StagedTLSFingerprintProfilesDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clock = dependencies.clock ?? Date.now;

    const profileIdMatch = PROFILE_ID_PATH.exec(path);
    const isKnownPath = path === PROFILES_PATH || profileIdMatch !== null;

    if (!isKnownPath) return null;

    if (env.DB === undefined) {
        return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");
    }

    try {
        const auth = await authenticateAdmin(request, env, clock);
        if (auth.role !== "admin") {
            return middlewareAuthError(403, "FORBIDDEN", "Admin access required");
        }

        const repository = new D1TLSFingerprintProfileRepository(env.DB);
        const service = new D1TLSFingerprintProfileService(repository);

        if (path === PROFILES_PATH && request.method === "GET") {
            const profiles = await service.list();
            return legacySuccess(profiles);
        }

        if (path === PROFILES_PATH && request.method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            if (body === null || typeof body !== "object" || Array.isArray(body)) {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }

            const created = await service.createProfile({
                name: body.name as string ?? "",
                description: body.description as string | null | undefined,
                enable_grease: body.enable_grease as boolean | undefined,
                cipher_suites: body.cipher_suites as number[] | undefined,
                curves: body.curves as number[] | undefined,
                point_formats: body.point_formats as number[] | undefined,
                signature_algorithms: body.signature_algorithms as number[] | undefined,
                alpn_protocols: body.alpn_protocols as string[] | undefined,
                supported_versions: body.supported_versions as number[] | undefined,
                key_share_groups: body.key_share_groups as number[] | undefined,
                psk_modes: body.psk_modes as number[] | undefined,
                extensions: body.extensions as number[] | undefined
            });
            return legacySuccess(created);
        }

        if (profileIdMatch !== null && request.method === "GET") {
            const id = Number(profileIdMatch[1]);
            const profile = await service.getProfileById(id);
            return legacySuccess(profile);
        }

        if (profileIdMatch !== null && request.method === "PUT") {
            const id = Number(profileIdMatch[1]);
            const body = await request.json() as Record<string, unknown>;
            if (body === null || typeof body !== "object" || Array.isArray(body)) {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }

            const updated = await service.updateProfile(id, {
                name: body.name as string | undefined,
                description: body.description as string | null | undefined,
                enable_grease: body.enable_grease as boolean | undefined,
                cipher_suites: body.cipher_suites as number[] | undefined,
                curves: body.curves as number[] | undefined,
                point_formats: body.point_formats as number[] | undefined,
                signature_algorithms: body.signature_algorithms as number[] | undefined,
                alpn_protocols: body.alpn_protocols as string[] | undefined,
                supported_versions: body.supported_versions as number[] | undefined,
                key_share_groups: body.key_share_groups as number[] | undefined,
                psk_modes: body.psk_modes as number[] | undefined,
                extensions: body.extensions as number[] | undefined
            });
            return legacySuccess(updated);
        }

        if (profileIdMatch !== null && request.method === "DELETE") {
            const id = Number(profileIdMatch[1]);
            await service.deleteProfile(id);
            return legacySuccess({ message: "Profile deleted successfully" });
        }

        return null;
    } catch (error: unknown) {
        if (error instanceof AccessAuthError) {
            return middlewareAuthError(401, error.code, error.message);
        }
        if (error instanceof ProfileError) {
            return legacyError(error.status, error.message, error.code);
        }
        return legacyInternalError();
    }
}
