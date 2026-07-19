import type { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import type { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { legacyTokenVersion } from "../utils/crypto.ts";
import {
    hashRefreshToken,
    isRefreshTokenFormat,
    type AuthTokenService
} from "./auth-tokens.ts";

export type AuthRefreshErrorCode =
    | "REFRESH_TOKEN_INVALID"
    | "REFRESH_TOKEN_EXPIRED"
    | "REFRESH_TOKEN_REUSED"
    | "TOKEN_REVOKED"
    | "USER_INACTIVE"
    | "BACKEND_MODE_ADMIN_ONLY";

export class AuthRefreshError extends Error {
    readonly code: AuthRefreshErrorCode;
    readonly status: number;

    constructor(code: AuthRefreshErrorCode, status: number, message: string) {
        super(message);
        this.name = "AuthRefreshError";
        this.code = code;
        this.status = status;
    }
}

export interface RefreshResponse {
    access_token: string;
    refresh_token: string;
    expires_in: number;
    token_type: "Bearer";
}

export class AuthRefreshService {
    readonly #users: D1AuthUserRepository;
    readonly #sessions: D1AuthSessionRepository;
    readonly #tokens: AuthTokenService;
    readonly #clock: () => number;

    constructor(
        users: D1AuthUserRepository,
        sessions: D1AuthSessionRepository,
        tokens: AuthTokenService,
        clock: () => number = Date.now
    ) {
        this.#users = users;
        this.#sessions = sessions;
        this.#tokens = tokens;
        this.#clock = clock;
    }

    async refresh(rawTokenValue: string, backendModeEnabled: boolean): Promise<RefreshResponse> {
        const rawToken = rawTokenValue.trim();
        if (!isRefreshTokenFormat(rawToken)) {
            throw invalidRefresh();
        }
        const tokenHash = await hashRefreshToken(rawToken);
        const session = await this.#sessions.get(tokenHash);
        if (session === null) {
            throw invalidRefresh();
        }
        const now = this.#clock();
        if (session.rotatedAt !== null) {
            await this.#tokens.revokeFamily(session.familyId);
            throw new AuthRefreshError(
                "REFRESH_TOKEN_REUSED",
                401,
                "Refresh token has been reused"
            );
        }
        if (session.revokedAt !== null) {
            throw invalidRefresh();
        }
        if (session.expiresAt <= now) {
            await this.#sessions.revokeToken(tokenHash, now);
            throw new AuthRefreshError(
                "REFRESH_TOKEN_EXPIRED",
                401,
                "Refresh token has expired"
            );
        }

        const user = await this.#users.findById(session.userId);
        if (user === null) {
            await this.#tokens.revokeFamily(session.familyId);
            throw invalidRefresh();
        }
        if (user.status !== "active") {
            await this.#tokens.revokeFamily(session.familyId);
            throw new AuthRefreshError("USER_INACTIVE", 401, "User account is not active");
        }
        const expectedVersion = await legacyTokenVersion(user.email, user.passwordHash, user.tokenVersion);
        if (session.tokenVersion !== expectedVersion) {
            await this.#tokens.revokeFamily(session.familyId);
            throw new AuthRefreshError("TOKEN_REVOKED", 401, "Token has been revoked");
        }
        if (backendModeEnabled && user.role !== "admin") {
            throw new AuthRefreshError(
                "BACKEND_MODE_ADMIN_ONLY",
                403,
                "Backend mode is active. Only admin login is allowed."
            );
        }

        const pair = await this.#tokens.rotate(user, session);
        if (pair === null) {
            const latest = await this.#sessions.get(tokenHash);
            if (latest?.rotatedAt !== null && latest?.rotatedAt !== undefined) {
                await this.#tokens.revokeFamily(session.familyId);
                throw new AuthRefreshError(
                    "REFRESH_TOKEN_REUSED",
                    401,
                    "Refresh token has been reused"
                );
            }
            throw invalidRefresh();
        }
        return {
            access_token: pair.accessToken,
            refresh_token: pair.refreshToken,
            expires_in: pair.expiresIn,
            token_type: "Bearer"
        };
    }

    async logout(rawTokenValue: string | undefined): Promise<void> {
        const rawToken = rawTokenValue?.trim() ?? "";
        if (!isRefreshTokenFormat(rawToken)) {
            return;
        }
        await this.#tokens.revoke(rawToken);
    }
}

function invalidRefresh(): AuthRefreshError {
    return new AuthRefreshError(
        "REFRESH_TOKEN_INVALID",
        401,
        "Invalid refresh token"
    );
}
