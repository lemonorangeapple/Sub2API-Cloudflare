import type { D1AuthUserRepository } from "../repositories/auth-users.ts";
import type { AuthUserRecord, JwtClaims } from "../types/auth.ts";
import { legacyTokenVersion } from "../utils/crypto.ts";
import type { AuthTokenService } from "./auth-tokens.ts";
import { JwtValidationError, type Hs256JwtVerifier } from "./jwt.ts";

export type AccessAuthErrorCode =
    | "UNAUTHORIZED"
    | "INVALID_AUTH_HEADER"
    | "EMPTY_TOKEN"
    | "INVALID_TOKEN"
    | "TOKEN_EXPIRED"
    | "USER_NOT_FOUND"
    | "USER_INACTIVE"
    | "TOKEN_REVOKED"
    | "FORBIDDEN";

export class AccessAuthError extends Error {
    readonly code: AccessAuthErrorCode;
    readonly status = 401;

    constructor(code: AccessAuthErrorCode, message: string) {
        super(message);
        this.name = "AccessAuthError";
        this.code = code;
    }
}

export interface AuthenticatedSubject {
    user: AuthUserRecord;
    claims: JwtClaims;
}

export class AccessAuthService {
    readonly #users: D1AuthUserRepository;
    readonly #verifier: Hs256JwtVerifier;
    readonly #tokens: AuthTokenService;
    readonly #clock: () => number;

    constructor(
        users: D1AuthUserRepository,
        verifier: Hs256JwtVerifier,
        tokens: AuthTokenService,
        clock: () => number = Date.now
    ) {
        this.#users = users;
        this.#verifier = verifier;
        this.#tokens = tokens;
        this.#clock = clock;
    }

    async authenticateAuthorization(headerValue: string | null): Promise<AuthenticatedSubject> {
        if (headerValue === null || headerValue.trim().length === 0) {
            throw new AccessAuthError("UNAUTHORIZED", "Authorization header is required");
        }
        const parts = headerValue.trim().split(/\s+/u);
        if (parts.length !== 2 || parts[0].toLowerCase() !== "bearer") {
            throw new AccessAuthError(
                "INVALID_AUTH_HEADER",
                "Authorization header format must be 'Bearer {token}'"
            );
        }
        const token = parts[1].trim();
        if (token.length === 0) {
            throw new AccessAuthError("EMPTY_TOKEN", "Token cannot be empty");
        }

        let claims: JwtClaims;
        try {
            claims = await this.#verifier.verify(token);
        } catch (error) {
            if (error instanceof JwtValidationError && error.code === "token_expired") {
                throw new AccessAuthError("TOKEN_EXPIRED", "Token has expired");
            }
            throw new AccessAuthError("INVALID_TOKEN", "Invalid token");
        }

        const user = await this.#users.findById(claims.userId);
        if (user === null) {
            throw new AccessAuthError("USER_NOT_FOUND", "User not found");
        }
        if (user.status !== "active") {
            throw new AccessAuthError("USER_INACTIVE", "User account is not active");
        }
        const expectedVersion = await legacyTokenVersion(user.email, user.passwordHash, user.tokenVersion);
        if (claims.tokenVersion !== expectedVersion) {
            throw new AccessAuthError(
                "TOKEN_REVOKED",
                "Token has been revoked (password changed)"
            );
        }
        return { user, claims };
    }

    async revokeAll(user: AuthUserRecord): Promise<void> {
        const now = new Date(this.#clock()).toISOString();
        const newVersion = await this.#users.incrementTokenVersion(user.id, now);
        if (newVersion === null) {
            throw new AccessAuthError("USER_NOT_FOUND", "User not found");
        }
        await this.#tokens.revokeUser(user.id);
    }
}
