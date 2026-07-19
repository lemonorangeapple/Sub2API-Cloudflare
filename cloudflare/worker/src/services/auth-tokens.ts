import type {
    D1AuthSessionRepository,
    StoredRefreshSession
} from "../repositories/auth-sessions.ts";
import type { AuthTokenPair, AuthUserRecord } from "../types/auth.ts";
import { legacyTokenVersion, randomHex, sha256Hex } from "../utils/crypto.ts";
import type { Hs256JwtSigner } from "./jwt.ts";

export class AuthTokenService {
    readonly #sessions: D1AuthSessionRepository;
    readonly #jwt: Hs256JwtSigner;
    readonly #refreshLifetimeMs: number;
    readonly #clock: () => number;

    constructor(
        sessions: D1AuthSessionRepository,
        jwt: Hs256JwtSigner,
        refreshLifetimeDays = 30,
        clock: () => number = Date.now
    ) {
        if (!Number.isInteger(refreshLifetimeDays) || refreshLifetimeDays <= 0 || refreshLifetimeDays > 365) {
            throw new RangeError("refresh token lifetime must be between 1 and 365 days");
        }
        this.#sessions = sessions;
        this.#jwt = jwt;
        this.#refreshLifetimeMs = refreshLifetimeDays * 24 * 60 * 60 * 1000;
        this.#clock = clock;
    }

    async issue(user: AuthUserRecord, familyId = randomHex(16)): Promise<AuthTokenPair> {
        const generated = await this.#generate(user, familyId);
        await this.#sessions.create(generated.session);
        return generated.pair;
    }

    async rotate(user: AuthUserRecord, source: StoredRefreshSession): Promise<AuthTokenPair | null> {
        const generated = await this.#generate(user, source.familyId);
        const rotated = await this.#sessions.rotateActive({
            ...generated.session,
            sourceHash: source.tokenHash,
            rotatedAt: this.#clock()
        });
        return rotated ? generated.pair : null;
    }

    async revoke(rawToken: string): Promise<boolean> {
        const tokenHash = await hashRefreshToken(rawToken);
        return this.#sessions.revokeToken(tokenHash, this.#clock());
    }

    async revokeFamily(familyId: string): Promise<number> {
        return this.#sessions.revokeFamily(familyId, this.#clock());
    }

    async revokeUser(userId: number): Promise<number> {
        return this.#sessions.revokeUser(userId, this.#clock());
    }

    async #generate(
        user: AuthUserRecord,
        familyId: string
    ): Promise<{ pair: AuthTokenPair; session: {
        tokenHash: string;
        userId: number;
        tokenVersion: bigint;
        familyId: string;
        createdAt: number;
        expiresAt: number;
    } }> {
        const tokenVersion = await legacyTokenVersion(user.email, user.passwordHash, user.tokenVersion);
        const access = await this.#jwt.sign({
            id: user.id,
            email: user.email,
            role: user.role,
            tokenVersion
        });
        const refreshToken = `rt_${randomHex(32)}`;
        const tokenHash = await hashRefreshToken(refreshToken);
        const now = this.#clock();
        return {
            pair: {
                accessToken: access.token,
                refreshToken,
                expiresIn: access.expiresIn
            },
            session: {
                tokenHash,
                userId: user.id,
                tokenVersion,
                familyId,
                createdAt: now,
                expiresAt: now + this.#refreshLifetimeMs
            }
        };
    }
}

export function isRefreshTokenFormat(value: string): boolean {
    return /^rt_[a-f0-9]{64}$/u.test(value);
}

export async function hashRefreshToken(value: string): Promise<string> {
    return sha256Hex(value);
}
