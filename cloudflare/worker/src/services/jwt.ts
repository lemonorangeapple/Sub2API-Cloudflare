import type { JwtClaims } from "../types/auth.ts";
import { base64UrlDecode, base64UrlEncode, decodeUtf8, utf8 } from "../utils/crypto.ts";

const MAX_TOKEN_LENGTH = 8192;

export interface AccessTokenSubject {
    id: number;
    email: string;
    role: string;
    tokenVersion: bigint;
}

export interface SignedAccessToken {
    token: string;
    expiresIn: number;
}

export type JwtValidationErrorCode =
    | "invalid_token"
    | "token_expired"
    | "token_not_active";

export class JwtValidationError extends Error {
    readonly code: JwtValidationErrorCode;

    constructor(code: JwtValidationErrorCode, message: string) {
        super(message);
        this.name = "JwtValidationError";
        this.code = code;
    }
}

export class Hs256JwtSigner {
    readonly #secret: string;
    readonly #expiresInSeconds: number;
    readonly #clock: () => number;

    constructor(secret: string, expiresInSeconds = 24 * 60 * 60, clock: () => number = Date.now) {
        validateSecret(secret);
        if (!Number.isInteger(expiresInSeconds) || expiresInSeconds <= 0 || expiresInSeconds > 7 * 24 * 60 * 60) {
            throw new RangeError("access token lifetime must be between 1 second and 7 days");
        }
        this.#secret = secret;
        this.#expiresInSeconds = expiresInSeconds;
        this.#clock = clock;
    }

    async sign(subject: AccessTokenSubject): Promise<SignedAccessToken> {
        const now = Math.floor(this.#clock() / 1000);
        const expiresAt = now + this.#expiresInSeconds;
        const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
        const payload = base64UrlEncode(buildPayload(subject, now, expiresAt));
        const signingInput = `${header}.${payload}`;
        const key = await importHmacKey(this.#secret, ["sign"]);
        const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8(signingInput)));
        return {
            token: `${signingInput}.${base64UrlEncode(signature)}`,
            expiresIn: this.#expiresInSeconds
        };
    }
}

export class Hs256JwtVerifier {
    readonly #secret: string;
    readonly #clock: () => number;

    constructor(secret: string, clock: () => number = Date.now) {
        validateSecret(secret);
        this.#secret = secret;
        this.#clock = clock;
    }

    async verify(tokenValue: string): Promise<JwtClaims> {
        const token = tokenValue.trim();
        if (token.length === 0 || token.length > MAX_TOKEN_LENGTH) {
            throw invalidToken();
        }
        const segments = token.split(".");
        if (segments.length !== 3 || segments.some((segment) => segment.length === 0)) {
            throw invalidToken();
        }

        const [headerSegment, payloadSegment, signatureSegment] = segments;
        const header = parseHeader(headerSegment);
        if (header.alg !== "HS256" || (header.typ !== undefined && header.typ !== "JWT")) {
            throw invalidToken();
        }

        let signature: Uint8Array;
        try {
            signature = base64UrlDecode(signatureSegment);
        } catch {
            throw invalidToken();
        }
        if (signature.byteLength !== 32) {
            throw invalidToken();
        }

        const key = await importHmacKey(this.#secret, ["verify"]);
        const valid = await crypto.subtle.verify(
            "HMAC",
            key,
            signature,
            utf8(`${headerSegment}.${payloadSegment}`)
        );
        if (!valid) {
            throw invalidToken();
        }

        const claims = parseClaims(payloadSegment);
        const now = Math.floor(this.#clock() / 1000);
        if (claims.notBefore > now) {
            throw new JwtValidationError("token_not_active", "Token is not active yet");
        }
        if (claims.expiresAt <= now) {
            throw new JwtValidationError("token_expired", "Token has expired");
        }
        return claims;
    }
}

function buildPayload(subject: AccessTokenSubject, issuedAt: number, expiresAt: number): string {
    if (!Number.isSafeInteger(subject.id) || subject.id <= 0) {
        throw new RangeError("JWT user id must be a positive safe integer");
    }
    return [
        "{",
        `\"user_id\":${subject.id},`,
        `\"email\":${JSON.stringify(subject.email)},`,
        `\"role\":${JSON.stringify(subject.role)},`,
        `\"token_version\":${subject.tokenVersion.toString()},`,
        `\"exp\":${expiresAt},`,
        `\"iat\":${issuedAt},`,
        `\"nbf\":${issuedAt}`,
        "}"
    ].join("");
}

function parseHeader(segment: string): { alg?: unknown; typ?: unknown } {
    try {
        const parsed: unknown = JSON.parse(decodeUtf8(base64UrlDecode(segment)));
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
            throw invalidToken();
        }
        return parsed as { alg?: unknown; typ?: unknown };
    } catch (error) {
        if (error instanceof JwtValidationError) {
            throw error;
        }
        throw invalidToken();
    }
}

function parseClaims(segment: string): JwtClaims {
    let text: string;
    try {
        text = decodeUtf8(base64UrlDecode(segment));
    } catch {
        throw invalidToken();
    }

    const versionMatches = [...text.matchAll(/"token_version"\s*:\s*(-?\d+)/gu)];
    if (versionMatches.length !== 1) {
        throw invalidToken();
    }
    const transformed = text.replace(
        /"token_version"\s*:\s*(-?\d+)/u,
        (_match, digits: string) => `"token_version":${JSON.stringify(digits)}`
    );

    let payload: Record<string, unknown>;
    try {
        const parsed: unknown = JSON.parse(transformed);
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
            throw invalidToken();
        }
        payload = parsed as Record<string, unknown>;
    } catch (error) {
        if (error instanceof JwtValidationError) {
            throw error;
        }
        throw invalidToken();
    }

    const userId = safeInteger(payload.user_id);
    const expiresAt = safeInteger(payload.exp);
    const issuedAt = safeInteger(payload.iat);
    const notBefore = safeInteger(payload.nbf);
    if (
        userId === null || userId <= 0 ||
        expiresAt === null || expiresAt <= 0 ||
        issuedAt === null || issuedAt <= 0 ||
        notBefore === null || notBefore <= 0 ||
        typeof payload.email !== "string" || payload.email.length === 0 ||
        typeof payload.role !== "string" || payload.role.length === 0 ||
        typeof payload.token_version !== "string"
    ) {
        throw invalidToken();
    }

    let tokenVersion: bigint;
    try {
        tokenVersion = BigInt(payload.token_version);
    } catch {
        throw invalidToken();
    }
    if (tokenVersion < 0n) {
        throw invalidToken();
    }

    return {
        userId,
        email: payload.email,
        role: payload.role,
        tokenVersion,
        expiresAt,
        issuedAt,
        notBefore
    };
}

function safeInteger(value: unknown): number | null {
    return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
}

function validateSecret(secret: string): void {
    if (utf8(secret).byteLength < 32) {
        throw new RangeError("JWT secret must be at least 32 bytes");
    }
}

async function importHmacKey(secret: string, usages: KeyUsage[]): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        "raw",
        utf8(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        usages
    );
}

function invalidToken(): JwtValidationError {
    return new JwtValidationError("invalid_token", "Invalid token");
}
