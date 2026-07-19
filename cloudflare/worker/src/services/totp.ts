import type { D1AuthUserRepository } from "../repositories/auth-users.ts";
import type { D1CoordinationRepository } from "../repositories/runtime-coordination.ts";
import type { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import type { AuthUserRecord, PasswordLoginResponse, TotpLoginResponse } from "../types/auth.ts";
import {
    base64Decode,
    base64Encode,
    hexToBytes,
    randomHex,
    sha256Hex,
    utf8
} from "../utils/crypto.ts";
import type { AuthTokenService } from "./auth-tokens.ts";
import { mapAuthUser } from "./auth-user.ts";

const LOGIN_SESSION_TTL_MS = 5 * 60 * 1000;
const VERIFY_ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
const MAX_VERIFY_ATTEMPTS = 5;
const TOTP_PERIOD_MS = 30_000;

export interface PendingOAuthTotpContext {
    pendingSessionToken: string;
    browserSessionKey: string;
    adoptDisplayName: boolean;
    adoptAvatar: boolean;
}

interface TotpLoginSession {
    userId: number;
    email: string;
    pendingOAuthBind?: PendingOAuthTotpContext;
}

export type TotpAuthErrorCode =
    | "invalid_2fa_session"
    | "invalid_totp_code"
    | "totp_too_many_attempts"
    | "totp_not_configured"
    | "user_not_active"
    | "backend_mode_admin_only";

export class TotpAuthError extends Error {
    readonly code: TotpAuthErrorCode;
    readonly status: number;

    constructor(code: TotpAuthErrorCode, status: number, message: string) {
        super(message);
        this.name = "TotpAuthError";
        this.code = code;
        this.status = status;
    }
}

export interface TotpSecretDecryptor {
    decrypt(ciphertext: string): Promise<string>;
}

export interface TotpSecretCipher extends TotpSecretDecryptor {
    encrypt(plaintext: string): Promise<string>;
}

export class AesGcmTotpSecretDecryptor implements TotpSecretCipher {
    readonly #keyBytes: Uint8Array;

    constructor(hexKey: string) {
        const keyBytes = hexToBytes(hexKey);
        if (keyBytes.byteLength !== 32) {
            throw new RangeError("TOTP encryption key must be 32 bytes (64 hex characters)");
        }
        this.#keyBytes = keyBytes;
    }

    async encrypt(plaintext: string): Promise<string> {
        const key = await crypto.subtle.importKey(
            "raw",
            this.#keyBytes,
            "AES-GCM",
            false,
            ["encrypt"]
        );
        const nonce = new Uint8Array(12);
        crypto.getRandomValues(nonce);
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: nonce },
            key,
            utf8(plaintext)
        ));
        const output = new Uint8Array(nonce.byteLength + ciphertext.byteLength);
        output.set(nonce, 0);
        output.set(ciphertext, nonce.byteLength);
        return base64Encode(output);
    }

    async decrypt(ciphertext: string): Promise<string> {
        const data = base64Decode(ciphertext.trim());
        if (data.byteLength < 12 + 16) {
            throw new TypeError("encrypted TOTP secret is too short");
        }
        const key = await crypto.subtle.importKey(
            "raw",
            this.#keyBytes,
            "AES-GCM",
            false,
            ["decrypt"]
        );
        const plaintext = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: data.slice(0, 12) },
            key,
            data.slice(12)
        );
        return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
    }
}

export class TotpLoginService {
    readonly #users: D1AuthUserRepository;
    readonly #state: D1ExpiringStateRepository;
    readonly #coordination: D1CoordinationRepository;
    readonly #tokens: AuthTokenService;
    readonly #decryptor: TotpSecretDecryptor;
    readonly #clock: () => number;

    constructor(
        users: D1AuthUserRepository,
        state: D1ExpiringStateRepository,
        coordination: D1CoordinationRepository,
        tokens: AuthTokenService,
        decryptor: TotpSecretDecryptor,
        clock: () => number = Date.now
    ) {
        this.#users = users;
        this.#state = state;
        this.#coordination = coordination;
        this.#tokens = tokens;
        this.#decryptor = decryptor;
        this.#clock = clock;
    }

    async create(user: AuthUserRecord): Promise<TotpLoginResponse> {
        return this.#create(user);
    }

    async createPendingOAuth(
        user: AuthUserRecord,
        pendingOAuthBind: PendingOAuthTotpContext
    ): Promise<TotpLoginResponse> {
        return this.#create(user, pendingOAuthBind);
    }

    async #create(
        user: AuthUserRecord,
        pendingOAuthBind?: PendingOAuthTotpContext
    ): Promise<TotpLoginResponse> {
        const tempToken = randomHex(32);
        await this.#state.put(
            await stateKey(tempToken),
            {
                userId: user.id,
                email: user.email,
                ...(pendingOAuthBind === undefined ? {} : { pendingOAuthBind })
            } satisfies TotpLoginSession,
            LOGIN_SESSION_TTL_MS
        );
        return {
            requires_2fa: true,
            temp_token: tempToken,
            user_email_masked: maskEmail(user.email)
        };
    }

    async complete(
        tempTokenValue: string,
        codeValue: string,
        backendModeEnabled: boolean,
        completePendingOAuth?: (
            user: AuthUserRecord,
            context: PendingOAuthTotpContext
        ) => Promise<void>
    ): Promise<PasswordLoginResponse> {
        const tempToken = tempTokenValue.trim();
        const code = codeValue.trim();
        if (!/^[a-f0-9]{64}$/u.test(tempToken) || !/^\d{6}$/u.test(code)) {
            throw invalidSession();
        }
        const key = await stateKey(tempToken);
        const pending = await this.#state.get<TotpLoginSession>(key);
        if (pending === null) {
            throw invalidSession();
        }

        const user = await this.#users.findById(pending.value.userId);
        if (user === null || !user.totpEnabled || !user.totpSecretEncrypted) {
            throw invalidSession();
        }
        if (user.status !== "active") {
            throw new TotpAuthError("user_not_active", 401, "User account is not active");
        }
        if (backendModeEnabled && user.role !== "admin") {
            throw new TotpAuthError(
                "backend_mode_admin_only",
                403,
                "Backend mode is active. Only admin login is allowed."
            );
        }

        const attempts = await this.#coordination.getFixedWindow(
            attemptKey(user.id),
            VERIFY_ATTEMPT_WINDOW_MS
        );
        if ((attempts?.count ?? 0) >= MAX_VERIFY_ATTEMPTS) {
            throw new TotpAuthError(
                "totp_too_many_attempts",
                429,
                "Too many verification attempts, please try again later"
            );
        }

        let secret: string;
        try {
            secret = await this.#decryptor.decrypt(user.totpSecretEncrypted);
        } catch {
            throw new TotpAuthError(
                "totp_not_configured",
                503,
                "TOTP verification is not configured"
            );
        }

        if (!await verifyTotpCode(secret, code, this.#clock())) {
            const attempt = await this.#coordination.consumeFixedWindow({
                key: attemptKey(user.id),
                limit: MAX_VERIFY_ATTEMPTS,
                windowMs: VERIFY_ATTEMPT_WINDOW_MS
            });
            if (!attempt.allowed) {
                throw new TotpAuthError(
                    "totp_too_many_attempts",
                    429,
                    "Too many verification attempts, please try again later"
                );
            }
            throw new TotpAuthError("invalid_totp_code", 400, "Invalid TOTP code");
        }

        if (pending.value.pendingOAuthBind !== undefined) {
            if (completePendingOAuth === undefined) {
                throw new TotpAuthError(
                    "totp_not_configured",
                    503,
                    "Pending OAuth TOTP completion is not configured"
                );
            }
            await completePendingOAuth(user, pending.value.pendingOAuthBind);
        }

        await this.#coordination.clearFixedWindow(attemptKey(user.id));
        const consumed = await this.#state.take<TotpLoginSession>(key);
        if (consumed === null || consumed.value.userId !== user.id) {
            throw invalidSession();
        }

        const tokenPair = await this.#tokens.issue(user);
        const now = new Date(this.#clock()).toISOString();
        await this.#users.recordSuccessfulLogin(user.id, now);
        return {
            access_token: tokenPair.accessToken,
            refresh_token: tokenPair.refreshToken,
            expires_in: tokenPair.expiresIn,
            token_type: "Bearer",
            user: mapAuthUser(user, now)
        };
    }
}

export async function verifyTotpCode(
    secretValue: string,
    code: string,
    nowMs = Date.now(),
    skew = 1
): Promise<boolean> {
    if (!/^\d{6}$/u.test(code) || !Number.isInteger(skew) || skew < 0 || skew > 10) {
        return false;
    }
    const secret = decodeBase32(secretValue);
    const counter = Math.floor(nowMs / TOTP_PERIOD_MS);
    for (let offset = -skew; offset <= skew; offset += 1) {
        if (counter + offset < 0) {
            continue;
        }
        const expected = await hotp(secret, BigInt(counter + offset));
        if (constantTimeTextEqual(expected, code)) {
            return true;
        }
    }
    return false;
}

async function hotp(secret: Uint8Array, counter: bigint): Promise<string> {
    const counterBytes = new Uint8Array(8);
    new DataView(counterBytes.buffer).setBigUint64(0, counter, false);
    const key = await crypto.subtle.importKey(
        "raw",
        secret,
        { name: "HMAC", hash: "SHA-1" },
        false,
        ["sign"]
    );
    const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
    const offset = digest[digest.length - 1] & 0x0f;
    const binary = (
        ((digest[offset] & 0x7f) << 24) |
        (digest[offset + 1] << 16) |
        (digest[offset + 2] << 8) |
        digest[offset + 3]
    ) >>> 0;
    return String(binary % 1_000_000).padStart(6, "0");
}

function decodeBase32(value: string): Uint8Array {
    const normalized = value.toUpperCase().replaceAll(/[-\s=]/gu, "");
    if (normalized.length === 0 || !/^[A-Z2-7]+$/u.test(normalized)) {
        throw new TypeError("invalid base32 TOTP secret");
    }
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const output: number[] = [];
    let buffer = 0;
    let bits = 0;
    for (const character of normalized) {
        buffer = (buffer << 5) | alphabet.indexOf(character);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            output.push((buffer >>> bits) & 0xff);
            buffer &= (1 << bits) - 1;
        }
    }
    return new Uint8Array(output);
}

async function stateKey(tempToken: string): Promise<string> {
    return `auth:totp-login:${await sha256Hex(tempToken)}`;
}

function attemptKey(userId: number): string {
    return `auth:totp-attempts:${userId}`;
}

function maskEmail(emailValue: string): string {
    const email = emailValue.trim();
    if (email.length < 3) {
        return "***";
    }
    const atIndex = email.indexOf("@");
    if (atIndex < 1) {
        return `${email.slice(0, 1)}***`;
    }
    const local = email.slice(0, atIndex);
    const domain = email.slice(atIndex);
    return local.length <= 2
        ? `${local.slice(0, 1)}***${domain}`
        : `${local.slice(0, 1)}***${local.slice(-1)}${domain}`;
}

function constantTimeTextEqual(left: string, right: string): boolean {
    const leftBytes = utf8(left);
    const rightBytes = utf8(right);
    if (leftBytes.byteLength !== rightBytes.byteLength) {
        return false;
    }
    let difference = 0;
    for (let index = 0; index < leftBytes.byteLength; index += 1) {
        difference |= leftBytes[index] ^ rightBytes[index];
    }
    return difference === 0;
}

function invalidSession(): TotpAuthError {
    return new TotpAuthError(
        "invalid_2fa_session",
        400,
        "Invalid or expired 2FA session"
    );
}
