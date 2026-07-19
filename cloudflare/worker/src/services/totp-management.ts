import type { D1AuthUserRepository } from "../repositories/auth-users.ts";
import type { D1CoordinationRepository } from "../repositories/runtime-coordination.ts";
import type { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import type { D1SecurityMutationRepository } from "../repositories/security-mutations.ts";
import type { AuthUserRecord } from "../types/auth.ts";
import { randomHex, sha256Hex, utf8 } from "../utils/crypto.ts";
import type { PasswordVerifier } from "./password.ts";
import type { TotpSecretCipher } from "./totp.ts";
import { verifyTotpCode } from "./totp.ts";

const TOTP_SETUP_TTL_MS = 5 * 60 * 1000;
const EMAIL_CODE_TTL_MS = 15 * 60 * 1000;
const EMAIL_CODE_ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
const MAX_EMAIL_CODE_ATTEMPTS = 5;
const TOTP_ISSUER = "Sub2API";

interface TotpSetupState {
    userId: number;
    secret: string;
    setupTokenHash: string;
    passwordHash: string;
}

export type TotpManagementErrorCode =
    | "totp_not_enabled"
    | "totp_already_enabled"
    | "totp_not_setup"
    | "verify_code_required"
    | "password_required"
    | "password_incorrect"
    | "invalid_verify_code"
    | "verify_code_max_attempts"
    | "totp_setup_expired"
    | "invalid_totp_code"
    | "security_state_changed";

export class TotpManagementError extends Error {
    readonly code: TotpManagementErrorCode;
    readonly status: number;

    constructor(code: TotpManagementErrorCode, status: number, message: string) {
        super(message);
        this.name = "TotpManagementError";
        this.code = code;
        this.status = status;
    }
}

export interface TotpSetupInput {
    emailCode?: string;
    password?: string;
}

export interface TotpSetupResult {
    secret: string;
    qr_code_url: string;
    setup_token: string;
    countdown: number;
}

export class TotpManagementService {
    readonly #users: D1AuthUserRepository;
    readonly #state: D1ExpiringStateRepository;
    readonly #coordination: D1CoordinationRepository;
    readonly #mutations: D1SecurityMutationRepository;
    readonly #passwords: PasswordVerifier;
    readonly #cipher: TotpSecretCipher;
    readonly #clock: () => number;

    constructor(
        users: D1AuthUserRepository,
        state: D1ExpiringStateRepository,
        coordination: D1CoordinationRepository,
        mutations: D1SecurityMutationRepository,
        passwords: PasswordVerifier,
        cipher: TotpSecretCipher,
        clock: () => number = Date.now
    ) {
        this.#users = users;
        this.#state = state;
        this.#coordination = coordination;
        this.#mutations = mutations;
        this.#passwords = passwords;
        this.#cipher = cipher;
        this.#clock = clock;
    }

    status(user: AuthUserRecord, featureEnabled: boolean): {
        enabled: boolean;
        enabled_at: number | null;
        feature_enabled: boolean;
    } {
        return {
            enabled: user.totpEnabled,
            enabled_at: user.totpEnabledAt === null
                ? null
                : Math.floor(Date.parse(user.totpEnabledAt) / 1000),
            feature_enabled: featureEnabled
        };
    }

    verificationMethod(emailVerificationEnabled: boolean): { method: "email" | "password" } {
        return { method: emailVerificationEnabled ? "email" : "password" };
    }

    async storeEmailVerificationCode(emailValue: string, codeValue: string): Promise<void> {
        const email = normalizeEmail(emailValue);
        const code = codeValue.trim();
        if (!/^\d{6}$/u.test(code)) {
            throw new TypeError("verification code must contain six digits");
        }
        await this.#state.put(
            await emailCodeStateKey(email),
            await sha256Hex(code),
            EMAIL_CODE_TTL_MS
        );
        await this.#coordination.clearFixedWindow(await emailAttemptKey(email));
    }

    async initiateSetup(
        user: AuthUserRecord,
        input: TotpSetupInput,
        featureEnabled: boolean,
        emailVerificationEnabled: boolean
    ): Promise<TotpSetupResult> {
        if (!featureEnabled) {
            throw new TotpManagementError("totp_not_enabled", 400, "totp feature is not enabled");
        }
        if (user.totpEnabled) {
            throw new TotpManagementError(
                "totp_already_enabled",
                400,
                "totp is already enabled for this account"
            );
        }
        await this.#verifyIdentity(user, input, emailVerificationEnabled);

        const secret = generateBase32Secret();
        const setupToken = randomHex(32);
        const setupState: TotpSetupState = {
            userId: user.id,
            secret,
            setupTokenHash: await sha256Hex(setupToken),
            passwordHash: user.passwordHash
        };
        await this.#state.put(setupStateKey(user.id), setupState, TOTP_SETUP_TTL_MS);
        const account = encodeURIComponent(user.email);
        const issuer = encodeURIComponent(TOTP_ISSUER);
        return {
            secret,
            qr_code_url: `otpauth://totp/${issuer}:${account}?secret=${secret}&issuer=${issuer}`,
            setup_token: setupToken,
            countdown: Math.floor(TOTP_SETUP_TTL_MS / 1000)
        };
    }

    async enable(
        user: AuthUserRecord,
        totpCodeValue: string,
        setupTokenValue: string
    ): Promise<{ success: true }> {
        if (user.totpEnabled) {
            throw new TotpManagementError(
                "totp_already_enabled",
                400,
                "totp is already enabled for this account"
            );
        }
        const code = totpCodeValue.trim();
        const setupToken = setupTokenValue.trim().toLowerCase();
        if (!/^\d{6}$/u.test(code) || !/^[a-f0-9]{64}$/u.test(setupToken)) {
            throw setupExpired();
        }
        const key = setupStateKey(user.id);
        const pending = await this.#state.get<TotpSetupState>(key);
        if (
            pending === null
            || pending.value.userId !== user.id
            || !constantTimeEqual(
                pending.value.setupTokenHash,
                await sha256Hex(setupToken)
            )
        ) {
            throw setupExpired();
        }
        if (!await verifyTotpCode(pending.value.secret, code, this.#clock(), 1)) {
            throw new TotpManagementError("invalid_totp_code", 400, "invalid totp code");
        }

        const encryptedSecret = await this.#cipher.encrypt(pending.value.secret);
        const now = this.#clock();
        const updated = await this.#mutations.enableTotp({
            userId: user.id,
            expectedPasswordHash: pending.value.passwordHash,
            encryptedSecret,
            setupStateKey: key,
            expectedStateJson: JSON.stringify(pending.value),
            enabledAt: new Date(now).toISOString(),
            updatedAt: new Date(now).toISOString(),
            now
        });
        if (!updated) {
            throw new TotpManagementError(
                "security_state_changed",
                409,
                "User security state changed before TOTP could be enabled"
            );
        }
        return { success: true };
    }

    async disable(
        user: AuthUserRecord,
        input: TotpSetupInput,
        emailVerificationEnabled: boolean
    ): Promise<{ success: true }> {
        if (!user.totpEnabled) {
            throw new TotpManagementError(
                "totp_not_setup",
                400,
                "totp is not set up for this account"
            );
        }
        await this.#verifyIdentity(user, input, emailVerificationEnabled);
        const now = this.#clock();
        const disabled = await this.#mutations.disableTotp({
            userId: user.id,
            expectedPasswordHash: user.passwordHash,
            updatedAt: new Date(now).toISOString(),
            revokedAt: now
        });
        if (!disabled) {
            throw new TotpManagementError(
                "security_state_changed",
                409,
                "User security state changed before TOTP could be disabled"
            );
        }
        return { success: true };
    }

    async #verifyIdentity(
        user: AuthUserRecord,
        input: TotpSetupInput,
        emailVerificationEnabled: boolean
    ): Promise<void> {
        if (emailVerificationEnabled) {
            const code = input.emailCode?.trim() ?? "";
            if (code.length === 0) {
                throw new TotpManagementError(
                    "verify_code_required",
                    400,
                    "email verification code is required"
                );
            }
            await this.#consumeEmailVerificationCode(user.email, code);
            return;
        }

        const password = input.password ?? "";
        if (password.length === 0) {
            throw new TotpManagementError("password_required", 400, "password is required");
        }
        if (!await this.#passwords.verify(password, user.passwordHash)) {
            throw new TotpManagementError("password_incorrect", 400, "password is incorrect");
        }
    }

    async #consumeEmailVerificationCode(emailValue: string, codeValue: string): Promise<void> {
        const email = normalizeEmail(emailValue);
        const key = await emailCodeStateKey(email);
        const attemptsKey = await emailAttemptKey(email);
        const attempts = await this.#coordination.getFixedWindow(
            attemptsKey,
            EMAIL_CODE_ATTEMPT_WINDOW_MS
        );
        if ((attempts?.count ?? 0) >= MAX_EMAIL_CODE_ATTEMPTS) {
            throw new TotpManagementError(
                "verify_code_max_attempts",
                429,
                "too many failed attempts, please request a new code"
            );
        }
        const stored = await this.#state.get<string>(key);
        const valid = stored !== null && constantTimeEqual(
            stored.value,
            await sha256Hex(codeValue.trim())
        );
        if (!valid) {
            const attempt = await this.#coordination.consumeFixedWindow({
                key: attemptsKey,
                limit: MAX_EMAIL_CODE_ATTEMPTS,
                windowMs: EMAIL_CODE_ATTEMPT_WINDOW_MS
            });
            if (!attempt.allowed) {
                throw new TotpManagementError(
                    "verify_code_max_attempts",
                    429,
                    "too many failed attempts, please request a new code"
                );
            }
            throw new TotpManagementError(
                "invalid_verify_code",
                400,
                "invalid or expired verification code"
            );
        }
        const consumed = await this.#state.take<string>(key);
        if (consumed === null || !constantTimeEqual(consumed.value, stored.value)) {
            throw new TotpManagementError(
                "invalid_verify_code",
                400,
                "invalid or expired verification code"
            );
        }
        await this.#coordination.clearFixedWindow(attemptsKey);
    }
}

function generateBase32Secret(): string {
    const bytes = new Uint8Array(20);
    crypto.getRandomValues(bytes);
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let output = "";
    let buffer = 0;
    let bits = 0;
    for (const byte of bytes) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            output += alphabet[(buffer >>> bits) & 31];
            buffer &= (1 << bits) - 1;
        }
    }
    if (bits > 0) {
        output += alphabet[(buffer << (5 - bits)) & 31];
    }
    return output;
}

function normalizeEmail(value: string): string {
    return value.trim().toLowerCase();
}

function setupStateKey(userId: number): string {
    return `auth:totp-setup:${userId}`;
}

async function emailCodeStateKey(email: string): Promise<string> {
    return `auth:email-code:${await sha256Hex(email)}`;
}

async function emailAttemptKey(email: string): Promise<string> {
    return `auth:email-code-attempts:${await sha256Hex(email)}`;
}

function constantTimeEqual(left: string, right: string): boolean {
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

function setupExpired(): TotpManagementError {
    return new TotpManagementError(
        "totp_setup_expired",
        400,
        "totp setup session expired"
    );
}
