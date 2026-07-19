import type { D1AuthEmailRepository } from "../repositories/auth-email.ts";
import { base64Decode, base64Encode, hexToBytes, randomHex, sha256Hex, utf8 } from "../utils/crypto.ts";

const VERIFY_TTL_MS = 15 * 60 * 1000;
const VERIFY_COOLDOWN_MS = 60 * 1000;
const RESET_TTL_MS = 30 * 60 * 1000;
const RESET_COOLDOWN_MS = 30 * 1000;

export interface VerificationEmailState {
    codeHash: string;
    secretEnvelope: string;
    attempts: number;
    createdAt: number;
}

export interface PasswordResetEmailState {
    tokenHash: string;
    secretEnvelope: string;
    createdAt: number;
}

export interface AuthenticationEmailTaskPayload {
    kind: "verify_code" | "password_reset";
    email: string;
    siteName: string;
    locale: string;
    stateKey: string;
    resetUrl?: string;
}

export interface EmailSecretCipher {
    seal(secret: string): Promise<string>;
    open(envelope: string): Promise<string>;
}

export interface EmailTaskProducerOptions {
    clock?: () => number;
    verificationCodeFactory?: () => string;
    resetTokenFactory?: () => string;
}

export class AesGcmEmailSecretCipher implements EmailSecretCipher {
    readonly #keyBytes: Uint8Array;

    constructor(hexKey: string) {
        const keyBytes = hexToBytes(hexKey);
        if (keyBytes.byteLength !== 32) {
            throw new RangeError("email task encryption key must be 32 bytes (64 hex characters)");
        }
        this.#keyBytes = keyBytes;
    }

    async seal(secret: string): Promise<string> {
        const key = await crypto.subtle.importKey("raw", this.#keyBytes, "AES-GCM", false, ["encrypt"]);
        const iv = new Uint8Array(12);
        crypto.getRandomValues(iv);
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            utf8(secret)
        ));
        const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
        combined.set(iv, 0);
        combined.set(ciphertext, iv.byteLength);
        return base64Encode(combined);
    }

    async open(envelope: string): Promise<string> {
        const combined = base64Decode(envelope);
        if (combined.byteLength < 28) {
            throw new TypeError("email secret envelope is invalid");
        }
        const key = await crypto.subtle.importKey("raw", this.#keyBytes, "AES-GCM", false, ["decrypt"]);
        const plaintext = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: combined.slice(0, 12) },
            key,
            combined.slice(12)
        );
        return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
    }
}

export class AuthenticationEmailTaskProducer {
    readonly #repository: D1AuthEmailRepository;
    readonly #cipher: EmailSecretCipher;
    readonly #clock: () => number;
    readonly #verificationCodeFactory: () => string;
    readonly #resetTokenFactory: () => string;

    constructor(
        repository: D1AuthEmailRepository,
        cipher: EmailSecretCipher,
        options: EmailTaskProducerOptions = {}
    ) {
        this.#repository = repository;
        this.#cipher = cipher;
        this.#clock = options.clock ?? Date.now;
        this.#verificationCodeFactory = options.verificationCodeFactory ?? randomVerificationCode;
        this.#resetTokenFactory = options.resetTokenFactory ?? (() => randomHex(32));
    }

    async enqueueVerification(
        emailValue: string,
        siteNameValue: string,
        localeValue = ""
    ): Promise<{ countdown: number; taskId: number }> {
        const email = normalizeEmail(emailValue);
        const siteName = normalizeSiteName(siteNameValue);
        const locale = normalizeLocale(localeValue);
        const code = this.#verificationCodeFactory();
        if (!/^\d{6}$/u.test(code)) {
            throw new TypeError("verification code factory must return six digits");
        }
        const now = this.#clock();
        const stateKey = await verificationStateKey(email);
        const state: VerificationEmailState = {
            codeHash: await sha256Hex(code),
            secretEnvelope: await this.#cipher.seal(code),
            attempts: 0,
            createdAt: now
        };
        const payload: AuthenticationEmailTaskPayload = {
            kind: "verify_code",
            email,
            siteName,
            locale,
            stateKey
        };
        const taskId = await this.#repository.createTask({
            stateKey,
            stateJson: JSON.stringify(state),
            expiresAt: now + VERIFY_TTL_MS,
            now,
            cooldownBefore: now - VERIFY_COOLDOWN_MS,
            idempotencyKey: `verify:${await sha256Hex(email)}:${now}`,
            payloadJson: JSON.stringify(payload),
            maxAttempts: 5
        });
        return { countdown: 60, taskId };
    }

    async enqueueTotpVerification(
        emailValue: string,
        siteNameValue: string,
        localeValue = ""
    ): Promise<{ countdown: number; taskId: number }> {
        const email = normalizeEmail(emailValue);
        const siteName = normalizeSiteName(siteNameValue);
        const locale = normalizeLocale(localeValue);
        const code = this.#verificationCodeFactory();
        if (!/^\d{6}$/u.test(code)) {
            throw new TypeError("verification code factory must return six digits");
        }
        const now = this.#clock();
        const stateKey = await totpEmailStateKey(email);
        const payload: AuthenticationEmailTaskPayload = {
            kind: "verify_code",
            email,
            siteName,
            locale,
            stateKey
        };
        const taskId = await this.#repository.createTask({
            stateKey,
            stateJson: JSON.stringify(await sha256Hex(code)),
            expiresAt: now + VERIFY_TTL_MS,
            now,
            cooldownBefore: now - VERIFY_COOLDOWN_MS,
            idempotencyKey: `totp-verify:${await sha256Hex(email)}:${now}`,
            payloadJson: JSON.stringify({
                ...payload,
                secretEnvelope: await this.#cipher.seal(code)
            }),
            maxAttempts: 5
        });
        return { countdown: 60, taskId };
    }

    async enqueueNotificationVerification(
        userId: number,
        emailValue: string,
        siteNameValue: string,
        localeValue = ""
    ): Promise<{ countdown: number; taskId: number }> {
        if (!Number.isSafeInteger(userId) || userId <= 0) throw new TypeError("a valid user ID is required");
        const email = normalizeEmail(emailValue);
        const siteName = normalizeSiteName(siteNameValue);
        const locale = normalizeLocale(localeValue);
        const code = this.#verificationCodeFactory();
        if (!/^\d{6}$/u.test(code)) throw new TypeError("verification code factory must return six digits");
        const now = this.#clock();
        const stateKey = await notificationEmailStateKey(userId, email);
        const state: VerificationEmailState = {
            codeHash: await sha256Hex(code),
            secretEnvelope: await this.#cipher.seal(code),
            attempts: 0,
            createdAt: now
        };
        const payload: AuthenticationEmailTaskPayload = {
            kind: "verify_code",
            email,
            siteName,
            locale,
            stateKey
        };
        const taskId = await this.#repository.createTask({
            stateKey,
            stateJson: JSON.stringify(state),
            expiresAt: now + VERIFY_TTL_MS,
            now,
            cooldownBefore: now - VERIFY_COOLDOWN_MS,
            idempotencyKey: `notify-verify:${userId}:${await sha256Hex(email)}:${now}`,
            payloadJson: JSON.stringify(payload),
            maxAttempts: 5
        });
        return { countdown: 60, taskId };
    }

    async enqueuePasswordReset(
        emailValue: string,
        siteNameValue: string,
        resetUrlValue: string,
        localeValue = ""
    ): Promise<{ taskId: number }> {
        const email = normalizeEmail(emailValue);
        const siteName = normalizeSiteName(siteNameValue);
        const resetUrl = normalizeResetUrl(resetUrlValue);
        const locale = normalizeLocale(localeValue);
        const token = this.#resetTokenFactory().trim().toLowerCase();
        if (!/^[a-f0-9]{64}$/u.test(token)) {
            throw new TypeError("reset token factory must return 32 random bytes as hexadecimal");
        }
        const now = this.#clock();
        const stateKey = await passwordResetStateKey(email);
        const state: PasswordResetEmailState = {
            tokenHash: await sha256Hex(token),
            secretEnvelope: await this.#cipher.seal(token),
            createdAt: now
        };
        const payload: AuthenticationEmailTaskPayload = {
            kind: "password_reset",
            email,
            siteName,
            locale,
            stateKey,
            resetUrl
        };
        const taskId = await this.#repository.createTask({
            stateKey,
            stateJson: JSON.stringify(state),
            expiresAt: now + RESET_TTL_MS,
            now,
            cooldownBefore: now - RESET_COOLDOWN_MS,
            idempotencyKey: `reset:${await sha256Hex(email)}:${now}`,
            payloadJson: JSON.stringify(payload),
            priority: 10,
            maxAttempts: 5
        });
        return { taskId };
    }
}

export async function verificationStateKey(email: string): Promise<string> {
    return `auth:verify-code:${await sha256Hex(email.trim().toLowerCase())}`;
}

export async function totpEmailStateKey(email: string): Promise<string> {
    return `auth:email-code:${await sha256Hex(email.trim().toLowerCase())}`;
}

export async function notificationEmailStateKey(userId: number, email: string): Promise<string> {
    return `auth:notify-email:${userId}:${await sha256Hex(email.trim().toLowerCase())}`;
}

export async function passwordResetStateKey(email: string): Promise<string> {
    return `auth:password-reset:${await sha256Hex(email.trim().toLowerCase())}`;
}

function randomVerificationCode(): string {
    const upperBound = Math.floor(0x1_0000_0000 / 1_000_000) * 1_000_000;
    const value = new Uint32Array(1);
    do {
        crypto.getRandomValues(value);
    } while (value[0] >= upperBound);
    return String(value[0] % 1_000_000).padStart(6, "0");
}

function normalizeEmail(value: string): string {
    const email = value.trim().toLowerCase();
    if (email.length === 0 || email.length > 254 || !/^[^\s@]+@[^\s@]+$/u.test(email)) {
        throw new TypeError("a valid email is required");
    }
    return email;
}

function normalizeSiteName(value: string): string {
    const siteName = value.trim();
    if (siteName.length === 0 || new TextEncoder().encode(siteName).byteLength > 256) {
        return "Sub2API";
    }
    return siteName;
}

function normalizeLocale(value: string): string {
    return value.trim().slice(0, 64);
}

function normalizeResetUrl(value: string): string {
    const resetUrl = value.trim();
    if (resetUrl.length === 0 || resetUrl.length > 2048) {
        throw new TypeError("password reset URL is not configured");
    }
    let parsed: URL;
    try {
        parsed = new URL(resetUrl);
    } catch {
        throw new TypeError("password reset URL is invalid");
    }
    if (parsed.protocol !== "https:" && parsed.hostname !== "localhost") {
        throw new TypeError("password reset URL must use HTTPS");
    }
    return parsed.toString();
}
