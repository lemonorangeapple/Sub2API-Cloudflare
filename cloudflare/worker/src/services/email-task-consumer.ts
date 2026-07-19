import { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import { D1SettingsRepository, type SettingsReader } from "../repositories/settings.ts";
import { D1TaskQueueRepository, type RuntimeTask } from "../repositories/task-queue.ts";
import type { D1Database } from "../types/d1.ts";
import type { EmailMessage, EmailSender, SmtpConfiguration } from "../types/email.ts";
import type { Clock, TokenFactory } from "../utils/runtime-validation.ts";
import type {
    AuthenticationEmailTaskPayload,
    EmailSecretCipher
} from "./email-task-producer.ts";
import { SmtpProtocolError } from "./smtp-email-sender.ts";

const EMAIL_QUEUE = "email";
const DEFAULT_BATCH_SIZE = 10;
const MAX_BATCH_SIZE = 50;
const CLAIM_TTL_MS = 2 * 60 * 1000;
const BASE_RETRY_DELAY_MS = 30 * 1000;
const MAX_RETRY_DELAY_MS = 15 * 60 * 1000;
const SMTP_SETTING_KEYS = [
    "smtp_host",
    "smtp_port",
    "smtp_username",
    "smtp_password",
    "smtp_from_email",
    "smtp_from_name",
    "smtp_use_tls"
] as const;

interface EmailConsumerOptions {
    clock?: Clock;
    tokenFactory?: TokenFactory;
    settings?: SettingsReader;
    owner?: string;
    batchSize?: number;
    smtpPassword?: string;
}

interface TaskPayload extends AuthenticationEmailTaskPayload {
    secretEnvelope?: string;
}

export interface EmailConsumerResult {
    claimed: number;
    sent: number;
    skipped: number;
    retried: number;
    failed: number;
}

export class AuthenticationEmailTaskConsumer {
    readonly #tasks: D1TaskQueueRepository;
    readonly #state: D1ExpiringStateRepository;
    readonly #settings: SettingsReader;
    readonly #cipher: EmailSecretCipher;
    readonly #sender: EmailSender;
    readonly #clock: Clock;
    readonly #owner: string;
    readonly #batchSize: number;
    readonly #smtpPassword: string | undefined;

    constructor(
        db: D1Database,
        cipher: EmailSecretCipher,
        sender: EmailSender,
        options: EmailConsumerOptions = {}
    ) {
        this.#clock = options.clock ?? Date.now;
        this.#tasks = new D1TaskQueueRepository(db, {
            clock: this.#clock,
            tokenFactory: options.tokenFactory
        });
        this.#state = new D1ExpiringStateRepository(db, { clock: this.#clock });
        this.#settings = options.settings ?? new D1SettingsRepository(db);
        this.#cipher = cipher;
        this.#sender = sender;
        this.#owner = normalizeOwner(options.owner ?? `email-cron:${crypto.randomUUID()}`);
        this.#batchSize = normalizeBatchSize(options.batchSize ?? DEFAULT_BATCH_SIZE);
        this.#smtpPassword = options.smtpPassword;
    }

    async processBatch(): Promise<EmailConsumerResult> {
        const result: EmailConsumerResult = {
            claimed: 0,
            sent: 0,
            skipped: 0,
            retried: 0,
            failed: 0
        };
        let configuration: SmtpConfiguration | null = null;

        for (let index = 0; index < this.#batchSize; index += 1) {
            const task = await this.#tasks.claimNext<TaskPayload>({
                queueName: EMAIL_QUEUE,
                owner: this.#owner,
                ttlMs: CLAIM_TTL_MS
            });
            if (task === null) {
                break;
            }
            result.claimed += 1;

            try {
                const payload = validatePayload(task.payload);
                const state = await this.#state.get<unknown>(payload.stateKey);
                if (state === null) {
                    await this.#complete(task, { outcome: "state_expired" });
                    result.skipped += 1;
                    continue;
                }

                const envelope = readSecretEnvelope(payload, state.value);
                let secret: string;
                try {
                    secret = await this.#cipher.open(envelope);
                } catch {
                    throw new RetryableEmailTaskError("email secret decryption failed");
                }
                validateSecret(payload.kind, secret);
                configuration ??= await this.#readConfiguration();
                const message = buildMessage(payload, secret, configuration);
                const delivery = await this.#sender.send(configuration, message);
                await this.#complete(task, {
                    outcome: "sent",
                    messageId: delivery.messageId,
                    deliveredAt: this.#clock()
                });
                result.sent += 1;
            } catch (error) {
                const permanent = isPermanentError(error);
                if (permanent) {
                    const changed = await this.#tasks.failPermanently({
                        taskId: task.id,
                        owner: this.#owner,
                        claimToken: requireClaimToken(task),
                        error: safeTaskError(error)
                    });
                    if (changed) {
                        result.failed += 1;
                    }
                    continue;
                }

                const status = await this.#tasks.fail({
                    taskId: task.id,
                    owner: this.#owner,
                    claimToken: requireClaimToken(task),
                    error: safeTaskError(error),
                    retryDelayMs: retryDelay(task.attempts)
                });
                if (status === "pending") {
                    result.retried += 1;
                } else if (status === "failed") {
                    result.failed += 1;
                }
            }
        }
        return result;
    }

    async #readConfiguration(): Promise<SmtpConfiguration> {
        let values: Record<string, string>;
        try {
            values = await this.#settings.getMany(SMTP_SETTING_KEYS);
        } catch {
            throw new RetryableEmailTaskError("SMTP settings could not be read");
        }
        const host = (values.smtp_host ?? "").trim();
        const from = (values.smtp_from_email ?? "").trim().toLowerCase();
        const portValue = (values.smtp_port ?? "").trim();
        const port = portValue === "" ? 587 : Number(portValue);
        if (host === "" || from === "") {
            throw new PermanentEmailTaskError("SMTP host and sender email must be configured");
        }
        if (!Number.isInteger(port) || port < 1 || port > 65_535) {
            throw new PermanentEmailTaskError("SMTP port is invalid");
        }
        if (port === 25) {
            throw new PermanentEmailTaskError("Cloudflare Workers cannot connect to SMTP port 25");
        }
        return {
            host,
            port,
            username: (values.smtp_username ?? "").trim(),
            password: (this.#smtpPassword ?? values.smtp_password ?? "").trim(),
            from,
            fromName: (values.smtp_from_name ?? "").trim(),
            useTls: (values.smtp_use_tls ?? "").trim().toLowerCase() === "true"
        };
    }

    async #complete(task: RuntimeTask<TaskPayload>, value: Record<string, unknown>): Promise<void> {
        const completed = await this.#tasks.complete({
            taskId: task.id,
            owner: this.#owner,
            claimToken: requireClaimToken(task),
            result: value
        });
        if (!completed) {
            throw new RetryableEmailTaskError("email task claim expired before completion");
        }
    }
}

class PermanentEmailTaskError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "PermanentEmailTaskError";
    }
}

class RetryableEmailTaskError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "RetryableEmailTaskError";
    }
}

function validatePayload(value: unknown): TaskPayload {
    if (!isRecord(value)) {
        throw new PermanentEmailTaskError("email task payload is invalid");
    }
    const kind = value.kind;
    const email = typeof value.email === "string" ? value.email.trim().toLowerCase() : "";
    const siteName = typeof value.siteName === "string" ? value.siteName.trim() : "";
    const locale = typeof value.locale === "string" ? value.locale.trim() : "";
    const stateKey = typeof value.stateKey === "string" ? value.stateKey.trim() : "";
    if (kind !== "verify_code" && kind !== "password_reset") {
        throw new PermanentEmailTaskError("email task kind is invalid");
    }
    if (email.length === 0 || email.length > 254 || !/^[^\s<>@]+@[^\s<>@]+$/u.test(email)) {
        throw new PermanentEmailTaskError("email task recipient is invalid");
    }
    if (siteName === "" || stateKey === "") {
        throw new PermanentEmailTaskError("email task payload is incomplete");
    }
    const payload: TaskPayload = { kind, email, siteName, locale, stateKey };
    if (typeof value.secretEnvelope === "string") {
        payload.secretEnvelope = value.secretEnvelope;
    }
    if (kind === "password_reset") {
        if (typeof value.resetUrl !== "string") {
            throw new PermanentEmailTaskError("password reset URL is missing");
        }
        try {
            const resetUrl = new URL(value.resetUrl);
            if (resetUrl.protocol !== "https:" && resetUrl.hostname !== "localhost") {
                throw new Error("insecure URL");
            }
            payload.resetUrl = resetUrl.toString();
        } catch {
            throw new PermanentEmailTaskError("password reset URL is invalid");
        }
    }
    return payload;
}

function readSecretEnvelope(payload: TaskPayload, state: unknown): string {
    if (payload.secretEnvelope !== undefined && payload.secretEnvelope !== "") {
        return payload.secretEnvelope;
    }
    if (isRecord(state) && typeof state.secretEnvelope === "string") {
        const envelope = state.secretEnvelope;
        if (envelope !== "") {
            return envelope;
        }
    }
    throw new PermanentEmailTaskError("email task secret envelope is missing");
}

function validateSecret(kind: TaskPayload["kind"], secret: string): void {
    const valid = kind === "verify_code"
        ? /^\d{6}$/u.test(secret)
        : /^[a-f0-9]{64}$/u.test(secret);
    if (!valid) {
        throw new PermanentEmailTaskError("email task secret is invalid");
    }
}

function buildMessage(
    payload: TaskPayload,
    secret: string,
    configuration: SmtpConfiguration
): EmailMessage {
    const siteName = escapeHtml(payload.siteName);
    if (payload.kind === "verify_code") {
        return {
            to: payload.email,
            from: configuration.from,
            fromName: configuration.fromName,
            subject: `[${payload.siteName}] Email Verification Code`,
            text: `Your ${payload.siteName} verification code is ${secret}. It expires in 15 minutes.`,
            html: `<!doctype html><html><body><h1>${siteName}</h1><p>Your verification code is:</p><p><strong>${secret}</strong></p><p>This code expires in 15 minutes.</p></body></html>`
        };
    }

    const resetUrl = new URL(payload.resetUrl as string);
    resetUrl.searchParams.set("email", payload.email);
    resetUrl.searchParams.set("token", secret);
    const safeResetUrl = escapeHtml(resetUrl.toString());
    return {
        to: payload.email,
        from: configuration.from,
        fromName: configuration.fromName,
        subject: `[${payload.siteName}] 密码重置请求`,
        text: `Use this link to reset your ${payload.siteName} password within 30 minutes: ${resetUrl}`,
        html: `<!doctype html><html><body><h1>${siteName}</h1><p>请在 30 分钟内使用以下链接重置密码：</p><p><a href="${safeResetUrl}">重置密码</a></p><p>如果这不是你的操作，请忽略此邮件。</p></body></html>`
    };
}

function escapeHtml(value: string): string {
    return value
        .replace(/&/gu, "&amp;")
        .replace(/</gu, "&lt;")
        .replace(/>/gu, "&gt;")
        .replace(/"/gu, "&quot;")
        .replace(/'/gu, "&#39;");
}

function retryDelay(attempts: number): number {
    return Math.min(BASE_RETRY_DELAY_MS * (2 ** Math.max(0, attempts - 1)), MAX_RETRY_DELAY_MS);
}

function safeTaskError(error: unknown): string {
    if (error instanceof PermanentEmailTaskError || error instanceof RetryableEmailTaskError) {
        return error.message;
    }
    if (error instanceof SmtpProtocolError) {
        return error.message;
    }
    return "SMTP delivery failed";
}

function isPermanentError(error: unknown): boolean {
    return error instanceof PermanentEmailTaskError
        || (error instanceof SmtpProtocolError && !error.retryable);
}

function requireClaimToken(task: RuntimeTask<unknown>): string {
    if (task.claimToken === null) {
        throw new Error("claimed email task has no claim token");
    }
    return task.claimToken;
}

function normalizeOwner(value: string): string {
    const owner = value.trim();
    if (owner === "" || owner.length > 256) {
        throw new TypeError("email consumer owner is invalid");
    }
    return owner;
}

function normalizeBatchSize(value: number): number {
    if (!Number.isInteger(value) || value < 1 || value > MAX_BATCH_SIZE) {
        throw new RangeError(`email consumer batch size must be between 1 and ${MAX_BATCH_SIZE}`);
    }
    return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
