import type { D1AuthUserRepository } from "../repositories/auth-users.ts";
import type { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import type { D1UserProfileRepository, UserAvatarMutation } from "../repositories/user-profile.ts";
import type { AuthUserRecord } from "../types/auth.ts";
import {
    notificationEmailStateKey,
    type VerificationEmailState
} from "./email-task-producer.ts";
import { base64Decode, sha256Hex } from "../utils/crypto.ts";

export interface UserProfileUpdateInput {
    username?: string;
    avatarUrl?: string | null;
    balanceNotifyEnabled?: boolean;
    balanceNotifyThreshold?: number | null;
}

export class UserProfileManagementError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "UserProfileManagementError";
        this.code = code;
        this.status = status;
    }
}

export class D1UserProfileManagementService {
    readonly #users: D1AuthUserRepository;
    readonly #repository: D1UserProfileRepository;
    readonly #clock: () => number;
    readonly #state: D1ExpiringStateRepository | null;

    constructor(
        users: D1AuthUserRepository,
        repository: D1UserProfileRepository,
        state: D1ExpiringStateRepository | null = null,
        clock: () => number = Date.now
    ) {
        this.#users = users;
        this.#repository = repository;
        this.#state = state;
        this.#clock = clock;
    }

    async update(userId: number, input: UserProfileUpdateInput): Promise<AuthUserRecord> {
        const username = input.username === undefined ? undefined : bounded(input.username, 100);
        const threshold = input.balanceNotifyThreshold === undefined
            ? undefined
            : input.balanceNotifyThreshold === null || input.balanceNotifyThreshold <= 0
                ? null
                : finiteThreshold(input.balanceNotifyThreshold);
        const avatar = input.avatarUrl === undefined ? undefined : await normalizeAvatar(input.avatarUrl ?? "");
        await this.#repository.update({
            userId,
            updatedAt: new Date(this.#clock()).toISOString(),
            ...(username === undefined ? {} : { username }),
            ...(input.balanceNotifyEnabled === undefined
                ? {} : { balanceNotifyEnabled: input.balanceNotifyEnabled }),
            ...(threshold === undefined ? {} : { balanceNotifyThreshold: threshold }),
            ...(avatar === undefined ? {} : { avatar })
        });
        const user = await this.#users.findById(userId);
        if (user === null) throw new UserProfileManagementError("user_not_found", 404, "User not found");
        return user;
    }

    async verifyAndAddNotificationEmail(userId: number, emailValue: string, codeValue: string): Promise<AuthUserRecord> {
        if (this.#state === null) throw new UserProfileManagementError("profile_not_configured", 503, "Profile verification is not configured");
        const email = normalizeEmail(emailValue);
        const code = codeValue.trim();
        if (!/^\d{6}$/u.test(code)) throw invalidVerificationCode();
        const key = await notificationEmailStateKey(userId, email);
        const stored = await this.#state.get<VerificationEmailState>(key);
        if (stored === null || stored.value.attempts >= 5) {
            throw stored?.value.attempts === 5
                ? new UserProfileManagementError("verify_code_max_attempts", 429, "Too many failed attempts")
                : invalidVerificationCode();
        }
        if (!constantTimeHexEqual(stored.value.codeHash, await sha256Hex(code))) {
            const attempts = stored.value.attempts + 1;
            await this.#state.compareAndSwap(key, stored.value, { ...stored.value, attempts });
            throw attempts >= 5
                ? new UserProfileManagementError("verify_code_max_attempts", 429, "Too many failed attempts")
                : invalidVerificationCode();
        }
        const user = await this.#requireUser(userId);
        const entries = notificationEntries(user.balanceNotifyExtraEmails);
        const existing = entries.find((entry) => entry.email.toLowerCase() === email);
        if (existing === undefined) {
            if (entries.length >= 3) {
                throw new UserProfileManagementError("too_many_notify_emails", 400, "Maximum 3 notification emails allowed");
            }
            entries.push({ email, disabled: false, verified: true });
        } else {
            existing.verified = true;
        }
        const consumed = await this.#repository.consumeNotificationVerification(
            userId,
            user.updatedAt,
            entries,
            key,
            JSON.stringify(stored.value),
            this.#clock()
        );
        if (!consumed) throw new UserProfileManagementError("profile_conflict", 409, "Profile changed; retry verification");
        return this.#requireUser(userId);
    }

    async removeNotificationEmail(userId: number, emailValue: string): Promise<AuthUserRecord> {
        const email = normalizeEmail(emailValue);
        return this.#mutateNotificationEmails(userId, (entries) => {
            const index = entries.findIndex((entry) => entry.email.toLowerCase() === email);
            if (index < 0) throw new UserProfileManagementError("email_not_found", 400, "Notification email not found");
            entries.splice(index, 1);
        });
    }

    async toggleNotificationEmail(
        userId: number,
        emailValue: string,
        disabled: boolean
    ): Promise<AuthUserRecord> {
        const email = emailValue.trim().toLowerCase();
        if (email !== "") normalizeEmail(email);
        return this.#mutateNotificationEmails(userId, (entries) => {
            const entry = entries.find((item) => item.email.toLowerCase() === email);
            if (entry === undefined) {
                throw new UserProfileManagementError("email_not_found", 400, "Notification email not found");
            }
            entry.disabled = disabled;
        });
    }

    async #mutateNotificationEmails(
        userId: number,
        mutation: (entries: NotificationEmailEntry[]) => void
    ): Promise<AuthUserRecord> {
        for (let attempt = 0; attempt < 3; attempt += 1) {
            const user = await this.#requireUser(userId);
            const entries = notificationEntries(user.balanceNotifyExtraEmails);
            mutation(entries);
            if (await this.#repository.updateNotificationEmails(
                userId,
                user.updatedAt,
                entries,
                new Date(this.#clock() + attempt).toISOString()
            )) return this.#requireUser(userId);
        }
        throw new UserProfileManagementError("profile_conflict", 409, "Profile changed; retry the request");
    }

    async #requireUser(userId: number): Promise<AuthUserRecord> {
        const user = await this.#users.findById(userId);
        if (user === null) throw new UserProfileManagementError("user_not_found", 404, "User not found");
        return user;
    }
}

interface NotificationEmailEntry {
    email: string;
    disabled: boolean;
    verified: boolean;
}

function notificationEntries(value: unknown[]): NotificationEmailEntry[] {
    const entries: NotificationEmailEntry[] = [];
    for (const item of value) {
        if (item === null || typeof item !== "object" || Array.isArray(item)) continue;
        const record = item as Record<string, unknown>;
        if (typeof record.email !== "string") continue;
        const email = record.email.trim().toLowerCase();
        if (email !== "" && !/^[^\s@]+@[^\s@]+$/u.test(email)) continue;
        if (entries.some((entry) => entry.email.toLowerCase() === email)) continue;
        entries.push({
            email,
            disabled: record.disabled === true,
            verified: record.verified === true
        });
    }
    return entries;
}

async function normalizeAvatar(rawValue: string): Promise<UserAvatarMutation | null> {
    const raw = rawValue.trim();
    if (raw === "") return null;
    if (raw.startsWith("data:")) return inlineAvatar(raw);
    let url: URL;
    try { url = new URL(raw); } catch { throw invalidAvatar(); }
    if (!/^https?:$/u.test(url.protocol) || url.host === "" || raw.length > 8192) throw invalidAvatar();
    return {
        storageProvider: "remote_url",
        url: raw,
        contentType: "",
        byteSize: 0,
        sha256: ""
    };
}

async function inlineAvatar(raw: string): Promise<UserAvatarMutation> {
    const match = /^data:(image\/[A-Za-z0-9.+-]+);base64,([A-Za-z0-9+/=]+)$/u.exec(raw);
    if (match === null) throw invalidAvatar();
    let bytes: Uint8Array;
    try { bytes = base64Decode(match[2]); } catch { throw invalidAvatar(); }
    if (bytes.length === 0 || bytes.length > 100 * 1024) {
        throw new UserProfileManagementError("avatar_too_large", 400, "Avatar exceeds 100 KiB");
    }
    return {
        storageProvider: "inline",
        url: raw,
        contentType: match[1].toLowerCase(),
        byteSize: bytes.length,
        sha256: await sha256Hex(bytes)
    };
}

function finiteThreshold(value: number): number {
    if (!Number.isFinite(value)) {
        throw new UserProfileManagementError("profile_invalid", 400, "Balance notification threshold is invalid");
    }
    return value;
}

function normalizeEmail(value: string): string {
    const email = value.trim().toLowerCase();
    if (email.length === 0 || email.length > 254 || !/^[^\s@]+@[^\s@]+$/u.test(email)) {
        throw new UserProfileManagementError("email_invalid", 400, "A valid email is required");
    }
    return email;
}

function constantTimeHexEqual(left: string, right: string): boolean {
    if (left.length !== right.length || !/^[a-f0-9]+$/iu.test(left) || !/^[a-f0-9]+$/iu.test(right)) {
        return false;
    }
    let difference = 0;
    for (let index = 0; index < left.length; index += 1) {
        difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
    }
    return difference === 0;
}

function invalidVerificationCode(): UserProfileManagementError {
    return new UserProfileManagementError("invalid_verify_code", 400, "Invalid or expired verification code");
}

function bounded(value: string, maximum: number): string {
    const text = value.trim();
    if ([...text].length > maximum) {
        throw new UserProfileManagementError("profile_invalid", 400, `Username exceeds ${maximum} characters`);
    }
    return text;
}

function invalidAvatar(): UserProfileManagementError {
    return new UserProfileManagementError("avatar_invalid", 400, "Avatar must be an HTTP(S) URL or base64 image");
}
