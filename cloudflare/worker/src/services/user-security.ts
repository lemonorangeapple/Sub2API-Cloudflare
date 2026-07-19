import type { D1AuthUserRepository } from "../repositories/auth-users.ts";
import type { D1SecurityMutationRepository } from "../repositories/security-mutations.ts";
import type { AuthUserRecord, AuthUserResponse } from "../types/auth.ts";
import { randomHex, sha256Hex } from "../utils/crypto.ts";
import type { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import { mapAuthUser } from "./auth-user.ts";
import type { PasswordHasher } from "./password.ts";

const PASSWORD_RESET_TTL_MS = 30 * 60 * 1000;

export type UserSecurityErrorCode =
    | "invalid_request"
    | "password_incorrect"
    | "user_not_found"
    | "user_inactive"
    | "admin_required"
    | "cannot_disable_admin"
    | "cannot_demote_self"
    | "cannot_demote_last_admin"
    | "cannot_delete_admin"
    | "email_conflict"
    | "security_state_changed"
    | "invalid_reset_token"
    | "unsupported_update_fields";

export class UserSecurityError extends Error {
    readonly code: UserSecurityErrorCode;
    readonly status: number;

    constructor(code: UserSecurityErrorCode, status: number, message: string) {
        super(message);
        this.name = "UserSecurityError";
        this.code = code;
        this.status = status;
    }
}

export interface AdminSecurityUpdateInput {
    email?: string;
    password?: string;
    role?: "admin" | "user";
    status?: "active" | "disabled";
}

export interface AdminSecurityUserResponse extends AuthUserResponse {
    notes: string;
}

export class UserSecurityService {
    readonly #users: D1AuthUserRepository;
    readonly #mutations: D1SecurityMutationRepository;
    readonly #passwords: PasswordHasher;
    readonly #state: D1ExpiringStateRepository;
    readonly #clock: () => number;

    constructor(
        users: D1AuthUserRepository,
        mutations: D1SecurityMutationRepository,
        passwords: PasswordHasher,
        state: D1ExpiringStateRepository,
        clock: () => number = Date.now
    ) {
        this.#users = users;
        this.#mutations = mutations;
        this.#passwords = passwords;
        this.#state = state;
        this.#clock = clock;
    }

    async changePassword(
        user: AuthUserRecord,
        oldPassword: string,
        newPassword: string
    ): Promise<{ message: string }> {
        validatePassword(oldPassword, "old_password", 1);
        validatePassword(newPassword, "new_password", 6);
        if (!await this.#passwords.verify(oldPassword, user.passwordHash)) {
            throw new UserSecurityError("password_incorrect", 400, "Current password is incorrect");
        }
        const newHash = await this.#passwords.hash(newPassword);
        const now = this.#clock();
        const changed = await this.#mutations.changePassword({
            userId: user.id,
            expectedPasswordHash: user.passwordHash,
            newPasswordHash: newHash,
            updatedAt: new Date(now).toISOString(),
            revokedAt: now
        });
        if (!changed) {
            throw new UserSecurityError(
                "security_state_changed",
                409,
                "User security state changed; retry with the current password"
            );
        }
        return { message: "Password changed successfully" };
    }

    async createPasswordResetToken(emailValue: string): Promise<string> {
        const email = normalizeEmail(emailValue);
        const token = randomHex(32);
        const hash = await sha256Hex(token);
        await this.#state.put(await passwordResetStateKey(email), hash, PASSWORD_RESET_TTL_MS);
        return token;
    }

    async resetPassword(
        emailValue: string,
        tokenValue: string,
        newPassword: string
    ): Promise<{ message: string }> {
        const email = normalizeEmail(emailValue);
        const token = tokenValue.trim().toLowerCase();
        if (!/^[a-f0-9]{64}$/u.test(token)) {
            throw invalidResetToken();
        }
        validatePassword(newPassword, "new_password", 6);
        const newHash = await this.#passwords.hash(newPassword);
        const now = this.#clock();
        const stateKey = await passwordResetStateKey(email);
        const stored = await this.#state.get<string | { tokenHash?: string }>(stateKey);
        const storedHash = typeof stored?.value === "string"
            ? stored.value
            : stored?.value.tokenHash;
        const stateHash = await sha256Hex(token);
        if (typeof storedHash !== "string" || !constantTimeHexEqual(storedHash, stateHash)) {
            throw invalidResetToken();
        }
        const changed = await this.#mutations.resetPassword({
            normalizedEmail: email,
            stateKey,
            expectedStateJson: JSON.stringify(stored?.value),
            newPasswordHash: newHash,
            updatedAt: new Date(now).toISOString(),
            now
        });
        if (!changed) {
            throw invalidResetToken();
        }
        return {
            message: "Your password has been reset successfully. You can now log in with your new password."
        };
    }

    async updateAdminSecurity(
        actor: AuthUserRecord,
        targetUserId: number,
        input: AdminSecurityUpdateInput
    ): Promise<AdminSecurityUserResponse> {
        requireAdmin(actor);
        requirePositiveId(targetUserId);
        const target = await this.#users.findById(targetUserId);
        if (target === null) {
            throw new UserSecurityError("user_not_found", 404, "User not found");
        }

        const email = input.email === undefined ? null : normalizeEmail(input.email);
        const role = input.role ?? null;
        const status = input.status ?? null;
        validateRole(role);
        validateStatus(status);
        if (target.role === "admin" && status === "disabled") {
            throw new UserSecurityError("cannot_disable_admin", 400, "cannot disable admin user");
        }
        if (target.id === actor.id && target.role === "admin" && role === "user") {
            throw new UserSecurityError("cannot_demote_self", 400, "cannot demote yourself from admin");
        }
        if (target.role === "admin" && role === "user" && await this.#users.countActiveAdmins() <= 1) {
            throw new UserSecurityError(
                "cannot_demote_last_admin",
                400,
                "cannot demote the last admin user"
            );
        }
        if (email !== null) {
            const owner = await this.#users.findByEmail(email);
            if (owner !== null && owner.id !== target.id) {
                throw new UserSecurityError("email_conflict", 409, "Email is already in use");
            }
        }

        let newPasswordHash: string | null = null;
        if (input.password !== undefined) {
            validatePassword(input.password, "password", 6);
            newPasswordHash = await this.#passwords.hash(input.password);
        }
        const changedFields =
            (email !== null && email !== normalizeEmail(target.email))
            || (role !== null && role !== target.role)
            || (status !== null && status !== target.status)
            || newPasswordHash !== null;
        if (!changedFields) {
            return mapAdminUser(target);
        }

        const now = this.#clock();
        const updated = await this.#mutations.updateAdminSecurity({
            actorAdminId: actor.id,
            targetUserId: target.id,
            expectedUpdatedAt: target.updatedAt,
            newEmail: email,
            newPasswordHash,
            newRole: role,
            newStatus: status,
            updatedAt: new Date(now).toISOString(),
            revokedAt: now,
            blockDisableAdmin: target.role === "admin" && status === "disabled",
            blockSelfDemotion: target.id === actor.id && target.role === "admin" && role === "user",
            requireOtherAdmin: target.role === "admin" && role === "user"
        });
        if (!updated) {
            throw new UserSecurityError(
                "security_state_changed",
                409,
                "User security state changed or a safety guard rejected the update"
            );
        }
        const result = await this.#users.findById(target.id);
        if (result === null) {
            throw new UserSecurityError("user_not_found", 404, "User not found");
        }
        return mapAdminUser(result);
    }

    async deleteUser(actor: AuthUserRecord, targetUserId: number): Promise<{ message: string }> {
        requireAdmin(actor);
        requirePositiveId(targetUserId);
        const target = await this.#users.findById(targetUserId);
        if (target === null) {
            throw new UserSecurityError("user_not_found", 404, "User not found");
        }
        if (target.role === "admin") {
            throw new UserSecurityError("cannot_delete_admin", 400, "cannot delete admin user");
        }
        const now = this.#clock();
        const deleted = await this.#mutations.softDeleteUser(
            target.id,
            new Date(now).toISOString(),
            now
        );
        if (!deleted) {
            throw new UserSecurityError(
                "security_state_changed",
                409,
                "User security state changed before deletion"
            );
        }
        return { message: "User deleted successfully" };
    }

    async restoreUserInternal(targetUserId: number): Promise<boolean> {
        requirePositiveId(targetUserId);
        return this.#mutations.restoreUser(
            targetUserId,
            new Date(this.#clock()).toISOString()
        );
    }
}

export function assertOnlySecurityUpdateFields(body: Record<string, unknown>): void {
    const allowed = new Set(["email", "password", "role", "status"]);
    const unsupported = Object.keys(body).filter((key) => !allowed.has(key));
    if (unsupported.length > 0) {
        throw new UserSecurityError(
            "unsupported_update_fields",
            409,
            `Security staging does not own fields: ${unsupported.sort().join(", ")}`
        );
    }
}

function mapAdminUser(user: AuthUserRecord): AdminSecurityUserResponse {
    return {
        ...mapAuthUser(user),
        notes: user.notes
    };
}

function normalizeEmail(value: string): string {
    const email = value.trim().toLowerCase();
    if (email.length === 0 || email.length > 254 || !/^[^\s@]+@[^\s@]+$/u.test(email)) {
        throw new UserSecurityError("invalid_request", 400, "A valid email is required");
    }
    return email;
}

function validatePassword(value: string, field: string, minimumLength: number): void {
    const byteLength = new TextEncoder().encode(value).byteLength;
    if (value.length < minimumLength || byteLength > 72) {
        throw new UserSecurityError(
            "invalid_request",
            400,
            `${field} must be at least ${minimumLength} characters and at most 72 UTF-8 bytes`
        );
    }
}

function validateRole(role: string | null): void {
    if (role !== null && role !== "admin" && role !== "user") {
        throw new UserSecurityError("invalid_request", 400, "role must be admin or user");
    }
}

function validateStatus(status: string | null): void {
    if (status !== null && status !== "active" && status !== "disabled") {
        throw new UserSecurityError("invalid_request", 400, "status must be active or disabled");
    }
}

function requireAdmin(user: AuthUserRecord): void {
    if (user.role !== "admin") {
        throw new UserSecurityError("admin_required", 403, "Administrator access is required");
    }
}

function requirePositiveId(value: number): void {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new UserSecurityError("invalid_request", 400, "Invalid user ID");
    }
}

async function passwordResetStateKey(email: string): Promise<string> {
    return `auth:password-reset:${await sha256Hex(email)}`;
}

function constantTimeHexEqual(left: string, right: string): boolean {
    if (left.length !== right.length) {
        return false;
    }
    let difference = 0;
    for (let index = 0; index < left.length; index += 1) {
        difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
    }
    return difference === 0;
}

function invalidResetToken(): UserSecurityError {
    return new UserSecurityError(
        "invalid_reset_token",
        400,
        "invalid or expired password reset token"
    );
}
