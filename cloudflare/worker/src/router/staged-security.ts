import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { D1CoordinationRepository } from "../repositories/runtime-coordination.ts";
import { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import { D1SecurityMutationRepository } from "../repositories/security-mutations.ts";
import { D1SettingsRepository } from "../repositories/settings.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import { BcryptPasswordService, type PasswordHasher } from "../services/password.ts";
import {
    AesGcmTotpSecretDecryptor,
    type TotpSecretCipher
} from "../services/totp.ts";
import {
    TotpManagementError,
    TotpManagementService
} from "../services/totp-management.ts";
import {
    assertOnlySecurityUpdateFields,
    UserSecurityError,
    UserSecurityService,
    type AdminSecurityUpdateInput
} from "../services/user-security.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
    routerError
} from "./responses.ts";

export const STAGED_SECURITY_PATHS = {
    changePassword: "/api/v1/user/password",
    resetPassword: "/api/v1/auth/reset-password",
    totpStatus: "/api/v1/user/totp/status",
    totpVerificationMethod: "/api/v1/user/totp/verification-method",
    totpSetup: "/api/v1/user/totp/setup",
    totpEnable: "/api/v1/user/totp/enable",
    totpDisable: "/api/v1/user/totp/disable"
} as const;

const SECURITY_SETTING_KEYS = [
    "password_reset_enabled",
    "totp_enabled",
    "email_verify_enabled"
] as const;

const ADMIN_USER_PATH = /^\/api\/v1\/admin\/users\/(\d+)$/u;

export interface StagedSecurityEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
    TOTP_ENCRYPTION_KEY?: string;
}

export interface StagedSecurityDependencies {
    clock?: () => number;
    passwordHasher?: PasswordHasher;
    totpCipher?: TotpSecretCipher;
}

export async function routeStagedSecurity(
    request: Request,
    env: StagedSecurityEnv,
    dependencies: StagedSecurityDependencies = {}
): Promise<Response | null> {
    const path = new URL(request.url).pathname;
    const adminMatch = ADMIN_USER_PATH.exec(path);
    const isKnownPath = Object.values(STAGED_SECURITY_PATHS).includes(
        path as typeof STAGED_SECURITY_PATHS[keyof typeof STAGED_SECURITY_PATHS]
    ) || adminMatch !== null;
    if (!isKnownPath) {
        return null;
    }
    if (env.DB === undefined) {
        return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");
    }

    if (adminMatch !== null) {
        if (request.method !== "PUT" && request.method !== "DELETE") {
            return routerError(
                405,
                "method_not_allowed",
                `${path} requires PUT or DELETE`,
                { allow: "PUT, DELETE" }
            );
        }
    } else {
        const expectedMethod = methodFor(path);
        if (request.method !== expectedMethod) {
            return routerError(
                405,
                "method_not_allowed",
                `${path} requires ${expectedMethod}`,
                { allow: expectedMethod }
            );
        }
    }

    const clock = dependencies.clock ?? Date.now;
    const users = new D1AuthUserRepository(env.DB);
    const sessions = new D1AuthSessionRepository(env.DB);
    const state = new D1ExpiringStateRepository(env.DB, { clock });
    const coordination = new D1CoordinationRepository(env.DB, { clock });
    const mutations = new D1SecurityMutationRepository(env.DB);
    const passwordHasher = dependencies.passwordHasher ?? new BcryptPasswordService();
    const security = new UserSecurityService(
        users,
        mutations,
        passwordHasher,
        state,
        clock
    );

    try {
        if (path === STAGED_SECURITY_PATHS.resetPassword) {
            const settings = await new D1SettingsRepository(env.DB).getMany(SECURITY_SETTING_KEYS);
            if (settings.password_reset_enabled !== "true") {
                return legacyError(403, "password reset is not enabled", "PASSWORD_RESET_DISABLED");
            }
            const body = await requiredJsonBody(request);
            return legacySuccess(await security.resetPassword(
                stringField(body, "email"),
                stringField(body, "token"),
                stringField(body, "new_password")
            ));
        }

        const access = createAccessService(env, users, sessions, clock);
        const authenticated = await access.authenticateAuthorization(
            request.headers.get("authorization")
        );

        if (path === STAGED_SECURITY_PATHS.changePassword) {
            const body = await requiredJsonBody(request);
            return legacySuccess(await security.changePassword(
                authenticated.user,
                stringField(body, "old_password"),
                stringField(body, "new_password")
            ));
        }

        if (adminMatch !== null) {
            const targetUserId = Number(adminMatch[1]);
            if (request.method === "DELETE") {
                return legacySuccess(await security.deleteUser(
                    authenticated.user,
                    targetUserId
                ));
            }
            const body = await requiredJsonBody(request);
            assertOnlySecurityUpdateFields(body);
            return legacySuccess(await security.updateAdminSecurity(
                authenticated.user,
                targetUserId,
                adminSecurityInput(body)
            ));
        }

        const settings = await new D1SettingsRepository(env.DB).getMany(SECURITY_SETTING_KEYS);
        const featureEnabled = settings.totp_enabled === "true";
        const emailVerificationEnabled = settings.email_verify_enabled === "true";

        if (path === STAGED_SECURITY_PATHS.totpStatus) {
            return legacySuccess({
                enabled: authenticated.user.totpEnabled,
                enabled_at: authenticated.user.totpEnabledAt === null
                    ? null
                    : Math.floor(Date.parse(authenticated.user.totpEnabledAt) / 1000),
                feature_enabled: featureEnabled
            });
        }
        if (path === STAGED_SECURITY_PATHS.totpVerificationMethod) {
            return legacySuccess({
                method: emailVerificationEnabled ? "email" : "password"
            });
        }

        const cipher = dependencies.totpCipher ?? createTotpCipher(env);
        const totp = new TotpManagementService(
            users,
            state,
            coordination,
            mutations,
            passwordHasher,
            cipher,
            clock
        );
        const body = await optionalJsonBody(request);
        if (path === STAGED_SECURITY_PATHS.totpSetup) {
            return legacySuccess(await totp.initiateSetup(
                authenticated.user,
                {
                    emailCode: optionalString(body, "email_code"),
                    password: optionalString(body, "password")
                },
                featureEnabled,
                emailVerificationEnabled
            ));
        }
        if (path === STAGED_SECURITY_PATHS.totpEnable) {
            return legacySuccess(await totp.enable(
                authenticated.user,
                stringField(body, "totp_code"),
                stringField(body, "setup_token")
            ));
        }
        return legacySuccess(await totp.disable(
            authenticated.user,
            {
                emailCode: optionalString(body, "email_code"),
                password: optionalString(body, "password")
            },
            emailVerificationEnabled
        ));
    } catch (error) {
        return securityFailure(error);
    }
}

function createAccessService(
    env: StagedSecurityEnv,
    users: D1AuthUserRepository,
    sessions: D1AuthSessionRepository,
    clock: () => number
): AccessAuthService {
    const secret = env.JWT_SECRET?.trim() ?? "";
    if (!secret) {
        throw new SecurityConfigurationError("JWT secret is not configured");
    }
    const accessSeconds = boundedIntegerEnv(
        env.JWT_ACCESS_TOKEN_EXPIRES_SECONDS,
        24 * 60 * 60,
        1,
        7 * 24 * 60 * 60
    );
    const refreshDays = boundedIntegerEnv(env.JWT_REFRESH_TOKEN_EXPIRE_DAYS, 30, 1, 365);
    const signer = new Hs256JwtSigner(secret, accessSeconds, clock);
    const verifier = new Hs256JwtVerifier(secret, clock);
    const tokens = new AuthTokenService(sessions, signer, refreshDays, clock);
    return new AccessAuthService(users, verifier, tokens, clock);
}

function createTotpCipher(env: StagedSecurityEnv): TotpSecretCipher {
    const key = env.TOTP_ENCRYPTION_KEY?.trim() ?? "";
    if (!key) {
        throw new SecurityConfigurationError("TOTP encryption key is not configured");
    }
    try {
        return new AesGcmTotpSecretDecryptor(key);
    } catch {
        throw new SecurityConfigurationError("TOTP encryption key is invalid");
    }
}

function methodFor(path: string): "GET" | "POST" | "PUT" {
    if (
        path === STAGED_SECURITY_PATHS.totpStatus
        || path === STAGED_SECURITY_PATHS.totpVerificationMethod
    ) {
        return "GET";
    }
    if (path === STAGED_SECURITY_PATHS.changePassword) {
        return "PUT";
    }
    return "POST";
}

function adminSecurityInput(body: Record<string, unknown>): AdminSecurityUpdateInput {
    return {
        ...(body.email === undefined ? {} : { email: stringField(body, "email") }),
        ...(body.password === undefined ? {} : { password: stringField(body, "password") }),
        ...(body.role === undefined ? {} : { role: stringField(body, "role") as "admin" | "user" }),
        ...(body.status === undefined ? {} : { status: stringField(body, "status") as "active" | "disabled" })
    };
}

async function requiredJsonBody(request: Request): Promise<Record<string, unknown>> {
    let value: unknown;
    try {
        value = await request.json();
    } catch {
        throw new UserSecurityError("invalid_request", 400, "Invalid request body");
    }
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new UserSecurityError("invalid_request", 400, "Invalid request body");
    }
    return value as Record<string, unknown>;
}

async function optionalJsonBody(request: Request): Promise<Record<string, unknown>> {
    const text = await request.text();
    if (text.trim().length === 0) {
        return {};
    }
    try {
        const value: unknown = JSON.parse(text);
        if (value === null || typeof value !== "object" || Array.isArray(value)) {
            throw new TypeError();
        }
        return value as Record<string, unknown>;
    } catch {
        throw new UserSecurityError("invalid_request", 400, "Invalid request body");
    }
}

function stringField(body: Record<string, unknown>, key: string): string {
    const value = body[key];
    if (typeof value !== "string") {
        throw new UserSecurityError("invalid_request", 400, `${key} is required`);
    }
    return value;
}

function optionalString(body: Record<string, unknown>, key: string): string | undefined {
    const value = body[key];
    if (value === undefined || value === null) {
        return undefined;
    }
    if (typeof value !== "string") {
        throw new UserSecurityError("invalid_request", 400, `${key} must be a string`);
    }
    return value;
}

function securityFailure(error: unknown): Response {
    if (error instanceof AccessAuthError) {
        return middlewareAuthError(error.status, error.code, error.message);
    }
    if (error instanceof UserSecurityError || error instanceof TotpManagementError) {
        return legacyError(error.status, error.message, error.code.toUpperCase());
    }
    if (error instanceof SecurityConfigurationError) {
        return legacyError(503, error.message, "SECURITY_NOT_CONFIGURED");
    }
    return legacyInternalError();
}

function boundedIntegerEnv(
    raw: string | undefined,
    fallback: number,
    minimum: number,
    maximum: number
): number {
    if (raw === undefined || raw.trim() === "") {
        return fallback;
    }
    const value = Number(raw);
    if (!Number.isInteger(value) || value < minimum || value > maximum) {
        throw new SecurityConfigurationError("Authentication lifetime configuration is invalid");
    }
    return value;
}

class SecurityConfigurationError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "SecurityConfigurationError";
    }
}
