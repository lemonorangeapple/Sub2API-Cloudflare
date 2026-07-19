import { D1AuthEmailRepository, EmailCooldownError } from "../repositories/auth-email.ts";
import { D1AdminAuthIdentityRepository } from "../repositories/admin-auth-identities.ts";
import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import { D1IdentityBindingRepository } from "../repositories/identity-bindings.ts";
import { D1CoordinationRepository } from "../repositories/runtime-coordination.ts";
import { D1SettingsRepository } from "../repositories/settings.ts";
import { D1UserManagementRepository } from "../repositories/user-management.ts";
import { D1UserProfileRepository } from "../repositories/user-profile.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import {
    AdminAuthIdentityError,
    D1AdminAuthIdentityService,
    type AdminBindAuthIdentityInput
} from "../services/admin-auth-identities.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import {
    AesGcmEmailSecretCipher,
    AuthenticationEmailTaskProducer,
    type EmailSecretCipher
} from "../services/email-task-producer.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import { D1IdentityBindingService, IdentityBindingError } from "../services/identity-bindings.ts";
import { BcryptPasswordService, type PasswordHasher } from "../services/password.ts";
import { TurnstileVerificationError, TurnstileVerifier } from "../services/turnstile.ts";
import {
    D1UserManagementService,
    UserManagementError,
    type AdminCreateUserInput,
    type AdminUpdateUserInput,
    type RegistrationInput
} from "../services/user-management.ts";
import {
    D1UserProfileManagementService,
    UserProfileManagementError,
    type UserProfileUpdateInput
} from "../services/user-profile-management.ts";
import { UserProfileService } from "../services/user-profile.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
    routerError
} from "./responses.ts";

export const SETUP_INSTALL_PATH = "/setup/install";

export const STAGED_USER_DOMAIN_PATHS = {
    register: "/api/v1/auth/register",
    sendVerifyCode: "/api/v1/auth/send-verify-code",
    forgotPassword: "/api/v1/auth/forgot-password",
    totpSendCode: "/api/v1/user/totp/send-code",
    sendEmailBindingCode: "/api/v1/user/account-bindings/email/send-code",
    bindEmail: "/api/v1/user/account-bindings/email",
    startIdentityBinding: "/api/v1/user/auth-identities/bind/start",
    profile: "/api/v1/user/profile",
    updateProfile: "/api/v1/user",
    notifyEmailSendCode: "/api/v1/user/notify-email/send-code",
    notifyEmailVerify: "/api/v1/user/notify-email/verify",
    notifyEmailToggle: "/api/v1/user/notify-email/toggle",
    notifyEmailRemove: "/api/v1/user/notify-email",
    adminUsers: "/api/v1/admin/users",
    setupInstall: SETUP_INSTALL_PATH
} as const;

const ADMIN_USER_PATH = /^\/api\/v1\/admin\/users\/(\d+)$/u;
const ADMIN_AUTH_IDENTITY_PATH = /^\/api\/v1\/admin\/users\/(\d+)\/auth-identities$/u;
const UNBIND_IDENTITY_PATH = /^\/api\/v1\/user\/account-bindings\/([^/]+)$/u;
const USER_DOMAIN_SETTING_KEYS = [
    "registration_enabled",
    "email_verify_enabled",
    "registration_email_suffix_whitelist",
    "invitation_code_enabled",
    "promo_code_enabled",
    "affiliate_enabled",
    "backend_mode_enabled",
    "password_reset_enabled",
    "turnstile_enabled",
    "turnstile_secret_key",
    "site_name",
    "frontend_url",
    "default_balance",
    "default_concurrency",
    "default_user_rpm_limit",
    "default_subscriptions",
    "default_platform_quotas",
    "auth_source_default_email_balance",
    "auth_source_default_email_concurrency",
    "auth_source_default_email_subscriptions",
    "auth_source_default_email_grant_on_signup",
    "auth_source_default_email_grant_on_first_bind",
    "auth_source_default_email_platform_quotas",
    "linuxdo_connect_enabled",
    "oidc_connect_enabled",
    "wechat_connect_enabled",
    "wechat_connect_open_enabled",
    "wechat_connect_mp_enabled",
    "wechat_connect_mobile_enabled",
    "dingtalk_connect_enabled"
] as const;

const RESERVED_EMAIL_SUFFIXES = [
    "@linuxdo-connect.invalid",
    "@oidc-connect.invalid",
    "@wechat-connect.invalid",
    "@dingtalk-connect.invalid"
] as const;

export interface StagedUserDomainEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
    EMAIL_TASK_ENCRYPTION_KEY?: string;
    RUN_MODE?: string;
}

export interface StagedUserDomainDependencies {
    clock?: () => number;
    passwordHasher?: PasswordHasher;
    emailCipher?: EmailSecretCipher;
    verificationCodeFactory?: () => string;
    resetTokenFactory?: () => string;
    fetchImplementation?: typeof fetch;
}

export async function routeStagedUserDomain(
    request: Request,
    env: StagedUserDomainEnv,
    dependencies: StagedUserDomainDependencies = {}
): Promise<Response | null> {
    const path = new URL(request.url).pathname;
    const adminMatch = ADMIN_USER_PATH.exec(path);
    const adminIdentityMatch = ADMIN_AUTH_IDENTITY_PATH.exec(path);
    const unbindMatch = path === STAGED_USER_DOMAIN_PATHS.bindEmail
        ? null
        : UNBIND_IDENTITY_PATH.exec(path);
    const known = Object.values(STAGED_USER_DOMAIN_PATHS).includes(
        path as typeof STAGED_USER_DOMAIN_PATHS[keyof typeof STAGED_USER_DOMAIN_PATHS]
    ) || adminMatch !== null || adminIdentityMatch !== null || unbindMatch !== null;
    if (!known) {
        return null;
    }
    if (env.DB === undefined) {
        return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");
    }

    const expectedMethod = methodFor(
        path,
        adminMatch !== null,
        adminIdentityMatch !== null,
        unbindMatch !== null
    );
    if (request.method !== expectedMethod) {
        return routerError(
            405,
            "method_not_allowed",
            `${path} requires ${expectedMethod}`,
            { allow: expectedMethod }
        );
    }

    const clock = dependencies.clock ?? Date.now;
    const users = new D1AuthUserRepository(env.DB);
    const sessions = new D1AuthSessionRepository(env.DB);
    const state = new D1ExpiringStateRepository(env.DB, { clock });
    const coordination = new D1CoordinationRepository(env.DB, { clock });
    const settings = await new D1SettingsRepository(env.DB).getMany(USER_DOMAIN_SETTING_KEYS);
    const passwords = dependencies.passwordHasher ?? new BcryptPasswordService();

    try {
        if (path === STAGED_USER_DOMAIN_PATHS.sendVerifyCode) {
            const limited = await consumeRateLimit(coordination, request, "auth-send-verify-code", 5);
            if (limited !== null) return limited;
            const body = await requiredJsonBody(request);
            await verifyTurnstileIfEnabled(body, request, settings, dependencies.fetchImplementation);
            const email = normalizeEmail(stringField(body, "email"));
            assertRegistrationEmailAllowed(email, settings);
            if (await users.findByEmail(email) !== null) {
                throw new UserManagementError("email_exists", 409, "Email is already in use");
            }
            const producer = createEmailProducer(env, dependencies, clock);
            const result = await producer.enqueueVerification(
                email,
                settings.site_name || "Sub2API",
                request.headers.get("accept-language") ?? ""
            );
            return legacySuccess({
                message: "Verification code sent successfully",
                countdown: result.countdown
            });
        }

        if (path === STAGED_USER_DOMAIN_PATHS.forgotPassword) {
            const limited = await consumeRateLimit(coordination, request, "forgot-password", 5);
            if (limited !== null) return limited;
            const body = await requiredJsonBody(request);
            await verifyTurnstileIfEnabled(body, request, settings, dependencies.fetchImplementation);
            if (settings.password_reset_enabled !== "true") {
                return legacyError(403, "password reset is not enabled", "PASSWORD_RESET_DISABLED");
            }
            const email = normalizeEmail(stringField(body, "email"));
            const user = await users.findByEmail(email);
            if (user !== null && user.status === "active") {
                const frontendUrl = settings.frontend_url?.trim() ?? "";
                if (frontendUrl === "") {
                    return legacyError(503, "Password reset is not configured", "PASSWORD_RESET_NOT_CONFIGURED");
                }
                try {
                    await createEmailProducer(env, dependencies, clock).enqueuePasswordReset(
                        email,
                        settings.site_name || "Sub2API",
                        `${frontendUrl.replace(/\/$/u, "")}/reset-password`,
                        request.headers.get("accept-language") ?? ""
                    );
                } catch (error) {
                    if (!(error instanceof EmailCooldownError)) throw error;
                }
            }
            return legacySuccess({
                message: "If your email is registered, you will receive a password reset link shortly."
            });
        }

        const tokenServices = createTokenServices(env, sessions, clock);
        const management = new D1UserManagementService(
            users,
            new D1UserManagementRepository(env.DB),
            passwords,
            state,
            tokenServices.tokens,
            clock
        );

        if (path === STAGED_USER_DOMAIN_PATHS.register) {
            const limited = await consumeRateLimit(coordination, request, "auth-register", 5);
            if (limited !== null) return limited;
            const body = await requiredJsonBody(request);
            if (!(settings.email_verify_enabled === "true" && optionalString(body, "verify_code")?.trim())) {
                await verifyTurnstileIfEnabled(body, request, settings, dependencies.fetchImplementation);
            }
            const input: RegistrationInput = {
                email: stringField(body, "email"),
                password: stringField(body, "password"),
                verifyCode: optionalString(body, "verify_code"),
                promoCode: optionalString(body, "promo_code"),
                invitationCode: optionalString(body, "invitation_code"),
                affiliateCode: optionalString(body, "aff_code")
            };
            return legacySuccess(await management.register(input, settings));
        }

        if (path === STAGED_USER_DOMAIN_PATHS.setupInstall) {
            const body = await requiredJsonBody(request);
            const admin = objectField(body, "admin");
            await management.createInitialAdmin(
                stringField(admin, "email"),
                stringField(admin, "password")
            );
            return legacySuccess({
                message: "Installation completed successfully.",
                restart: false
            });
        }

        const access = new AccessAuthService(users, tokenServices.verifier, tokenServices.tokens, clock);
        const authenticated = await access.authenticateAuthorization(request.headers.get("authorization"));
        if (settings.backend_mode_enabled === "true" && authenticated.user.role !== "admin") {
            return legacyError(403, "Backend mode is active. Only admin login is allowed.", "BACKEND_MODE_ADMIN_ONLY");
        }
        const identities = new D1IdentityBindingService(
            users,
            new D1IdentityBindingRepository(env.DB),
            state,
            passwords,
            clock
        );
        const runMode = env.RUN_MODE === "simple" ? "simple" : "standard";

        if (path === STAGED_USER_DOMAIN_PATHS.profile) {
            return legacySuccess(await new UserProfileService(users).getProfile(
                authenticated.user,
                settings,
                runMode
            ));
        }

        if (path === STAGED_USER_DOMAIN_PATHS.updateProfile) {
            const body = await requiredJsonBody(request, 512 * 1024);
            const updated = await new D1UserProfileManagementService(
                users,
                new D1UserProfileRepository(env.DB),
                state,
                clock
            ).update(authenticated.user.id, profileUpdateInput(body));
            return legacySuccess(await new UserProfileService(users).getProfile(updated, settings, runMode));
        }

        if (path === STAGED_USER_DOMAIN_PATHS.notifyEmailSendCode) {
            const limited = await consumeRateLimit(
                coordination,
                request,
                `notify-email-code:${authenticated.user.id}`,
                5
            );
            if (limited !== null) return limited;
            const body = await requiredJsonBody(request);
            const result = await createEmailProducer(env, dependencies, clock).enqueueNotificationVerification(
                authenticated.user.id,
                stringField(body, "email"),
                settings.site_name || "Sub2API",
                request.headers.get("accept-language") ?? ""
            );
            return legacySuccess({ message: "Verification code sent successfully", countdown: result.countdown });
        }

        if (
            path === STAGED_USER_DOMAIN_PATHS.notifyEmailVerify
            || path === STAGED_USER_DOMAIN_PATHS.notifyEmailToggle
            || path === STAGED_USER_DOMAIN_PATHS.notifyEmailRemove
        ) {
            const body = await requiredJsonBody(request);
            const profileManagement = new D1UserProfileManagementService(
                users,
                new D1UserProfileRepository(env.DB),
                state,
                clock
            );
            const updated = path === STAGED_USER_DOMAIN_PATHS.notifyEmailVerify
                ? await profileManagement.verifyAndAddNotificationEmail(
                    authenticated.user.id,
                    stringField(body, "email"),
                    stringField(body, "code")
                )
                : path === STAGED_USER_DOMAIN_PATHS.notifyEmailToggle
                    ? await profileManagement.toggleNotificationEmail(
                        authenticated.user.id,
                        stringField(body, "email"),
                        booleanField(body, "disabled")
                    )
                    : await profileManagement.removeNotificationEmail(
                        authenticated.user.id,
                        stringField(body, "email")
                    );
            return legacySuccess(await new UserProfileService(users).getProfile(updated, settings, runMode));
        }

        if (path === STAGED_USER_DOMAIN_PATHS.sendEmailBindingCode) {
            const limited = await consumeRateLimit(
                coordination,
                request,
                `email-binding-code:${authenticated.user.id}`,
                5
            );
            if (limited !== null) return limited;
            const body = await requiredJsonBody(request);
            const email = await identities.prepareEmailCode(
                authenticated.user,
                stringField(body, "email"),
                settings
            );
            const result = await createEmailProducer(env, dependencies, clock).enqueueVerification(
                email,
                settings.site_name || "Sub2API",
                request.headers.get("accept-language") ?? ""
            );
            return legacySuccess({
                message: "Verification code sent successfully",
                countdown: result.countdown
            });
        }

        if (path === STAGED_USER_DOMAIN_PATHS.bindEmail) {
            const body = await requiredJsonBody(request);
            return legacySuccess(await identities.bindEmail(
                authenticated.user,
                stringField(body, "email"),
                stringField(body, "verify_code"),
                stringField(body, "password"),
                settings,
                runMode
            ));
        }

        if (path === STAGED_USER_DOMAIN_PATHS.startIdentityBinding) {
            const body = await requiredJsonBody(request);
            return legacySuccess(identities.prepareBindingStart(
                stringField(body, "provider"),
                optionalString(body, "redirect_to") ?? ""
            ));
        }

        if (unbindMatch !== null) {
            return legacySuccess(await identities.unbindProvider(
                authenticated.user,
                unbindMatch[1],
                settings,
                runMode
            ));
        }

        if (path === STAGED_USER_DOMAIN_PATHS.totpSendCode) {
            if (settings.email_verify_enabled !== "true") {
                return legacyError(409, "Email verification is not enabled", "EMAIL_VERIFICATION_DISABLED");
            }
            const limited = await consumeRateLimit(
                coordination,
                request,
                `totp-send-code:${authenticated.user.id}`,
                5
            );
            if (limited !== null) return limited;
            const result = await createEmailProducer(env, dependencies, clock).enqueueTotpVerification(
                authenticated.user.email,
                settings.site_name || "Sub2API",
                request.headers.get("accept-language") ?? ""
            );
            return legacySuccess({ success: true, countdown: result.countdown });
        }

        if (path === STAGED_USER_DOMAIN_PATHS.adminUsers) {
            const body = await requiredJsonBody(request);
            return legacySuccess(await management.createByAdmin(
                authenticated.user,
                adminCreateInput(body),
                settings
            ));
        }

        if (adminIdentityMatch !== null) {
            const body = await requiredJsonBody(request);
            return legacySuccess(await new D1AdminAuthIdentityService(
                users,
                new D1AdminAuthIdentityRepository(env.DB),
                clock
            ).bind(authenticated.user, Number(adminIdentityMatch[1]), adminBindIdentityInput(body)));
        }

        if (adminMatch !== null) {
            const body = await requiredJsonBody(request);
            return legacySuccess(await management.updateByAdmin(
                authenticated.user,
                Number(adminMatch[1]),
                adminUpdateInput(body)
            ));
        }

        return null;
    } catch (error) {
        return userDomainFailure(error);
    }
}

function createTokenServices(
    env: StagedUserDomainEnv,
    sessions: D1AuthSessionRepository,
    clock: () => number
) {
    const secret = env.JWT_SECRET?.trim() ?? "";
    if (secret === "") {
        throw new UserDomainConfigurationError("JWT secret is not configured");
    }
    const accessSeconds = boundedIntegerEnv(
        env.JWT_ACCESS_TOKEN_EXPIRES_SECONDS,
        24 * 60 * 60,
        1,
        7 * 24 * 60 * 60
    );
    const refreshDays = boundedIntegerEnv(env.JWT_REFRESH_TOKEN_EXPIRE_DAYS, 30, 1, 365);
    const signer = new Hs256JwtSigner(secret, accessSeconds, clock);
    return {
        tokens: new AuthTokenService(sessions, signer, refreshDays, clock),
        verifier: new Hs256JwtVerifier(secret, clock)
    };
}

function createEmailProducer(
    env: StagedUserDomainEnv,
    dependencies: StagedUserDomainDependencies,
    clock: () => number
): AuthenticationEmailTaskProducer {
    let cipher = dependencies.emailCipher;
    if (cipher === undefined) {
        const key = env.EMAIL_TASK_ENCRYPTION_KEY?.trim() ?? "";
        if (key === "") {
            throw new UserDomainConfigurationError("Email task encryption key is not configured");
        }
        cipher = new AesGcmEmailSecretCipher(key);
    }
    return new AuthenticationEmailTaskProducer(
        new D1AuthEmailRepository(env.DB as D1Database),
        cipher,
        {
            clock,
            verificationCodeFactory: dependencies.verificationCodeFactory,
            resetTokenFactory: dependencies.resetTokenFactory
        }
    );
}

async function verifyTurnstileIfEnabled(
    body: Record<string, unknown>,
    request: Request,
    settings: Record<string, string>,
    fetchImplementation?: typeof fetch
): Promise<void> {
    if (settings.turnstile_enabled !== "true") return;
    const secret = settings.turnstile_secret_key?.trim() ?? "";
    if (secret === "") {
        throw new UserDomainConfigurationError("Turnstile verification is not configured");
    }
    await new TurnstileVerifier(secret, fetchImplementation ?? fetch).verify(
        stringField(body, "turnstile_token"),
        clientIp(request)
    );
}

async function consumeRateLimit(
    coordination: D1CoordinationRepository,
    request: Request,
    scope: string,
    limit: number
): Promise<Response | null> {
    const result = await coordination.consumeFixedWindow({
        key: `${scope}:${clientIp(request)}`,
        limit,
        windowMs: 60_000
    });
    return result.allowed ? null : legacyError(
        429,
        "Too many requests, please try again later",
        "RATE_LIMIT_EXCEEDED",
        { reset_at: String(result.resetAt) }
    );
}

function assertRegistrationEmailAllowed(email: string, settings: Record<string, string>): void {
    if (settings.registration_enabled !== "true") {
        throw new UserManagementError("registration_disabled", 403, "registration is disabled");
    }
    if (RESERVED_EMAIL_SUFFIXES.some((suffix) => email.endsWith(suffix))) {
        throw new UserManagementError("email_reserved", 400, "This email address is reserved");
    }
    const raw = settings.registration_email_suffix_whitelist;
    if (raw === undefined || raw.trim() === "") return;
    let parsed: unknown;
    try { parsed = JSON.parse(raw); } catch { return; }
    if (!Array.isArray(parsed) || parsed.length === 0) return;
    const domain = email.slice(email.lastIndexOf("@") + 1);
    if (!parsed.some((item) => typeof item === "string" && item.trim().toLowerCase() === domain)) {
        throw new UserManagementError(
            "registration_email_not_allowed",
            403,
            "Email domain is not allowed for registration"
        );
    }
}

function methodFor(
    path: string,
    isAdminItem: boolean,
    isAdminIdentity: boolean,
    isIdentityUnbind: boolean
): "GET" | "POST" | "PUT" | "DELETE" {
    if (isIdentityUnbind) return "DELETE";
    if (isAdminIdentity) return "POST";
    if (path === STAGED_USER_DOMAIN_PATHS.profile) return "GET";
    if (path === STAGED_USER_DOMAIN_PATHS.updateProfile) return "PUT";
    if (path === STAGED_USER_DOMAIN_PATHS.notifyEmailToggle) return "PUT";
    if (path === STAGED_USER_DOMAIN_PATHS.notifyEmailRemove) return "DELETE";
    return isAdminItem ? "PUT" : "POST";
}

function adminBindIdentityInput(body: Record<string, unknown>): AdminBindAuthIdentityInput {
    const issuer = nullableOptionalString(body, "issuer");
    const metadata = nullableOptionalObject(body, "metadata");
    const rawChannel = body.channel;
    let channel: AdminBindAuthIdentityInput["channel"];
    if (rawChannel === undefined || rawChannel === null) {
        channel = rawChannel;
    } else if (typeof rawChannel === "object" && !Array.isArray(rawChannel)) {
        const value = rawChannel as Record<string, unknown>;
        channel = {
            channel: stringField(value, "channel"),
            appId: stringField(value, "channel_app_id"),
            subject: stringField(value, "channel_subject"),
            metadata: nullableOptionalObject(value, "metadata")
        };
    } else {
        throw new RequestBodyError("channel must be an object or null");
    }
    return {
        providerType: stringField(body, "provider_type"),
        providerKey: stringField(body, "provider_key"),
        providerSubject: stringField(body, "provider_subject"),
        ...(issuer === undefined ? {} : { issuer }),
        ...(metadata === undefined ? {} : { metadata }),
        ...(channel === undefined ? {} : { channel })
    };
}

function profileUpdateInput(body: Record<string, unknown>): UserProfileUpdateInput {
    const allowed = new Set([
        "username", "avatar_url", "balance_notify_enabled",
        "balance_notify_threshold", "balance_notify_extra_emails"
    ]);
    const unsupported = Object.keys(body).filter((key) => !allowed.has(key));
    if (unsupported.length > 0) {
        throw new RequestBodyError(`Unsupported profile fields: ${unsupported.sort().join(", ")}`);
    }
    const input: UserProfileUpdateInput = {};
    if ("username" in body) input.username = nullableString(body, "username") ?? "";
    if ("avatar_url" in body) input.avatarUrl = nullableString(body, "avatar_url");
    if ("balance_notify_enabled" in body) {
        if (typeof body.balance_notify_enabled !== "boolean") {
            throw new RequestBodyError("balance_notify_enabled must be a boolean");
        }
        input.balanceNotifyEnabled = body.balance_notify_enabled;
    }
    if ("balance_notify_threshold" in body) {
        const value = body.balance_notify_threshold;
        if (value !== null && (typeof value !== "number" || !Number.isFinite(value))) {
            throw new RequestBodyError("balance_notify_threshold must be a finite number or null");
        }
        input.balanceNotifyThreshold = value as number | null;
    }
    return input;
}

function adminCreateInput(body: Record<string, unknown>): AdminCreateUserInput {
    return {
        email: stringField(body, "email"),
        password: stringField(body, "password"),
        username: optionalString(body, "username"),
        notes: optionalString(body, "notes"),
        role: optionalEnum(body, "role", ["admin", "user"]),
        balance: optionalNumber(body, "balance"),
        concurrency: optionalInteger(body, "concurrency"),
        rpmLimit: optionalInteger(body, "rpm_limit"),
        allowedGroups: optionalIdArray(body, "allowed_groups")
    };
}

function adminUpdateInput(body: Record<string, unknown>): AdminUpdateUserInput {
    const allowed = new Set([
        "email", "password", "username", "notes", "role", "balance",
        "concurrency", "rpm_limit", "status", "allowed_groups", "group_rates"
    ]);
    const unsupported = Object.keys(body).filter((key) => !allowed.has(key));
    if (unsupported.length > 0) {
        throw new RequestBodyError(`Unsupported user fields: ${unsupported.sort().join(", ")}`);
    }
    return {
        email: optionalString(body, "email"),
        password: optionalString(body, "password"),
        username: optionalString(body, "username"),
        notes: optionalString(body, "notes"),
        role: optionalEnum(body, "role", ["admin", "user"]),
        balance: optionalNumber(body, "balance"),
        concurrency: optionalInteger(body, "concurrency"),
        rpmLimit: optionalInteger(body, "rpm_limit"),
        status: optionalEnum(body, "status", ["active", "disabled"]),
        allowedGroups: optionalIdArray(body, "allowed_groups"),
        groupRates: optionalNullableNumberRecord(body, "group_rates")
    };
}

async function requiredJsonBody(request: Request, maximumBytes = 32 * 1024): Promise<Record<string, unknown>> {
    const text = await request.text();
    if (text.trim() === "" || new TextEncoder().encode(text).byteLength > maximumBytes) {
        throw new RequestBodyError("Invalid request body");
    }
    try {
        const value: unknown = JSON.parse(text);
        if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError();
        return value as Record<string, unknown>;
    } catch {
        throw new RequestBodyError("Invalid request body");
    }
}

function nullableString(body: Record<string, unknown>, key: string): string | null {
    const value = body[key];
    if (value === null) return null;
    if (typeof value !== "string") throw new RequestBodyError(`${key} must be a string or null`);
    return value;
}

function nullableOptionalString(body: Record<string, unknown>, key: string): string | null | undefined {
    if (!(key in body)) return undefined;
    return nullableString(body, key);
}

function nullableOptionalObject(
    body: Record<string, unknown>,
    key: string
): Record<string, unknown> | null | undefined {
    if (!(key in body)) return undefined;
    const value = body[key];
    if (value === null) return null;
    if (typeof value !== "object" || Array.isArray(value)) {
        throw new RequestBodyError(`${key} must be an object or null`);
    }
    return value as Record<string, unknown>;
}

function objectField(body: Record<string, unknown>, key: string): Record<string, unknown> {
    const value = body[key];
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new RequestBodyError(`${key} is required`);
    }
    return value as Record<string, unknown>;
}

function stringField(body: Record<string, unknown>, key: string): string {
    const value = body[key];
    if (typeof value !== "string") throw new RequestBodyError(`${key} is required`);
    return value;
}

function booleanField(body: Record<string, unknown>, key: string): boolean {
    const value = body[key];
    if (typeof value !== "boolean") throw new RequestBodyError(`${key} must be a boolean`);
    return value;
}

function optionalString(body: Record<string, unknown>, key: string): string | undefined {
    const value = body[key];
    if (value === undefined || value === null) return undefined;
    if (typeof value !== "string") throw new RequestBodyError(`${key} must be a string`);
    return value;
}

function optionalNumber(body: Record<string, unknown>, key: string): number | undefined {
    const value = body[key];
    if (value === undefined || value === null) return undefined;
    if (typeof value !== "number" || !Number.isFinite(value)) {
        throw new RequestBodyError(`${key} must be a finite number`);
    }
    return value;
}

function optionalInteger(body: Record<string, unknown>, key: string): number | undefined {
    const value = optionalNumber(body, key);
    if (value !== undefined && !Number.isSafeInteger(value)) {
        throw new RequestBodyError(`${key} must be an integer`);
    }
    return value;
}

function optionalIdArray(body: Record<string, unknown>, key: string): number[] | null | undefined {
    const value = body[key];
    if (value === undefined) return undefined;
    if (value === null) return null;
    if (!Array.isArray(value) || value.some((item) => !Number.isSafeInteger(item) || item <= 0)) {
        throw new RequestBodyError(`${key} must contain positive integer IDs`);
    }
    return value as number[];
}

function optionalNullableNumberRecord(
    body: Record<string, unknown>,
    key: string
): Record<string, number | null> | undefined {
    const value = body[key];
    if (value === undefined || value === null) return undefined;
    if (typeof value !== "object" || Array.isArray(value)) {
        throw new RequestBodyError(`${key} must be an object`);
    }
    const output: Record<string, number | null> = {};
    for (const [entryKey, entryValue] of Object.entries(value)) {
        if (entryValue !== null && (typeof entryValue !== "number" || !Number.isFinite(entryValue))) {
            throw new RequestBodyError(`${key}.${entryKey} must be a number or null`);
        }
        output[entryKey] = entryValue as number | null;
    }
    return output;
}

function optionalEnum<T extends string>(
    body: Record<string, unknown>,
    key: string,
    values: readonly T[]
): T | undefined {
    const value = body[key];
    if (value === undefined || value === null || value === "") return undefined;
    if (typeof value !== "string" || !values.includes(value as T)) {
        throw new RequestBodyError(`${key} is invalid`);
    }
    return value as T;
}

function normalizeEmail(value: string): string {
    const email = value.trim().toLowerCase();
    if (email.length === 0 || email.length > 254 || !/^[^\s@]+@[^\s@]+$/u.test(email)) {
        throw new RequestBodyError("A valid email is required");
    }
    return email;
}

function clientIp(request: Request): string {
    return request.headers.get("cf-connecting-ip")?.trim()
        || request.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
        || "unknown";
}

function boundedIntegerEnv(
    raw: string | undefined,
    fallback: number,
    minimum: number,
    maximum: number
): number {
    if (raw === undefined || raw.trim() === "") return fallback;
    const value = Number(raw);
    if (!Number.isInteger(value) || value < minimum || value > maximum) {
        throw new UserDomainConfigurationError("Authentication lifetime configuration is invalid");
    }
    return value;
}

function userDomainFailure(error: unknown): Response {
    if (error instanceof AccessAuthError) {
        return middlewareAuthError(error.status, error.code, error.message);
    }
    if (error instanceof UserManagementError) {
        return legacyError(error.status, error.message, error.code.toUpperCase());
    }
    if (error instanceof IdentityBindingError) {
        return legacyError(error.status, error.message, error.code.toUpperCase());
    }
    if (error instanceof UserProfileManagementError) {
        return legacyError(error.status, error.message, error.code.toUpperCase());
    }
    if (error instanceof AdminAuthIdentityError) {
        return legacyError(error.status, error.message, error.code.toUpperCase());
    }
    if (error instanceof TurnstileVerificationError) {
        return legacyError(400, error.message, "TURNSTILE_VERIFICATION_FAILED");
    }
    if (error instanceof EmailCooldownError) {
        return legacyError(429, "please wait before requesting a new code", "VERIFY_CODE_TOO_FREQUENT");
    }
    if (error instanceof RequestBodyError) {
        return legacyError(400, error.message, "INVALID_REQUEST");
    }
    if (error instanceof UserDomainConfigurationError || error instanceof RangeError || error instanceof TypeError) {
        return legacyError(503, error instanceof Error ? error.message : "User domain is not configured");
    }
    return legacyInternalError();
}

class RequestBodyError extends Error {}
class UserDomainConfigurationError extends Error {}
