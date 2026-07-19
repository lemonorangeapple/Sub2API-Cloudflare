import type { D1AuthUserRepository } from "../repositories/auth-users.ts";
import type {
    PasswordLoginResponse,
    TotpLoginResponse
} from "../types/auth.ts";
import type { AuthTokenService } from "./auth-tokens.ts";
import { mapAuthUser } from "./auth-user.ts";
import type { PasswordVerifier } from "./password.ts";
import type { TotpLoginService } from "./totp.ts";

const DUMMY_BCRYPT_HASH = "$2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa";

export type PasswordAuthErrorCode =
    | "invalid_request"
    | "invalid_credentials"
    | "user_not_active"
    | "admin_required"
    | "backend_mode_admin_only"
    | "totp_required"
    | "totp_not_configured";

export class PasswordAuthError extends Error {
    readonly code: PasswordAuthErrorCode;
    readonly status: number;

    constructor(code: PasswordAuthErrorCode, status: number, message: string) {
        super(message);
        this.name = "PasswordAuthError";
        this.code = code;
        this.status = status;
    }
}

export interface PasswordLoginOptions {
    backendModeEnabled: boolean;
    totpFeatureEnabled: boolean;
}

export class PasswordAuthService {
    readonly #users: D1AuthUserRepository;
    readonly #passwords: PasswordVerifier;
    readonly #tokens: AuthTokenService;
    readonly #totp: TotpLoginService | null;
    readonly #clock: () => number;

    constructor(
        users: D1AuthUserRepository,
        passwords: PasswordVerifier,
        tokens: AuthTokenService,
        clock: () => number = Date.now,
        totp: TotpLoginService | null = null
    ) {
        this.#users = users;
        this.#passwords = passwords;
        this.#tokens = tokens;
        this.#clock = clock;
        this.#totp = totp;
    }

    async login(
        emailValue: string,
        password: string,
        options: PasswordLoginOptions
    ): Promise<PasswordLoginResponse | TotpLoginResponse> {
        const user = await this.#verifyCredentials(emailValue, password);
        if (options.backendModeEnabled && user.role !== "admin") {
            throw new PasswordAuthError(
                "backend_mode_admin_only",
                403,
                "Backend mode is active. Only admin login is allowed."
            );
        }
        if (options.totpFeatureEnabled && user.totpEnabled) {
            if (this.#totp === null) {
                throw new PasswordAuthError(
                    "totp_not_configured",
                    503,
                    "TOTP completion is not configured"
                );
            }
            return this.#totp.create(user);
        }
        return this.#completeLogin(user);
    }

    async loginAdministrator(emailValue: string, password: string): Promise<PasswordLoginResponse> {
        const user = await this.#verifyCredentials(emailValue, password);
        if (user.role !== "admin") {
            throw new PasswordAuthError("admin_required", 403, "Administrator access is required");
        }
        if (user.totpEnabled) {
            throw new PasswordAuthError(
                "totp_required",
                409,
                "TOTP completion must be migrated before this administrator can use native login"
            );
        }
        return this.#completeLogin(user);
    }

    async #verifyCredentials(emailValue: string, password: string) {
        const email = normalizeEmail(emailValue);
        validatePasswordInput(password);
        const user = await this.#users.findByEmail(email);
        const passwordMatches = await this.#passwords.verify(
            password,
            user?.passwordHash ?? DUMMY_BCRYPT_HASH
        );
        if (user === null || !passwordMatches) {
            throw new PasswordAuthError("invalid_credentials", 401, "Invalid email or password");
        }
        if (user.status !== "active") {
            throw new PasswordAuthError("user_not_active", 401, "User account is not active");
        }
        return user;
    }

    async #completeLogin(user: Awaited<ReturnType<D1AuthUserRepository["findById"]>> & object): Promise<PasswordLoginResponse> {
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

function normalizeEmail(value: string): string {
    const email = value.trim().toLowerCase();
    if (email.length === 0 || email.length > 254 || !/^[^\s@]+@[^\s@]+$/u.test(email)) {
        throw new PasswordAuthError("invalid_request", 400, "A valid email is required");
    }
    return email;
}

function validatePasswordInput(password: string): void {
    const byteLength = new TextEncoder().encode(password).byteLength;
    if (password.length === 0 || byteLength > 72) {
        throw new PasswordAuthError("invalid_request", 400, "Password must be between 1 and 72 UTF-8 bytes");
    }
}
