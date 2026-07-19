import { D1AuthSessionRepository } from "../repositories/auth-sessions.ts";
import { D1AuthUserRepository } from "../repositories/auth-users.ts";
import { D1SettingsRepository } from "../repositories/settings.ts";
import { AccessAuthError, AccessAuthService } from "../services/access-auth.ts";
import { AuthTokenService } from "../services/auth-tokens.ts";
import {
    AdminSettingsError,
    D1AdminSettingsService,
    type AdminSettingsUpdateInput
} from "../services/admin-settings.ts";
import { AdminSettingsFeatureError, D1AdminSettingsFeatureService } from "../services/admin-settings-features.ts";
import { AdminSettingsEmailTemplatesError, D1AdminSettingsEmailTemplatesService } from "../services/admin-settings-email-templates.ts";
import { Hs256JwtSigner, Hs256JwtVerifier } from "../services/jwt.ts";
import { WorkerSmtpEmailSender, type SmtpSocketConnector, SmtpProtocolError } from "../services/smtp-email-sender.ts";
import type { SmtpConfiguration } from "../types/email.ts";
import type { D1Database } from "../types/d1.ts";
import {
    legacyError,
    legacyInternalError,
    legacySuccess,
    middlewareAuthError,
    routerError
} from "./responses.ts";

export const STAGED_ADMIN_SETTINGS_PATHS = {
    updateSettings: "/api/v1/admin/settings"
} as const;

const ROOT_RE = /^\/api\/v1\/admin\/settings\/?$/;
const TEST_SMTP_RE = /^\/api\/v1\/admin\/settings\/test-smtp\/?$/;
const SEND_TEST_EMAIL_RE = /^\/api\/v1\/admin\/settings\/send-test-email\/?$/;
const OVERLOAD_COOLDOWN_RE = /^\/api\/v1\/admin\/settings\/overload-cooldown\/?$/;
const RATE_LIMIT_429_RE = /^\/api\/v1\/admin\/settings\/rate-limit-429-cooldown\/?$/;
const STREAM_TIMEOUT_RE = /^\/api\/v1\/admin\/settings\/stream-timeout\/?$/;
const RECTIFIER_RE = /^\/api\/v1\/admin\/settings\/rectifier\/?$/;
const BETA_POLICY_RE = /^\/api\/v1\/admin\/settings\/beta-policy\/?$/;
const ADMIN_API_KEY_RE = /^\/api\/v1\/admin\/settings\/admin-api-key\/?$/;
const ADMIN_API_KEY_REGENERATE_RE = /^\/api\/v1\/admin\/settings\/admin-api-key\/regenerate\/?$/;
const WEB_SEARCH_RE = /^\/api\/v1\/admin\/settings\/web-search-emulation\/?$/;
const EMAIL_TEMPLATES_LIST_RE = /^\/api\/v1\/admin\/settings\/email-templates\/?$/;
const EMAIL_TEMPLATE_PREVIEW_RE = /^\/api\/v1\/admin\/settings\/email-template-preview\/?$/;
const EMAIL_TEMPLATE_BY_EVENT_LOCALE_RE = /^\/api\/v1\/admin\/settings\/email-templates\/([a-z][a-z0-9_.]+)\/([a-z]{2})(?:\/([a-z-]+))?\/?$/;

export interface StagedAdminSettingsEnv {
    DB?: D1Database;
    JWT_SECRET?: string;
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS?: string;
    JWT_REFRESH_TOKEN_EXPIRE_DAYS?: string;
    TOTP_ENCRYPTION_KEY?: string;
}

export interface StagedAdminSettingsDependencies {
    clock?: () => number;
    totpEncryptionKeyConfigured?: boolean;
}

function boundedIntegerEnv(
    value: string | undefined,
    defaultValue: number,
    min: number,
    max: number
): number {
    if (value === undefined || value.trim() === "") {
        return defaultValue;
    }
    const parsed = Number.parseInt(value.trim(), 10);
    if (!Number.isInteger(parsed)) {
        return defaultValue;
    }
    return Math.min(max, Math.max(min, parsed));
}

function isAdminSettingsPath(pathname: string): boolean {
    return pathname.startsWith("/api/v1/admin/settings");
}

async function authenticateAdmin(
    request: Request,
    env: StagedAdminSettingsEnv,
    clock: () => number
): Promise<void> {
    const authHeader = request.headers.get("authorization");
    if (!authHeader) {
        throw new AccessAuthError("UNAUTHORIZED", "Missing authorization header");
    }
    const secret = env.JWT_SECRET?.trim() ?? "";
    if (!secret) {
        throw new AccessAuthError("UNAUTHORIZED", "JWT secret is not configured");
    }

    const users = new D1AuthUserRepository(env.DB!);
    const sessions = new D1AuthSessionRepository(env.DB!);
    const signer = new Hs256JwtSigner(secret, boundedIntegerEnv(env.JWT_ACCESS_TOKEN_EXPIRES_SECONDS, 24 * 60 * 60, 1, 7 * 24 * 60 * 60), clock);
    const verifier = new Hs256JwtVerifier(secret, clock);
    const tokens = new AuthTokenService(sessions, signer, boundedIntegerEnv(env.JWT_REFRESH_TOKEN_EXPIRE_DAYS, 30, 1, 365), clock);
    const auth = new AccessAuthService(users, verifier, tokens, clock);
    const subject = await auth.authenticateAuthorization(authHeader);
    if (subject.user.role !== "admin") {
        throw new AccessAuthError("FORBIDDEN", "Admin access required");
    }
}

export async function routeStagedAdminSettings(
    request: Request,
    env: StagedAdminSettingsEnv,
    dependencies: StagedAdminSettingsDependencies = {}
): Promise<Response | null> {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method;

    if (!isAdminSettingsPath(pathname)) {
        return null;
    }

    if (env.DB === undefined) {
        return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");
    }

    const settings = new D1SettingsRepository(env.DB);

    try {
        // Root path: GET (read all) or PUT (update), need admin role
        if (ROOT_RE.test(pathname)) {
            const authHeader = request.headers.get("authorization");
            if (!authHeader) {
                return middlewareAuthError(401, "authorization_required", "Missing authorization header");
            }
            const secret = env.JWT_SECRET?.trim() ?? "";
            if (!secret) {
                return routerError(503, "jwt_secret_not_configured", "JWT secret is not configured");
            }
            const clock = dependencies.clock ?? Date.now;
            const users = new D1AuthUserRepository(env.DB);
            const sessions = new D1AuthSessionRepository(env.DB);
            const signer = new Hs256JwtSigner(secret, boundedIntegerEnv(env.JWT_ACCESS_TOKEN_EXPIRES_SECONDS, 24 * 60 * 60, 1, 7 * 24 * 60 * 60), clock);
            const verifier = new Hs256JwtVerifier(secret, clock);
            const tokens = new AuthTokenService(sessions, signer, boundedIntegerEnv(env.JWT_REFRESH_TOKEN_EXPIRE_DAYS, 30, 1, 365), clock);
            const auth = new AccessAuthService(users, verifier, tokens, clock);
            const subject = await auth.authenticateAuthorization(authHeader);
            if (subject.user.role !== "admin") {
                return middlewareAuthError(403, "forbidden", "Admin access required");
            }

            if (method === "GET") {
                const svc = new D1AdminSettingsService(settings);
                return legacySuccess(await svc.getSettings());
            }

            if (method !== "PUT") {
                return routerError(405, "method_not_allowed", `${pathname} requires GET or PUT`, { allow: "GET, PUT" });
            }

            let body: Record<string, unknown>;
            try {
                body = await request.json() as Record<string, unknown>;
            } catch {
                return legacyError(400, "Invalid JSON body", "INVALID_JSON");
            }
            if (body === null || typeof body !== "object" || Array.isArray(body)) {
                return legacyError(400, "Request body must be a JSON object", "INVALID_BODY");
            }
            const adminSettingsService = new D1AdminSettingsService(settings);
            await adminSettingsService.validateAuthSettings(body as AdminSettingsUpdateInput);
            const result = await adminSettingsService.updateSettings(body as AdminSettingsUpdateInput);
            return legacySuccess({ message: "Settings updated successfully", updated_count: result.updated });
        }

        // Sub-paths: authenticate then route
        await authenticateAdmin(request, env, dependencies.clock ?? Date.now);
        const featureSvc = new D1AdminSettingsFeatureService(settings);
        const emailSvc = new D1AdminSettingsEmailTemplatesService(settings);

        // POST /api/v1/admin/settings/test-smtp — test SMTP connection
        if (TEST_SMTP_RE.test(pathname) && method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            const savedValues = await settings.getMany(["smtp_host", "smtp_port", "smtp_username", "smtp_password", "smtp_from_email", "smtp_from_name", "smtp_use_tls"]);
            const host = typeof body.smtp_host === "string" && body.smtp_host.trim() !== "" ? body.smtp_host.trim() : (savedValues.smtp_host ?? "").trim();
            const portStr = typeof body.smtp_port === "number" ? String(body.smtp_port) : (savedValues.smtp_port ?? "").trim();
            const port = portStr === "" ? 587 : Number(portStr);
            const username = typeof body.smtp_username === "string" ? body.smtp_username.trim() : (savedValues.smtp_username ?? "").trim();
            const password = typeof body.smtp_password === "string" && body.smtp_password !== "" ? body.smtp_password : (savedValues.smtp_password ?? "").trim();
            const from = (savedValues.smtp_from_email ?? "").trim().toLowerCase();
            const fromName = (savedValues.smtp_from_name ?? "").trim();
            const useTls = body.smtp_use_tls === true || body.smtp_use_tls === "true" || savedValues.smtp_use_tls === "true";
            if (host === "") return legacyError(400, "SMTP host is required", "SMTP_HOST_REQUIRED");
            if (from === "") return legacyError(400, "SMTP sender email is required (configure it first)", "SMTP_FROM_REQUIRED");
            try {
                const config: SmtpConfiguration = { host, port, username, password, from, fromName, useTls };
                const sockets = await import("cloudflare:sockets");
                const connector: SmtpSocketConnector = { connect: sockets.connect };
                const sender = new WorkerSmtpEmailSender(connector);
                await sender.testConnection(config);
                return legacySuccess({ message: "SMTP connection successful" });
            } catch (error) {
                const msg = error instanceof SmtpProtocolError ? error.message : error instanceof Error ? error.message : "SMTP connection failed";
                return legacyError(400, msg, "SMTP_TEST_FAILED");
            }
        }

        // POST /api/v1/admin/settings/send-test-email — send a test email
        if (SEND_TEST_EMAIL_RE.test(pathname) && method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            const recipient = typeof body.email === "string" ? body.email.trim() : "";
            if (recipient === "") return legacyError(400, "Recipient email is required", "EMAIL_REQUIRED");
            const savedValues = await settings.getMany(["smtp_host", "smtp_port", "smtp_username", "smtp_password", "smtp_from_email", "smtp_from_name", "smtp_use_tls"]);
            const host = typeof body.smtp_host === "string" && body.smtp_host.trim() !== "" ? body.smtp_host.trim() : (savedValues.smtp_host ?? "").trim();
            const portStr = typeof body.smtp_port === "number" ? String(body.smtp_port) : (savedValues.smtp_port ?? "").trim();
            const port = portStr === "" ? 587 : Number(portStr);
            const username = typeof body.smtp_username === "string" ? body.smtp_username.trim() : (savedValues.smtp_username ?? "").trim();
            const password = typeof body.smtp_password === "string" && body.smtp_password !== "" ? body.smtp_password : (savedValues.smtp_password ?? "").trim();
            const from = typeof body.smtp_from_email === "string" && body.smtp_from_email.trim() !== "" ? body.smtp_from_email.trim().toLowerCase() : (savedValues.smtp_from_email ?? "").trim().toLowerCase();
            const fromName = typeof body.smtp_from_name === "string" ? body.smtp_from_name.trim() : (savedValues.smtp_from_name ?? "").trim();
            const useTls = body.smtp_use_tls === true || body.smtp_use_tls === "true" || savedValues.smtp_use_tls === "true";
            if (host === "") return legacyError(400, "SMTP host is required", "SMTP_HOST_REQUIRED");
            if (from === "") return legacyError(400, "SMTP sender email is required (configure it first)", "SMTP_FROM_REQUIRED");
            try {
                const config: SmtpConfiguration = { host, port, username, password, from, fromName, useTls };
                const siteName = (savedValues.site_name ?? "Sub2API").trim();
                const subject = `Test Email from ${siteName}`;
                const html = `<h2>Test Email</h2><p>If you receive this email, your SMTP configuration is working correctly.</p><p>Sent from ${siteName} at ${new Date().toISOString()}</p>`;
                const text = `Test Email\n\nIf you receive this email, your SMTP configuration is working correctly.\n\nSent from ${siteName} at ${new Date().toISOString()}`;
                const sockets = await import("cloudflare:sockets");
                const connector: SmtpSocketConnector = { connect: sockets.connect };
                const sender = new WorkerSmtpEmailSender(connector);
                await sender.send(config, { to: recipient, from, fromName, subject, html, text });
                return legacySuccess({ message: "Test email sent successfully" });
            } catch (error) {
                const msg = error instanceof SmtpProtocolError ? error.message : error instanceof Error ? error.message : "Failed to send test email";
                return legacyError(400, msg, "SEND_TEST_EMAIL_FAILED");
            }
        }

        // Email template preview
        if (EMAIL_TEMPLATE_PREVIEW_RE.test(pathname) && method === "POST") {
            const body = await request.json() as Record<string, unknown>;
            if (!body || typeof body !== "object") {
                return legacyError(400, "Invalid request body", "INVALID_BODY");
            }
            const result = await emailSvc.preview({
                event: String(body.event ?? ""),
                locale: String(body.locale ?? "en"),
                subject: String(body.subject ?? ""),
                html: String(body.html ?? ""),
                variables: body.variables as Record<string, string> | undefined,
            });
            return legacySuccess({ subject: result.subject, html: result.html });
        }

        // Email template by event/locale (including restore-official action)
        const emailTmplMatch = EMAIL_TEMPLATE_BY_EVENT_LOCALE_RE.exec(pathname);
        if (emailTmplMatch !== null) {
            const tmplEvent = emailTmplMatch[1];
            const tmplLocale = emailTmplMatch[2];
            const tmplAction = emailTmplMatch[3];
            if (tmplAction === "restore-official" && method === "POST") {
                return legacySuccess(await emailSvc.restoreOfficial(tmplEvent, tmplLocale));
            }
            if (!tmplAction) {
                if (method === "GET") {
                    return legacySuccess(await emailSvc.getTemplate(tmplEvent, tmplLocale));
                }
                if (method === "PUT") {
                    const body = await request.json() as Record<string, unknown>;
                    if (!body || typeof body !== "object") {
                        return legacyError(400, "Invalid request body", "INVALID_BODY");
                    }
                    const subject = String(body.subject ?? "");
                    const html = String(body.html ?? "");
                    if (!subject || !html) {
                        return legacyError(400, "subject and html are required", "MISSING_FIELDS");
                    }
                    return legacySuccess(await emailSvc.updateTemplate(tmplEvent, tmplLocale, subject, html));
                }
            }
        }

        // Email template list
        if (EMAIL_TEMPLATES_LIST_RE.test(pathname) && method === "GET") {
            const events = emailSvc.listEvents();
            const templates = await emailSvc.listTemplates();
            return legacySuccess({
                events,
                locales: emailSvc.supportedLocales(),
                templates,
                placeholders: emailSvc.allPlaceholders(),
            });
        }

        // Overload cooldown
        if (OVERLOAD_COOLDOWN_RE.test(pathname)) {
            if (method === "GET") {
                return legacySuccess(await featureSvc.getOverloadCooldown());
            }
            if (method === "PUT") {
                const body = await request.json() as Record<string, unknown>;
                return legacySuccess(await featureSvc.setOverloadCooldown({
                    enabled: body.enabled === true,
                    cooldownMinutes: typeof body.cooldown_minutes === "number" ? body.cooldown_minutes : 10,
                }));
            }
        }

        // Rate limit 429 cooldown
        if (RATE_LIMIT_429_RE.test(pathname)) {
            if (method === "GET") {
                return legacySuccess(await featureSvc.getRateLimit429Cooldown());
            }
            if (method === "PUT") {
                const body = await request.json() as Record<string, unknown>;
                return legacySuccess(await featureSvc.setRateLimit429Cooldown({
                    enabled: body.enabled === true,
                    cooldownSeconds: typeof body.cooldown_seconds === "number" ? body.cooldown_seconds : 5,
                }));
            }
        }

        // Stream timeout
        if (STREAM_TIMEOUT_RE.test(pathname)) {
            if (method === "GET") {
                return legacySuccess(await featureSvc.getStreamTimeout());
            }
            if (method === "PUT") {
                const body = await request.json() as Record<string, unknown>;
                return legacySuccess(await featureSvc.setStreamTimeout({
                    enabled: body.enabled === true,
                    action: typeof body.action === "string" ? body.action : "temp_unsched",
                    tempUnschedMinutes: typeof body.temp_unsched_minutes === "number" ? body.temp_unsched_minutes : undefined,
                    thresholdCount: typeof body.threshold_count === "number" ? body.threshold_count : undefined,
                    thresholdWindowMinutes: typeof body.threshold_window_minutes === "number" ? body.threshold_window_minutes : undefined,
                }));
            }
        }

        // Rectifier
        if (RECTIFIER_RE.test(pathname)) {
            if (method === "GET") {
                return legacySuccess(await featureSvc.getRectifier());
            }
            if (method === "PUT") {
                const body = await request.json() as Record<string, unknown>;
                return legacySuccess(await featureSvc.setRectifier({
                    enabled: body.enabled === true,
                    thinkingSignatureEnabled: body.thinking_signature_enabled === true,
                    thinkingBudgetEnabled: body.thinking_budget_enabled === true,
                    apikeySignatureEnabled: body.apikey_signature_enabled === true,
                    apikeySignaturePatterns: Array.isArray(body.apikey_signature_patterns) ? body.apikey_signature_patterns as string[] : undefined,
                }));
            }
        }

        // Beta policy
        if (BETA_POLICY_RE.test(pathname)) {
            if (method === "GET") {
                return legacySuccess(await featureSvc.getBetaPolicy());
            }
            if (method === "PUT") {
                const body = await request.json() as Record<string, unknown>;
                return legacySuccess(await featureSvc.setBetaPolicy({
                    rules: Array.isArray(body.rules) ? body.rules : [],
                }));
            }
        }

        // Admin API key regenerate
        if (ADMIN_API_KEY_REGENERATE_RE.test(pathname) && method === "POST") {
            return legacySuccess(await featureSvc.regenerateAdminApiKey());
        }

        // Admin API key
        if (ADMIN_API_KEY_RE.test(pathname)) {
            if (method === "GET") {
                return legacySuccess(await featureSvc.getAdminApiKeyStatus());
            }
            if (method === "DELETE") {
                await featureSvc.deleteAdminApiKey();
                return legacySuccess({ message: "Admin API key deleted" });
            }
        }

        // Web search emulation
        if (WEB_SEARCH_RE.test(pathname)) {
            if (method === "GET") {
                return legacySuccess(await featureSvc.getWebSearchEmulation());
            }
            if (method === "PUT") {
                const body = await request.json() as Record<string, unknown>;
                return legacySuccess(await featureSvc.setWebSearchEmulation({
                    enabled: body.enabled === true,
                    providers: Array.isArray(body.providers) ? body.providers : [],
                }));
            }
        }

        return routerError(405, "method_not_allowed", `${pathname} requires ${method}`);
    } catch (error) {
        if (error instanceof AccessAuthError) {
            return middlewareAuthError(error.status, error.code, error.message);
        }
        if (error instanceof AdminSettingsError) {
            return legacyError(error.status, error.message, error.code);
        }
        if (error instanceof AdminSettingsFeatureError) {
            return legacyError(error.status, error.message, error.code);
        }
        if (error instanceof AdminSettingsEmailTemplatesError) {
            return legacyError(error.status, error.message, error.code);
        }
        return legacyInternalError(error instanceof Error ? error.message : "internal server error");
    }
}
