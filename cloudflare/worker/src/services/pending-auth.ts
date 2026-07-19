import {
    D1PendingAuthRepository,
    type IdentityAdoptionDecisionRecord,
    type PendingAuthSessionRecord
} from "../repositories/pending-auth.ts";
import { randomHex, sha256Hex } from "../utils/crypto.ts";

const INTENTS = ["login", "bind_current_user", "adopt_existing_user_by_email"] as const;
const PROVIDERS = ["email", "github", "google", "linuxdo", "oidc", "wechat", "dingtalk"] as const;
const DEFAULT_SESSION_TTL_MS = 15 * 60 * 1000;
const DEFAULT_COMPLETION_TTL_MS = 5 * 60 * 1000;

export class PendingAuthError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "PendingAuthError";
        this.code = code;
        this.status = status;
    }
}

export interface CreatePendingAuthInput {
    sessionToken?: string;
    intent: string;
    providerType: string;
    providerKey: string;
    providerSubject: string;
    targetUserId?: number;
    redirectTo?: string;
    resolvedEmail?: string;
    registrationPasswordHash?: string;
    browserSessionKey?: string;
    upstreamIdentityClaims?: Record<string, unknown>;
    localFlowState?: Record<string, unknown>;
    expiresAt?: number;
}

export interface PendingAuthServiceOptions {
    clock?: () => number;
    opaqueTokenFactory?: () => string;
}

export class D1PendingAuthService {
    readonly #repository: D1PendingAuthRepository;
    readonly #clock: () => number;
    readonly #opaqueTokenFactory: () => string;

    constructor(repository: D1PendingAuthRepository, options: PendingAuthServiceOptions = {}) {
        this.#repository = repository;
        this.#clock = options.clock ?? Date.now;
        this.#opaqueTokenFactory = options.opaqueTokenFactory ?? (() => randomHex(24));
    }

    async create(input: CreatePendingAuthInput): Promise<{
        session: PendingAuthSessionRecord;
        sessionToken: string;
    }> {
        const sessionToken = opaqueToken(input.sessionToken ?? this.#opaqueTokenFactory());
        const intent = enumValue(input.intent, INTENTS, "pending auth intent");
        const providerType = enumValue(input.providerType, PROVIDERS, "auth provider type");
        const providerKey = requiredText(input.providerKey, "provider key");
        const providerSubject = requiredText(input.providerSubject, "provider subject");
        const targetUserId = input.targetUserId ?? null;
        if (targetUserId !== null && (!Number.isSafeInteger(targetUserId) || targetUserId <= 0)) {
            throw new PendingAuthError("pending_auth_invalid", 400, "target user ID is invalid");
        }
        const now = this.#clock();
        const expiresAt = input.expiresAt ?? now + DEFAULT_SESSION_TTL_MS;
        if (!Number.isFinite(expiresAt) || expiresAt <= now || expiresAt > now + 24 * 60 * 60 * 1000) {
            throw new PendingAuthError("pending_auth_invalid", 400, "pending auth expiry is invalid");
        }
        const createdAt = new Date(now).toISOString();
        const session = await this.#repository.create({
            sessionTokenHash: await sha256Hex(sessionToken),
            intent,
            providerType,
            providerKey,
            providerSubject,
            targetUserId,
            redirectTo: boundedText(input.redirectTo ?? "", "redirect", 2048),
            resolvedEmail: boundedText(input.resolvedEmail ?? "", "resolved email", 254),
            registrationPasswordHash: boundedText(
                input.registrationPasswordHash ?? "",
                "registration password hash",
                255
            ),
            upstreamIdentityClaims: objectCopy(input.upstreamIdentityClaims),
            localFlowState: objectCopy(input.localFlowState),
            browserSessionKey: boundedText(input.browserSessionKey ?? "", "browser session key", 255),
            expiresAt: new Date(expiresAt).toISOString(),
            createdAt
        });
        return { session, sessionToken };
    }

    async issueCompletionCode(
        pendingAuthSessionId: number,
        browserSessionKey = "",
        ttlMs = DEFAULT_COMPLETION_TTL_MS
    ): Promise<{ code: string; expiresAt: string }> {
        positiveId(pendingAuthSessionId, "pending auth session ID");
        if (!Number.isInteger(ttlMs) || ttlMs <= 0 || ttlMs > 30 * 60 * 1000) {
            throw new PendingAuthError("pending_auth_invalid", 400, "completion-code TTL is invalid");
        }
        const code = opaqueToken(this.#opaqueTokenFactory());
        const now = this.#clock();
        const expiresAt = new Date(now + ttlMs).toISOString();
        const issued = await this.#repository.issueCompletionCode(
            pendingAuthSessionId,
            await sha256Hex(code),
            boundedText(browserSessionKey, "browser session key", 255),
            expiresAt,
            new Date(now).toISOString()
        );
        if (!issued) throw pendingError("not_found");
        return { code, expiresAt };
    }

    async getBrowserSession(sessionTokenValue: string, browserSessionKey = ""): Promise<PendingAuthSessionRecord> {
        const session = await this.#findBySessionToken(sessionTokenValue);
        this.#validate(session, browserSessionKey, "session");
        return session;
    }

    async consumeBrowserSession(
        sessionTokenValue: string,
        browserSessionKey = ""
    ): Promise<PendingAuthSessionRecord> {
        const session = await this.#findBySessionToken(sessionTokenValue);
        return this.#consume(session, browserSessionKey, "session");
    }

    async consumeCompletionCode(
        codeValue: string,
        browserSessionKey = ""
    ): Promise<PendingAuthSessionRecord> {
        const code = codeValue.trim();
        if (code === "") throw pendingError("code_invalid");
        const session = await this.#repository.findByCompletionCodeHash(await sha256Hex(code));
        if (session === null) throw pendingError("code_invalid");
        return this.#consume(session, browserSessionKey, "code");
    }

    async transitionAccountChoice(
        sessionTokenValue: string,
        browserSessionKey: string,
        emailValue: string,
        targetUserId: number
    ): Promise<PendingAuthSessionRecord> {
        positiveId(targetUserId, "target user ID");
        const email = boundedText(emailValue, "resolved email", 254).toLowerCase();
        if (!/^[^\s@]+@[^\s@]+$/u.test(email)) {
            throw new PendingAuthError("pending_auth_invalid", 400, "resolved email is invalid");
        }
        const session = await this.#findBySessionToken(sessionTokenValue);
        this.#validate(session, browserSessionKey, "session");
        const completion = {
            ...objectValue(session.localFlowState.completion_response),
            step: "choose_account_action_required",
            adoption_required: true,
            force_email_on_signup: true,
            email_binding_required: true,
            existing_account_bindable: true,
            email,
            resolved_email: email
        };
        const updatedAt = new Date(this.#clock()).toISOString();
        const updated = await this.#repository.transitionAccountChoice({
            id: session.id,
            browserSessionKey: browserSessionKey.trim(),
            email,
            targetUserId,
            localFlowState: { ...session.localFlowState, completion_response: completion },
            updatedAt
        });
        if (updated === null) throw pendingError("session_consumed");
        return updated;
    }

    async upsertAdoptionDecision(input: {
        pendingAuthSessionId: number;
        identityId?: number;
        adoptDisplayName: boolean;
        adoptAvatar: boolean;
    }): Promise<IdentityAdoptionDecisionRecord> {
        positiveId(input.pendingAuthSessionId, "pending auth session ID");
        const identityId = input.identityId ?? null;
        if (identityId !== null) positiveId(identityId, "identity ID");
        return this.#repository.upsertAdoptionDecision({
            pendingAuthSessionId: input.pendingAuthSessionId,
            identityId,
            adoptDisplayName: input.adoptDisplayName,
            adoptAvatar: input.adoptAvatar,
            decidedAt: new Date(this.#clock()).toISOString()
        });
    }

    async #findBySessionToken(sessionTokenValue: string): Promise<PendingAuthSessionRecord> {
        const token = sessionTokenValue.trim();
        if (token === "") throw pendingError("not_found");
        const session = await this.#repository.findBySessionTokenHash(await sha256Hex(token));
        if (session === null) throw pendingError("not_found");
        return session;
    }

    async #consume(
        session: PendingAuthSessionRecord,
        browserSessionKey: string,
        mode: "session" | "code"
    ): Promise<PendingAuthSessionRecord> {
        this.#validate(session, browserSessionKey, mode);
        const nowIso = new Date(this.#clock()).toISOString();
        const consumed = await this.#repository.consume(
            session.id,
            browserSessionKey.trim(),
            sanitizeLocalFlowState(session.localFlowState),
            nowIso
        );
        if (consumed !== null) return consumed;
        const current = await this.#repository.findById(session.id);
        if (current === null) throw pendingError("not_found");
        this.#validate(current, browserSessionKey, mode);
        throw pendingError(mode === "code" ? "code_consumed" : "session_consumed");
    }

    #validate(
        session: PendingAuthSessionRecord,
        browserSessionKey: string,
        mode: "session" | "code"
    ): void {
        if (session.consumedAt !== null) {
            throw pendingError(mode === "code" ? "code_consumed" : "session_consumed");
        }
        const now = this.#clock();
        const completionExpired = session.completionCodeExpiresAt !== null
            && Date.parse(session.completionCodeExpiresAt) < now;
        if (Date.parse(session.expiresAt) < now || completionExpired) {
            throw pendingError(mode === "code" ? "code_expired" : "session_expired");
        }
        const expectedBrowser = session.browserSessionKey.trim();
        if (expectedBrowser !== "" && expectedBrowser !== browserSessionKey.trim()) {
            throw pendingError("browser_mismatch");
        }
    }
}

function sanitizeLocalFlowState(value: Record<string, unknown>): Record<string, unknown> {
    const sanitized = objectCopy(value);
    const completion = sanitized.completion_response;
    if (completion === null || typeof completion !== "object" || Array.isArray(completion)) {
        return sanitized;
    }
    const cleaned = { ...(completion as Record<string, unknown>) };
    for (const key of ["access_token", "refresh_token", "expires_in", "token_type"]) {
        delete cleaned[key];
    }
    sanitized.completion_response = cleaned;
    return sanitized;
}

function objectValue(value: unknown): Record<string, unknown> {
    return value !== null && typeof value === "object" && !Array.isArray(value)
        ? { ...(value as Record<string, unknown>) }
        : {};
}

function pendingError(kind: string): PendingAuthError {
    const values: Record<string, [string, number, string]> = {
        not_found: ["pending_auth_session_not_found", 404, "pending auth session not found"],
        session_expired: ["pending_auth_session_expired", 401, "pending auth session has expired"],
        session_consumed: ["pending_auth_session_consumed", 401, "pending auth session has already been used"],
        code_invalid: ["pending_auth_code_invalid", 401, "pending auth completion code is invalid"],
        code_expired: ["pending_auth_code_expired", 401, "pending auth completion code has expired"],
        code_consumed: ["pending_auth_code_consumed", 401, "pending auth completion code has already been used"],
        browser_mismatch: ["pending_auth_browser_mismatch", 401, "pending auth completion code does not match this browser session"]
    };
    const [code, status, message] = values[kind] ?? values.not_found;
    return new PendingAuthError(code, status, message);
}

function opaqueToken(value: string): string {
    const token = value.trim();
    if (token === "" || token.length > 255) {
        throw new PendingAuthError("pending_auth_invalid", 400, "opaque token is invalid");
    }
    return token;
}

function requiredText(value: string, field: string): string {
    const normalized = value.trim();
    if (normalized === "") {
        throw new PendingAuthError("pending_auth_invalid", 400, `${field} is required`);
    }
    return normalized;
}

function boundedText(value: string, field: string, maximum: number): string {
    const normalized = value.trim();
    if (normalized.length > maximum) {
        throw new PendingAuthError("pending_auth_invalid", 400, `${field} is too long`);
    }
    return normalized;
}

function enumValue<T extends string>(value: string, allowed: readonly T[], field: string): T {
    const normalized = value.trim().toLowerCase();
    if (!allowed.includes(normalized as T)) {
        throw new PendingAuthError("pending_auth_invalid", 400, `invalid ${field}`);
    }
    return normalized as T;
}

function positiveId(value: number, field: string): void {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new PendingAuthError("pending_auth_invalid", 400, `${field} is invalid`);
    }
}

function objectCopy(value: Record<string, unknown> | undefined): Record<string, unknown> {
    return value === undefined ? {} : { ...value };
}
