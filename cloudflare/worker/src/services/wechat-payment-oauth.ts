import type { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import {
    base64UrlDecode,
    base64UrlEncode,
    decodeUtf8,
    hexToBytes,
    randomHex,
    sha256Hex,
    utf8
} from "../utils/crypto.ts";

const PAYMENT_STATE_TTL_MS = 10 * 60 * 1000;
const RESUME_TOKEN_TTL_SECONDS = 15 * 60;

export interface WeChatPaymentOAuthState {
    browserSessionKey: string;
    paymentType: "wxpay" | "wxpay_direct";
    amount: string;
    orderType: string;
    planId: number;
    redirectTo: string;
    scope: "snsapi_base" | "snsapi_userinfo";
}

export interface WeChatPaymentResumeClaims {
    tk: "wechat_payment_resume";
    openid: string;
    pt: "wxpay";
    amt?: string;
    ot: string;
    pid?: number;
    rd: string;
    scp: string;
    iat: number;
    exp: number;
}

export class WeChatPaymentOAuthError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "WeChatPaymentOAuthError";
        this.code = code;
        this.status = status;
    }
}

export class D1WeChatPaymentOAuthStateService {
    readonly #state: D1ExpiringStateRepository;
    readonly #tokens: () => string;

    constructor(state: D1ExpiringStateRepository, tokenFactory: () => string = () => randomHex(32)) {
        this.#state = state;
        this.#tokens = tokenFactory;
    }

    async create(input: Omit<WeChatPaymentOAuthState, "browserSessionKey">) {
        const state = opaque(this.#tokens());
        const browserSessionKey = opaque(this.#tokens());
        const value = { ...input, browserSessionKey } satisfies WeChatPaymentOAuthState;
        await this.#state.put(await stateKey(state, browserSessionKey), value, PAYMENT_STATE_TTL_MS);
        return { state, browserSessionKey };
    }

    async consume(stateValue: string, browserValue: string): Promise<WeChatPaymentOAuthState> {
        const state = opaque(stateValue);
        const browser = opaque(browserValue);
        const stored = await this.#state.take<WeChatPaymentOAuthState>(await stateKey(state, browser));
        if (stored === null || stored.value.browserSessionKey !== browser) {
            throw new WeChatPaymentOAuthError("invalid_state", 400, "invalid or expired payment oauth state");
        }
        return stored.value;
    }
}

export class WeChatPaymentResumeService {
    readonly #signingKey: Uint8Array;
    readonly #verifyKeys: readonly Uint8Array[];
    readonly #clock: () => number;

    constructor(signingKey: Uint8Array, verifyFallbacks: readonly Uint8Array[] = [], clock: () => number = Date.now) {
        if (signingKey.byteLength === 0) {
            throw new WeChatPaymentOAuthError(
                "payment_resume_not_configured",
                503,
                "payment resume tokens require a configured signing key"
            );
        }
        this.#signingKey = signingKey.slice();
        this.#verifyKeys = uniqueKeys([this.#signingKey, ...verifyFallbacks]);
        this.#clock = clock;
    }

    async create(input: {
        openId: string;
        paymentType: string;
        amount: string;
        orderType: string;
        planId: number;
        redirectTo: string;
        scope: string;
    }): Promise<string> {
        const openId = input.openId.trim();
        if (!/^[A-Za-z0-9_-]{1,128}$/u.test(openId)) {
            throw new WeChatPaymentOAuthError("invalid_context", 400, "wechat payment openid is invalid");
        }
        const now = Math.floor(this.#clock() / 1000);
        const claims: WeChatPaymentResumeClaims = {
            tk: "wechat_payment_resume",
            openid: openId,
            pt: normalizePaymentType(input.paymentType),
            ...(input.amount.trim() === "" ? {} : { amt: bounded(input.amount, 64) }),
            ot: bounded(input.orderType, 64) || "balance",
            ...(input.planId > 0 ? { pid: input.planId } : {}),
            rd: normalizePaymentRedirect(input.redirectTo),
            scp: normalizePaymentScope(input.scope),
            iat: now,
            exp: now + RESUME_TOKEN_TTL_SECONDS
        };
        const payload = base64UrlEncode(JSON.stringify(claims));
        return `${payload}.${await sign(payload, this.#signingKey)}`;
    }

    async parse(tokenValue: string): Promise<WeChatPaymentResumeClaims> {
        const parts = tokenValue.trim().split(".");
        if (parts.length !== 2 || parts[0] === "" || parts[1] === "") {
            throw invalidResumeToken();
        }
        let verified = false;
        for (const key of this.#verifyKeys) {
            if (await verify(parts[0], parts[1], key)) {
                verified = true;
                break;
            }
        }
        if (!verified) throw invalidResumeToken();
        let value: unknown;
        try { value = JSON.parse(decodeUtf8(base64UrlDecode(parts[0]))); } catch { throw invalidResumeToken(); }
        if (!isObject(value) || value.tk !== "wechat_payment_resume") throw invalidResumeToken();
        const expiresAt = number(value.exp);
        const issuedAt = number(value.iat);
        const openId = text(value.openid);
        if (openId === "" || expiresAt <= Math.floor(this.#clock() / 1000) || issuedAt <= 0) {
            throw invalidResumeToken();
        }
        return {
            tk: "wechat_payment_resume",
            openid: openId,
            pt: normalizePaymentType(text(value.pt)),
            ...(text(value.amt) === "" ? {} : { amt: bounded(text(value.amt), 64) }),
            ot: bounded(text(value.ot), 64) || "balance",
            ...(number(value.pid) > 0 ? { pid: number(value.pid) } : {}),
            rd: normalizePaymentRedirect(text(value.rd)),
            scp: normalizePaymentScope(text(value.scp)),
            iat: issuedAt,
            exp: expiresAt
        };
    }
}

export function resolvePaymentResumeKeys(env: {
    PAYMENT_RESUME_SIGNING_KEY?: string;
    TOTP_ENCRYPTION_KEY?: string;
}): { signingKey: Uint8Array; verifyFallbacks: Uint8Array[] } {
    const explicit = env.PAYMENT_RESUME_SIGNING_KEY?.trim() ?? "";
    const legacy = legacyKey(env.TOTP_ENCRYPTION_KEY);
    if (explicit !== "") {
        return {
            signingKey: utf8(explicit),
            verifyFallbacks: legacy === null ? [] : [legacy]
        };
    }
    if (legacy !== null) return { signingKey: legacy, verifyFallbacks: [] };
    throw new WeChatPaymentOAuthError(
        "payment_resume_not_configured",
        503,
        "payment resume tokens require PAYMENT_RESUME_SIGNING_KEY"
    );
}

export function normalizePaymentType(value: string): "wxpay" {
    const type = value.trim();
    if (type !== "wxpay" && type !== "wxpay_direct") {
        throw new WeChatPaymentOAuthError("invalid_payment_type", 400, "Invalid payment type");
    }
    return "wxpay";
}

export function normalizePaymentScope(value: string): "snsapi_base" | "snsapi_userinfo" {
    const values = value.trim().split(/[\s,]+/u);
    return values.includes("snsapi_userinfo") ? "snsapi_userinfo" : "snsapi_base";
}

export function normalizePaymentRedirect(value: string): string {
    const path = value.trim();
    if (path === "" || !path.startsWith("/") || path.startsWith("//") || path.length > 2048) return "/purchase";
    if (path === "/payment") return "/purchase";
    if (path.startsWith("/payment?")) return `/purchase${path.slice("/payment".length)}`;
    return path;
}

export function parsePaymentPlanId(value: string): number {
    const parsed = Number(value.trim());
    return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : 0;
}

async function stateKey(state: string, browser: string): Promise<string> {
    return `oauth-wechat-payment-state:${await sha256Hex(`${state}\n${browser}`)}`;
}

async function sign(payload: string, key: Uint8Array): Promise<string> {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key as BufferSource,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );
    return base64UrlEncode(new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, utf8(payload))));
}

async function verify(payload: string, signature: string, key: Uint8Array): Promise<boolean> {
    let decoded: Uint8Array;
    try { decoded = base64UrlDecode(signature); } catch { return false; }
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key as BufferSource,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["verify"]
    );
    return crypto.subtle.verify("HMAC", cryptoKey, decoded as BufferSource, utf8(payload));
}

function opaque(value: string): string {
    const result = value.trim();
    if (!/^[A-Za-z0-9_-]{32,256}$/u.test(result)) {
        throw new WeChatPaymentOAuthError("invalid_state", 400, "invalid payment oauth state");
    }
    return result;
}

function legacyKey(value: string | undefined): Uint8Array | null {
    const raw = value?.trim() ?? "";
    if (!/^[a-f0-9]{64}$/iu.test(raw)) return null;
    return hexToBytes(raw);
}

function uniqueKeys(values: readonly Uint8Array[]): Uint8Array[] {
    const seen = new Set<string>();
    return values.filter((value) => {
        const key = base64UrlEncode(value);
        if (seen.has(key) || value.byteLength === 0) return false;
        seen.add(key);
        return true;
    });
}

function invalidResumeToken(): WeChatPaymentOAuthError {
    return new WeChatPaymentOAuthError(
        "invalid_wechat_payment_resume_token",
        400,
        "wechat payment resume token payload is invalid"
    );
}

function bounded(value: string, maximum: number): string {
    return value.trim().slice(0, maximum);
}

function text(value: unknown): string {
    return typeof value === "string" || typeof value === "number" ? String(value).trim() : "";
}

function number(value: unknown): number {
    return typeof value === "number" && Number.isSafeInteger(value) ? value : 0;
}

function isObject(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}
