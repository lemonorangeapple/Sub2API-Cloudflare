import type { D1ExpiringStateRepository } from "../repositories/expiring-state.ts";
import {
    base64Encode,
    base64UrlDecode,
    base64UrlEncode,
    decodeUtf8,
    randomHex,
    sha256,
    sha256Hex,
    utf8
} from "../utils/crypto.ts";

const STATE_TTL_MS = 10 * 60 * 1000;
const SYNTHETIC_EMAIL_DOMAIN = "@oidc-connect.invalid";
const SUPPORTED_ALGORITHMS = ["RS256", "PS256", "ES256"] as const;

type SupportedAlgorithm = typeof SUPPORTED_ALGORITHMS[number];

export interface OIDCOAuthConfig {
    enabled: boolean;
    providerName: string;
    clientId: string;
    clientSecret: string;
    issuerUrl: string;
    discoveryUrl: string;
    authorizeUrl: string;
    tokenUrl: string;
    userInfoUrl: string;
    jwksUrl: string;
    scopes: string;
    redirectUrl: string;
    frontendRedirectUrl: string;
    tokenAuthMethod: "client_secret_post" | "client_secret_basic" | "none";
    usePkce: boolean;
    validateIdToken: boolean;
    allowedSigningAlgs: SupportedAlgorithm[];
    clockSkewSeconds: number;
    requireEmailVerified: boolean;
    userInfoEmailPath: string;
    userInfoIdPath: string;
    userInfoUsernamePath: string;
}

export interface OIDCOAuthState {
    browserSessionKey: string;
    redirectTo: string;
    intent: "login" | "bind_current_user";
    bindUserId: number | null;
    promoCode: string;
    codeVerifier: string;
    nonce: string;
}

export interface OIDCOAuthStartResult {
    authorizeUrl: string;
    state: string;
    browserSessionKey: string;
}

export interface OIDCProviderUser {
    syntheticEmail: string;
    compatEmail: string;
    username: string;
    subject: string;
    issuer: string;
    emailVerified: boolean | null;
    displayName: string;
    avatarUrl: string;
}

interface OIDCTokenResponse {
    accessToken: string;
    tokenType: string;
    idToken: string;
}

interface ProviderMetadata {
    issuer?: unknown;
    authorization_endpoint?: unknown;
    token_endpoint?: unknown;
    userinfo_endpoint?: unknown;
    jwks_uri?: unknown;
}

export class OIDCOAuthError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "OIDCOAuthError";
        this.code = code;
        this.status = status;
    }
}

export class D1OIDCOAuthStateService {
    readonly #state: D1ExpiringStateRepository;
    readonly #opaqueTokenFactory: () => string;

    constructor(
        state: D1ExpiringStateRepository,
        opaqueTokenFactory: () => string = () => randomHex(32)
    ) {
        this.#state = state;
        this.#opaqueTokenFactory = opaqueTokenFactory;
    }

    async create(
        config: OIDCOAuthConfig,
        input: Omit<OIDCOAuthState, "browserSessionKey" | "codeVerifier" | "nonce">
    ): Promise<OIDCOAuthStartResult> {
        validateConfig(config);
        const state = opaqueToken(this.#opaqueTokenFactory());
        const browserSessionKey = opaqueToken(this.#opaqueTokenFactory());
        const codeVerifier = config.usePkce ? opaqueToken(this.#opaqueTokenFactory()) : "";
        const nonce = config.validateIdToken ? opaqueToken(this.#opaqueTokenFactory()) : "";
        await this.#state.put(await stateKey(state, browserSessionKey), {
            ...input,
            browserSessionKey,
            codeVerifier,
            nonce
        } satisfies OIDCOAuthState, STATE_TTL_MS);

        const url = new URL(config.authorizeUrl);
        url.searchParams.set("response_type", "code");
        url.searchParams.set("client_id", config.clientId);
        url.searchParams.set("redirect_uri", config.redirectUrl);
        url.searchParams.set("scope", config.scopes);
        url.searchParams.set("state", state);
        if (nonce !== "") url.searchParams.set("nonce", nonce);
        if (codeVerifier !== "") {
            url.searchParams.set("code_challenge", base64UrlEncode(await sha256(codeVerifier)));
            url.searchParams.set("code_challenge_method", "S256");
        }
        return { authorizeUrl: url.toString(), state, browserSessionKey };
    }

    async consume(stateValue: string, browserSessionKeyValue: string): Promise<OIDCOAuthState> {
        const state = opaqueToken(stateValue);
        const browserSessionKey = opaqueToken(browserSessionKeyValue);
        const stored = await this.#state.take<OIDCOAuthState>(await stateKey(state, browserSessionKey));
        if (stored === null) throw new OIDCOAuthError("invalid_state", 400, "invalid or expired oauth state");
        return stored.value;
    }
}

export class OIDCOAuthClient {
    readonly #fetch: typeof fetch;
    readonly #clock: () => number;

    constructor(fetchImplementation: typeof fetch = fetch, clock: () => number = Date.now) {
        this.#fetch = fetchImplementation;
        this.#clock = clock;
    }

    async fetchUser(
        config: OIDCOAuthConfig,
        codeValue: string,
        state: Pick<OIDCOAuthState, "codeVerifier" | "nonce">
    ): Promise<OIDCProviderUser> {
        validateConfig(config);
        const code = codeValue.trim();
        if (code === "") throw new OIDCOAuthError("missing_params", 400, "missing oauth code");
        const token = await this.#exchange(config, code, state.codeVerifier);
        let idClaims: Record<string, unknown> = {};
        if (config.validateIdToken) {
            if (token.idToken === "") {
                throw new OIDCOAuthError("missing_id_token", 502, "missing id_token");
            }
            idClaims = await validateOIDCIDToken(
                token.idToken,
                config,
                state.nonce,
                this.#fetch,
                this.#clock()
            );
        }
        const userInfo = await this.#userinfo(config, token);
        const idSubject = stringValue(idClaims.sub);
        const infoSubject = firstPath(userInfo, [config.userInfoIdPath, "sub", "id", "user_id", "uid", "user.id"]);
        if (idSubject !== "" && infoSubject !== "" && idSubject !== infoSubject) {
            throw new OIDCOAuthError("subject_mismatch", 502, "userinfo subject does not match id_token");
        }
        const subject = idSubject || infoSubject;
        if (subject === "" || subject.length > 255 || /[\u0000-\u001f\u007f]/u.test(subject)) {
            throw new OIDCOAuthError("missing_subject", 502, "oauth identity subject is invalid");
        }
        const issuer = stringValue(idClaims.iss) || config.issuerUrl;
        const infoEmail = firstPath(userInfo, [
            config.userInfoEmailPath, "email", "user.email", "data.email", "attributes.email"
        ]);
        const compatEmail = infoEmail || stringValue(idClaims.email);
        const verified = booleanValue(userInfo.email_verified) ?? booleanValue(idClaims.email_verified);
        if (config.requireEmailVerified && verified !== true) {
            throw new OIDCOAuthError("email_not_verified", 403, "email is not verified");
        }
        const username = firstPath(userInfo, [
            config.userInfoUsernamePath,
            "preferred_username",
            "username",
            "name",
            "user.username",
            "user.name"
        ]) || stringValue(idClaims.preferred_username) || stringValue(idClaims.name) || fallbackUsername(subject);
        const displayName = firstPath(userInfo, [
            "name", "nickname", "display_name", "preferred_username", "username"
        ]) || stringValue(idClaims.name) || username;
        const avatarUrl = firstPath(userInfo, [
            "picture", "avatar_url", "avatar", "profile_image_url", "user.avatar", "user.avatar_url"
        ]);
        return {
            syntheticEmail: await syntheticEmail(issuer, subject),
            compatEmail,
            username,
            subject,
            issuer,
            emailVerified: verified,
            displayName,
            avatarUrl
        };
    }

    async #exchange(config: OIDCOAuthConfig, code: string, codeVerifier: string): Promise<OIDCTokenResponse> {
        const form = new URLSearchParams({
            grant_type: "authorization_code",
            client_id: config.clientId,
            code,
            redirect_uri: config.redirectUrl
        });
        if (codeVerifier !== "") form.set("code_verifier", codeVerifier);
        const headers = new Headers({ accept: "application/json", "content-type": "application/x-www-form-urlencoded" });
        if (config.tokenAuthMethod === "client_secret_post") {
            form.set("client_secret", config.clientSecret);
        } else if (config.tokenAuthMethod === "client_secret_basic") {
            headers.set("authorization", `Basic ${base64Encode(utf8(`${config.clientId}:${config.clientSecret}`))}`);
        }
        let response: Response;
        try {
            response = await this.#fetch(config.tokenUrl, { method: "POST", headers, body: form.toString() });
        } catch {
            throw new OIDCOAuthError("token_exchange_failed", 502, "failed to exchange oauth code");
        }
        const body = await response.text();
        if (!response.ok) {
            throw new OIDCOAuthError(
                "token_exchange_failed",
                502,
                providerErrorMessage(body, "failed to exchange oauth code")
            );
        }
        const parsed = parseTokenResponse(body);
        if (parsed.accessToken === "" && parsed.idToken === "") {
            throw new OIDCOAuthError("token_exchange_failed", 502, "oauth token response is invalid");
        }
        return parsed;
    }

    async #userinfo(config: OIDCOAuthConfig, token: OIDCTokenResponse): Promise<Record<string, unknown>> {
        if (config.userInfoUrl === "") return {};
        if (token.accessToken === "") {
            throw new OIDCOAuthError("userinfo_failed", 502, "missing access_token for userinfo request");
        }
        let response: Response;
        try {
            response = await this.#fetch(config.userInfoUrl, {
                headers: {
                    accept: "application/json",
                    authorization: `${token.tokenType || "Bearer"} ${token.accessToken}`
                }
            });
        } catch {
            throw new OIDCOAuthError("userinfo_failed", 502, "failed to fetch oauth user info");
        }
        if (!response.ok) throw new OIDCOAuthError("userinfo_failed", 502, "failed to fetch oauth user info");
        return parseObject(await response.text(), "oauth user info response is invalid");
    }
}

export async function resolveOIDCOAuthConfig(
    settings: Record<string, string>,
    env: Record<string, string | undefined>,
    fetchImplementation: typeof fetch = fetch
): Promise<OIDCOAuthConfig> {
    const issuerUrl = firstNonEmpty(settings.oidc_connect_issuer_url, env.OIDC_ISSUER_URL);
    const discoveryUrl = firstNonEmpty(
        settings.oidc_connect_discovery_url,
        env.OIDC_DISCOVERY_URL,
        issuerUrl === "" ? "" : `${issuerUrl.replace(/\/+$/u, "")}/.well-known/openid-configuration`
    );
    let authorizeUrl = firstNonEmpty(settings.oidc_connect_authorize_url, env.OIDC_AUTHORIZE_URL);
    let tokenUrl = firstNonEmpty(settings.oidc_connect_token_url, env.OIDC_TOKEN_URL);
    let userInfoUrl = firstNonEmpty(settings.oidc_connect_userinfo_url, env.OIDC_USERINFO_URL);
    let jwksUrl = firstNonEmpty(settings.oidc_connect_jwks_url, env.OIDC_JWKS_URL);
    const validateIdToken = booleanSetting(settings.oidc_connect_validate_id_token, env.OIDC_VALIDATE_ID_TOKEN, true);
    if (authorizeUrl === "" || tokenUrl === "" || (validateIdToken && jwksUrl === "")) {
        assertHttpUrl(discoveryUrl, "oauth discovery url");
        let response: Response;
        try {
            response = await fetchImplementation(discoveryUrl, { headers: { accept: "application/json" } });
        } catch {
            throw new OIDCOAuthError("oauth_config_invalid", 503, "oauth discovery resolve failed");
        }
        if (!response.ok) throw new OIDCOAuthError("oauth_config_invalid", 503, "oauth discovery resolve failed");
        const metadata = parseObject(await response.text(), "oauth discovery document is invalid") as ProviderMetadata;
        const discoveredIssuer = stringValue(metadata.issuer);
        if (discoveredIssuer !== "" && discoveredIssuer !== issuerUrl) {
            throw new OIDCOAuthError("oauth_config_invalid", 503, "oauth discovery issuer mismatch");
        }
        authorizeUrl ||= stringValue(metadata.authorization_endpoint);
        tokenUrl ||= stringValue(metadata.token_endpoint);
        userInfoUrl ||= stringValue(metadata.userinfo_endpoint);
        jwksUrl ||= stringValue(metadata.jwks_uri);
    }
    const tokenAuthMethod = firstNonEmpty(
        settings.oidc_connect_token_auth_method,
        env.OIDC_TOKEN_AUTH_METHOD,
        "client_secret_post"
    ).toLowerCase();
    if (!isTokenAuthMethod(tokenAuthMethod)) {
        throw new OIDCOAuthError("oauth_config_invalid", 503, "oauth token auth method is invalid");
    }
    const config: OIDCOAuthConfig = {
        enabled: settings.oidc_connect_enabled === "true" || env.OIDC_ENABLED?.trim().toLowerCase() === "true",
        providerName: firstNonEmpty(settings.oidc_connect_provider_name, env.OIDC_PROVIDER_NAME, "OIDC"),
        clientId: firstNonEmpty(settings.oidc_connect_client_id, env.OIDC_CLIENT_ID),
        clientSecret: firstNonEmpty(settings.oidc_connect_client_secret, env.OIDC_CLIENT_SECRET),
        issuerUrl,
        discoveryUrl,
        authorizeUrl,
        tokenUrl,
        userInfoUrl,
        jwksUrl,
        scopes: firstNonEmpty(settings.oidc_connect_scopes, env.OIDC_SCOPES, "openid email profile"),
        redirectUrl: firstNonEmpty(settings.oidc_connect_redirect_url, env.OIDC_REDIRECT_URL),
        frontendRedirectUrl: firstNonEmpty(
            settings.oidc_connect_frontend_redirect_url,
            env.OIDC_FRONTEND_REDIRECT_URL,
            "/auth/oidc/callback"
        ),
        tokenAuthMethod,
        usePkce: booleanSetting(settings.oidc_connect_use_pkce, env.OIDC_USE_PKCE, true),
        validateIdToken,
        allowedSigningAlgs: parseAlgorithms(firstNonEmpty(
            settings.oidc_connect_allowed_signing_algs,
            env.OIDC_ALLOWED_SIGNING_ALGS,
            "RS256,ES256,PS256"
        )),
        clockSkewSeconds: boundedInteger(
            firstNonEmpty(settings.oidc_connect_clock_skew_seconds, env.OIDC_CLOCK_SKEW_SECONDS),
            120,
            0,
            600
        ),
        requireEmailVerified: booleanSetting(
            settings.oidc_connect_require_email_verified,
            env.OIDC_REQUIRE_EMAIL_VERIFIED,
            false
        ),
        userInfoEmailPath: firstNonEmpty(settings.oidc_connect_userinfo_email_path, env.OIDC_USERINFO_EMAIL_PATH),
        userInfoIdPath: firstNonEmpty(settings.oidc_connect_userinfo_id_path, env.OIDC_USERINFO_ID_PATH),
        userInfoUsernamePath: firstNonEmpty(
            settings.oidc_connect_userinfo_username_path,
            env.OIDC_USERINFO_USERNAME_PATH
        )
    };
    validateConfig(config);
    return config;
}

export async function validateOIDCIDToken(
    token: string,
    config: OIDCOAuthConfig,
    expectedNonce: string,
    fetchImplementation: typeof fetch = fetch,
    nowMs = Date.now()
): Promise<Record<string, unknown>> {
    const parts = token.trim().split(".");
    if (parts.length !== 3 || parts.some((part) => part === "")) {
        throw new OIDCOAuthError("invalid_id_token", 502, "id_token is malformed");
    }
    let header: Record<string, unknown>;
    let claims: Record<string, unknown>;
    try {
        header = parseObject(decodeUtf8(base64UrlDecode(parts[0])), "id_token header is invalid");
        claims = parseObject(decodeUtf8(base64UrlDecode(parts[1])), "id_token claims are invalid");
    } catch {
        throw new OIDCOAuthError("invalid_id_token", 502, "id_token is malformed");
    }
    const algorithm = stringValue(header.alg).toUpperCase();
    if (!isSupportedAlgorithm(algorithm) || !config.allowedSigningAlgs.includes(algorithm)) {
        throw new OIDCOAuthError("invalid_id_token", 502, "id_token signing algorithm is not allowed");
    }
    let jwksResponse: Response;
    try {
        jwksResponse = await fetchImplementation(config.jwksUrl, { headers: { accept: "application/json" } });
    } catch {
        throw new OIDCOAuthError("invalid_id_token", 502, "failed to load oidc signing keys");
    }
    if (!jwksResponse.ok) {
        throw new OIDCOAuthError("invalid_id_token", 502, "failed to load oidc signing keys");
    }
    const jwks = parseObject(await jwksResponse.text(), "oidc signing keys are invalid");
    const keys = Array.isArray(jwks.keys) ? jwks.keys.filter(isObject) : [];
    const jwk = selectJwk(keys, stringValue(header.kid), algorithm);
    const cryptoAlgorithm = importAlgorithm(algorithm);
    let key: CryptoKey;
    try {
        key = await crypto.subtle.importKey("jwk", jwk as JsonWebKey, cryptoAlgorithm, false, ["verify"]);
    } catch {
        throw new OIDCOAuthError("invalid_id_token", 502, "oidc signing key is invalid");
    }
    const verifyAlgorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams = algorithm === "PS256"
        ? { name: "RSA-PSS", saltLength: 32 }
        : algorithm === "ES256"
            ? { name: "ECDSA", hash: "SHA-256" }
            : { name: "RSASSA-PKCS1-v1_5" };
    const valid = await crypto.subtle.verify(
        verifyAlgorithm,
        key,
        base64UrlDecode(parts[2]),
        utf8(`${parts[0]}.${parts[1]}`)
    );
    if (!valid) throw new OIDCOAuthError("invalid_id_token", 502, "id_token signature is invalid");
    validateClaims(claims, config, expectedNonce, nowMs);
    return claims;
}

function validateClaims(
    claims: Record<string, unknown>,
    config: OIDCOAuthConfig,
    expectedNonce: string,
    nowMs: number
): void {
    if (stringValue(claims.iss) !== config.issuerUrl) claimError("issuer mismatch");
    const audience = typeof claims.aud === "string"
        ? [claims.aud]
        : Array.isArray(claims.aud) ? claims.aud.filter((value): value is string => typeof value === "string") : [];
    if (!audience.includes(config.clientId)) claimError("audience mismatch");
    const authorizedParty = stringValue(claims.azp);
    if ((audience.length > 1 || authorizedParty !== "") && authorizedParty !== config.clientId) {
        claimError("authorized party mismatch");
    }
    if (stringValue(claims.sub) === "") claimError("subject is missing");
    if (expectedNonce !== "" && stringValue(claims.nonce) !== expectedNonce) claimError("nonce mismatch");
    const now = Math.floor(nowMs / 1000);
    const skew = config.clockSkewSeconds;
    const expiresAt = numericClaim(claims.exp);
    const issuedAt = numericClaim(claims.iat);
    if (expiresAt === null || expiresAt < now - skew) claimError("token is expired");
    if (issuedAt === null || issuedAt > now + skew) claimError("issued-at time is invalid");
    const notBefore = claims.nbf === undefined ? null : numericClaim(claims.nbf);
    if (claims.nbf !== undefined && (notBefore === null || notBefore > now + skew)) {
        claimError("not-before time is invalid");
    }
}

function selectJwk(
    keys: Record<string, unknown>[],
    kid: string,
    algorithm: SupportedAlgorithm
): Record<string, unknown> {
    const expectedType = algorithm === "ES256" ? "EC" : "RSA";
    const matches = keys.filter((key) => {
        const use = stringValue(key.use);
        const declaredAlgorithm = stringValue(key.alg).toUpperCase();
        return stringValue(key.kty).toUpperCase() === expectedType
            && (use === "" || use === "sig")
            && (declaredAlgorithm === "" || declaredAlgorithm === algorithm)
            && (kid === "" || stringValue(key.kid) === kid);
    });
    if (matches.length !== 1) {
        throw new OIDCOAuthError("invalid_id_token", 502, "a unique oidc signing key was not found");
    }
    return matches[0];
}

function importAlgorithm(algorithm: SupportedAlgorithm): RsaHashedImportParams | EcKeyImportParams {
    if (algorithm === "ES256") return { name: "ECDSA", namedCurve: "P-256" };
    return { name: algorithm === "PS256" ? "RSA-PSS" : "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
}

function parseTokenResponse(body: string): OIDCTokenResponse {
    try {
        const parsed = parseObject(body, "oauth token response is invalid");
        return {
            accessToken: stringValue(parsed.access_token),
            tokenType: stringValue(parsed.token_type),
            idToken: stringValue(parsed.id_token)
        };
    } catch {
        const values = new URLSearchParams(body);
        return {
            accessToken: values.get("access_token")?.trim() ?? "",
            tokenType: values.get("token_type")?.trim() ?? "",
            idToken: values.get("id_token")?.trim() ?? ""
        };
    }
}

function parseObject(body: string, message: string): Record<string, unknown> {
    let parsed: unknown;
    try { parsed = JSON.parse(body); } catch { throw new OIDCOAuthError("invalid_response", 502, message); }
    if (!isObject(parsed)) throw new OIDCOAuthError("invalid_response", 502, message);
    return parsed;
}

function firstPath(value: Record<string, unknown>, paths: readonly string[]): string {
    for (const path of paths) {
        const normalized = path.trim();
        if (normalized === "") continue;
        let current: unknown = value;
        for (const part of normalized.split(".")) current = isObject(current) ? current[part] : undefined;
        const result = stringValue(current);
        if (result !== "") return result;
    }
    return "";
}

async function syntheticEmail(issuer: string, subject: string): Promise<string> {
    const hash = await sha256Hex(`${issuer.trim().toLowerCase()}\u001f${subject.trim()}`);
    return `oidc-${hash.slice(0, 32)}${SYNTHETIC_EMAIL_DOMAIN}`;
}

async function stateKey(state: string, browserSessionKey: string): Promise<string> {
    return `oauth-oidc-state:${await sha256Hex(`${state}\n${browserSessionKey}`)}`;
}

function fallbackUsername(subject: string): string {
    return `oidc_${subject.replace(/[^A-Za-z0-9_-]/gu, "_").slice(0, 40) || "user"}`;
}

function validateConfig(config: OIDCOAuthConfig): void {
    if (!config.enabled) throw new OIDCOAuthError("oauth_disabled", 404, "oauth login is disabled");
    if (config.clientId === "" || config.issuerUrl === "" || config.redirectUrl === "") {
        throw new OIDCOAuthError("oauth_config_invalid", 503, "required oidc configuration is missing");
    }
    if (!config.scopes.toLowerCase().split(/\s+/u).includes("openid")) {
        throw new OIDCOAuthError("oauth_config_invalid", 503, "oauth scopes must contain openid");
    }
    if (config.tokenAuthMethod !== "none" && config.clientSecret === "") {
        throw new OIDCOAuthError("oauth_config_invalid", 503, "oauth client secret is not configured");
    }
    for (const [value, label] of [
        [config.issuerUrl, "oauth issuer url"],
        [config.authorizeUrl, "oauth authorize url"],
        [config.tokenUrl, "oauth token url"],
        [config.redirectUrl, "oauth redirect url"]
    ] as const) assertHttpUrl(value, label);
    if (config.userInfoUrl !== "") assertHttpUrl(config.userInfoUrl, "oauth userinfo url");
    if (config.validateIdToken) assertHttpUrl(config.jwksUrl, "oauth jwks url");
    assertFrontendRedirect(config.frontendRedirectUrl);
}

function parseAlgorithms(raw: string): SupportedAlgorithm[] {
    const values = [...new Set(raw.split(",").map((value) => value.trim().toUpperCase()).filter(Boolean))];
    if (values.length === 0 || values.some((value) => !isSupportedAlgorithm(value))) {
        throw new OIDCOAuthError("oauth_config_invalid", 503, "oauth signing algorithms are invalid");
    }
    return values as SupportedAlgorithm[];
}

function providerErrorMessage(body: string, fallback: string): string {
    try {
        const parsed = parseObject(body, fallback);
        return firstNonEmpty(
            stringValue(parsed.error_description),
            stringValue(parsed.message),
            stringValue(parsed.error),
            fallback
        );
    } catch {
        const values = new URLSearchParams(body);
        return firstNonEmpty(values.get("error_description") ?? "", values.get("error") ?? "", fallback);
    }
}

function claimError(message: string): never {
    throw new OIDCOAuthError("invalid_id_token", 502, `id_token ${message}`);
}

function numericClaim(value: unknown): number | null {
    return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function booleanValue(value: unknown): boolean | null {
    return typeof value === "boolean" ? value : null;
}

function booleanSetting(setting: string | undefined, environment: string | undefined, fallback: boolean): boolean {
    const raw = firstNonEmpty(setting, environment);
    return raw === "" ? fallback : raw.toLowerCase() === "true";
}

function boundedInteger(raw: string, fallback: number, minimum: number, maximum: number): number {
    if (raw === "") return fallback;
    const value = Number(raw);
    if (!Number.isInteger(value) || value < minimum || value > maximum) {
        throw new OIDCOAuthError("oauth_config_invalid", 503, "oauth numeric configuration is invalid");
    }
    return value;
}

function opaqueToken(value: string): string {
    const token = value.trim();
    if (!/^[A-Za-z0-9_-]{43,128}$/u.test(token)) {
        throw new OIDCOAuthError("invalid_state", 400, "invalid oauth state");
    }
    return token;
}

function assertHttpUrl(value: string, label: string): void {
    let url: URL;
    try { url = new URL(value); } catch {
        throw new OIDCOAuthError("oauth_config_invalid", 503, `${label} is invalid`);
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") {
        throw new OIDCOAuthError("oauth_config_invalid", 503, `${label} is invalid`);
    }
}

function assertFrontendRedirect(value: string): void {
    if (value.startsWith("/") && !value.startsWith("//")) return;
    assertHttpUrl(value, "oauth frontend redirect url");
}

function isTokenAuthMethod(value: string): value is OIDCOAuthConfig["tokenAuthMethod"] {
    return value === "client_secret_post" || value === "client_secret_basic" || value === "none";
}

function isSupportedAlgorithm(value: string): value is SupportedAlgorithm {
    return SUPPORTED_ALGORITHMS.includes(value as SupportedAlgorithm);
}

function firstNonEmpty(...values: Array<string | undefined>): string {
    for (const value of values) {
        const normalized = value?.trim() ?? "";
        if (normalized !== "") return normalized;
    }
    return "";
}

function stringValue(value: unknown): string {
    return typeof value === "string" || typeof value === "number" ? String(value).trim() : "";
}

function isObject(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}
