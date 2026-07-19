import type { SettingsReader } from "../repositories/settings.ts";

const PUBLIC_SETTING_KEYS = [
    "registration_enabled",
    "email_verify_enabled",
    "force_email_on_third_party_signup",
    "registration_email_suffix_whitelist",
    "promo_code_enabled",
    "password_reset_enabled",
    "invitation_code_enabled",
    "totp_enabled",
    "login_agreement_enabled",
    "login_agreement_mode",
    "login_agreement_updated_at",
    "login_agreement_documents",
    "turnstile_enabled",
    "turnstile_site_key",
    "site_name",
    "site_logo",
    "site_subtitle",
    "api_base_url",
    "contact_info",
    "doc_url",
    "home_content",
    "hide_ccs_import_button",
    "purchase_subscription_enabled",
    "purchase_subscription_url",
    "table_default_page_size",
    "table_page_size_options",
    "custom_menu_items",
    "custom_endpoints",
    "linuxdo_connect_enabled",
    "dingtalk_connect_enabled",
    "wechat_connect_enabled",
    "wechat_connect_app_id",
    "wechat_connect_app_secret",
    "wechat_connect_open_app_id",
    "wechat_connect_open_app_secret",
    "wechat_connect_mp_app_id",
    "wechat_connect_mp_app_secret",
    "wechat_connect_mobile_app_id",
    "wechat_connect_mobile_app_secret",
    "wechat_connect_open_enabled",
    "wechat_connect_mp_enabled",
    "wechat_connect_mobile_enabled",
    "wechat_connect_mode",
    "backend_mode_enabled",
    "payment_enabled",
    "oidc_connect_enabled",
    "oidc_connect_provider_name",
    "github_oauth_enabled",
    "github_oauth_client_id",
    "github_oauth_client_secret",
    "google_oauth_enabled",
    "google_oauth_client_id",
    "google_oauth_client_secret",
    "balance_low_notify_enabled",
    "balance_low_notify_threshold",
    "balance_low_notify_recharge_url",
    "account_quota_notify_enabled",
    "channel_monitor_enabled",
    "channel_monitor_default_interval_seconds",
    "available_channels_enabled",
    "affiliate_enabled",
    "risk_control_enabled",
    "allow_user_view_error_requests"
] as const;

const DEFAULT_LOGIN_AGREEMENT_DATE = "2026-03-31";
const DEFAULT_LOGIN_AGREEMENT_MODE = "modal";
const EMAIL_DOMAIN_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/u;

export interface LoginAgreementDocument {
    id: string;
    title: string;
    content_md: string;
}

export interface CustomMenuItem {
    id: string;
    label: string;
    icon_svg: string;
    url: string;
    page_slug?: string;
    visibility: string;
    sort_order: number;
}

export interface CustomEndpoint {
    name: string;
    endpoint: string;
    description: string;
}

export interface PublicSettingsPayload {
    registration_enabled: boolean;
    email_verify_enabled: boolean;
    force_email_on_third_party_signup: boolean;
    registration_email_suffix_whitelist: string[];
    promo_code_enabled: boolean;
    password_reset_enabled: boolean;
    invitation_code_enabled: boolean;
    totp_enabled: boolean;
    login_agreement_enabled: boolean;
    login_agreement_mode: string;
    login_agreement_updated_at: string;
    login_agreement_revision: string;
    login_agreement_documents: LoginAgreementDocument[];
    turnstile_enabled: boolean;
    turnstile_site_key: string;
    site_name: string;
    site_logo: string;
    site_subtitle: string;
    api_base_url: string;
    contact_info: string;
    doc_url: string;
    home_content: string;
    hide_ccs_import_button: boolean;
    purchase_subscription_enabled: boolean;
    purchase_subscription_url: string;
    table_default_page_size: number;
    table_page_size_options: number[];
    custom_menu_items: CustomMenuItem[];
    custom_endpoints: CustomEndpoint[];
    dingtalk_oauth_enabled: boolean;
    linuxdo_oauth_enabled: boolean;
    wechat_oauth_enabled: boolean;
    wechat_oauth_open_enabled: boolean;
    wechat_oauth_mp_enabled: boolean;
    wechat_oauth_mobile_enabled: boolean;
    oidc_oauth_enabled: boolean;
    oidc_oauth_provider_name: string;
    github_oauth_enabled: boolean;
    google_oauth_enabled: boolean;
    sora_client_enabled: boolean;
    backend_mode_enabled: boolean;
    payment_enabled: boolean;
    version: string;
    server_timezone: string;
    server_utc_offset: string;
    balance_low_notify_enabled: boolean;
    account_quota_notify_enabled: boolean;
    balance_low_notify_threshold: number;
    balance_low_notify_recharge_url: string;
    channel_monitor_enabled: boolean;
    channel_monitor_default_interval_seconds: number;
    available_channels_enabled: boolean;
    affiliate_enabled: boolean;
    risk_control_enabled: boolean;
    allow_user_view_error_requests: boolean;
}

export interface PublicSettingsRuntime {
    version?: string;
    serverTimezone?: string;
    serverUTCOffset?: string;
}

function stringValue(values: Record<string, string>, key: string): string {
    return values[key] ?? "";
}

function enabled(values: Record<string, string>, key: string): boolean {
    return stringValue(values, key) === "true";
}

function nonEmpty(value: string, fallback: string): string {
    const trimmed = value.trim();
    return trimmed === "" ? fallback : trimmed;
}

function valueOrDefault(value: string, fallback: string): string {
    return value === "" ? fallback : value;
}

function isFalseSettingValue(value: string): boolean {
    return ["false", "0", "off", "disabled"].includes(value.trim().toLowerCase());
}

function parseFiniteNonNegative(value: string): number {
    const parsed = Number.parseFloat(value);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
}

function normalizePagePreferences(defaultRaw: string, optionsRaw: string): [number, number[]] {
    const parsedDefault = Number.parseInt(defaultRaw.trim(), 10);
    const defaultPageSize = Number.isInteger(parsedDefault) && parsedDefault >= 5 && parsedDefault <= 1000
        ? parsedDefault
        : 20;
    let rawOptions: unknown = [];
    try {
        rawOptions = JSON.parse(optionsRaw || "[]");
    } catch {
        rawOptions = [];
    }
    const options = Array.isArray(rawOptions)
        ? [...new Set(rawOptions.filter((item): item is number => Number.isInteger(item) && item >= 5 && item <= 1000))]
            .sort((left, right) => left - right)
        : [];
    return [defaultPageSize, options.length > 0 ? options : [10, 20, 50]];
}

function normalizeEmailWhitelist(raw: string): string[] {
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw || "[]");
    } catch {
        return [];
    }
    if (!Array.isArray(parsed)) {
        return [];
    }
    const result: string[] = [];
    const seen = new Set<string>();
    for (const item of parsed) {
        if (typeof item !== "string") {
            continue;
        }
        const value = item.trim().toLowerCase();
        let normalized: string | null = null;
        if (value.startsWith("*.")) {
            const domain = value.slice(2);
            normalized = EMAIL_DOMAIN_PATTERN.test(domain) ? `*.${domain}` : null;
        } else {
            const domain = value.startsWith("@") ? value.slice(1) : value;
            normalized = EMAIL_DOMAIN_PATTERN.test(domain) ? `@${domain}` : null;
        }
        if (normalized !== null && !seen.has(normalized)) {
            seen.add(normalized);
            result.push(normalized);
        }
    }
    return result;
}

function defaultLoginAgreementDocuments(): LoginAgreementDocument[] {
    return [
        { id: "terms", title: "服务条款", content_md: "" },
        { id: "usage-policy", title: "使用政策", content_md: "" },
        { id: "supported-regions", title: "支持的国家和地区", content_md: "" },
        { id: "service-specific-terms", title: "服务特定条款", content_md: "" }
    ];
}

async function sha256Hex(value: string): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
    return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function goCompatibleJSON(value: unknown): string {
    return JSON.stringify(value)
        .replace(/&/gu, "\\u0026")
        .replace(/</gu, "\\u003c")
        .replace(/>/gu, "\\u003e")
        .replace(/\u2028/gu, "\\u2028")
        .replace(/\u2029/gu, "\\u2029");
}

function normalizeDocumentId(value: string): string {
    let result = "";
    let lastSeparator = false;
    for (const character of value.trim().toLowerCase()) {
        if (/^[a-z0-9]$/u.test(character)) {
            result += character;
            lastSeparator = false;
            continue;
        }
        if (["-", "_", " ", ".", "/"].includes(character) && !lastSeparator && result.length > 0) {
            result += character === "_" ? "_" : "-";
            lastSeparator = true;
        }
    }
    return result.replace(/^[-_]+|[-_]+$/gu, "");
}

async function parseLoginAgreementDocuments(raw: string): Promise<LoginAgreementDocument[]> {
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw || "[]");
    } catch {
        return defaultLoginAgreementDocuments();
    }
    if (!Array.isArray(parsed)) {
        return defaultLoginAgreementDocuments();
    }
    const result: LoginAgreementDocument[] = [];
    const seen = new Set<string>();
    for (const [index, item] of parsed.entries()) {
        if (item === null || typeof item !== "object" || Array.isArray(item)) {
            continue;
        }
        const record = item as Record<string, unknown>;
        const title = typeof record.title === "string" ? record.title.trim() : "";
        const content = typeof record.content_md === "string" ? record.content_md.trim() : "";
        if (title === "" && content === "") {
            continue;
        }
        let id = normalizeDocumentId(typeof record.id === "string" ? record.id : "");
        if (id === "") {
            id = (await sha256Hex(`${index}:${title}:${content}`)).slice(0, 12);
        }
        const baseId = id;
        for (let suffix = 2; seen.has(id); suffix += 1) {
            id = `${baseId}-${suffix}`;
        }
        seen.add(id);
        result.push({ id, title, content_md: content });
    }
    return result.length > 0 ? result : defaultLoginAgreementDocuments();
}

function parseCustomMenuItems(raw: string): CustomMenuItem[] {
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw || "[]");
    } catch {
        return [];
    }
    if (!Array.isArray(parsed)) {
        return [];
    }
    return parsed.flatMap((item) => {
        if (item === null || typeof item !== "object" || Array.isArray(item)) {
            return [];
        }
        const value = item as Record<string, unknown>;
        const visibility = typeof value.visibility === "string" ? value.visibility : "";
        if (visibility === "admin") {
            return [];
        }
        return [{
            id: typeof value.id === "string" ? value.id : "",
            label: typeof value.label === "string" ? value.label : "",
            icon_svg: typeof value.icon_svg === "string" ? value.icon_svg : "",
            url: typeof value.url === "string" ? value.url : "",
            ...(typeof value.page_slug === "string" && value.page_slug !== "" ? { page_slug: value.page_slug } : {}),
            visibility,
            sort_order: Number.isInteger(value.sort_order) ? value.sort_order as number : 0
        }];
    });
}

function parseCustomEndpoints(raw: string): CustomEndpoint[] {
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw || "[]");
    } catch {
        return [];
    }
    if (!Array.isArray(parsed)) {
        return [];
    }
    return parsed.flatMap((item) => {
        if (item === null || typeof item !== "object" || Array.isArray(item)) {
            return [];
        }
        const value = item as Record<string, unknown>;
        return [{
            name: typeof value.name === "string" ? value.name : "",
            endpoint: typeof value.endpoint === "string" ? value.endpoint : "",
            description: typeof value.description === "string" ? value.description : ""
        }];
    });
}

function parseChannelMonitorInterval(raw: string): number {
    const parsed = Number.parseInt(raw.trim(), 10);
    if (!Number.isInteger(parsed)) {
        return 60;
    }
    if (parsed <= 0) {
        return 0;
    }
    return Math.min(3600, Math.max(15, parsed));
}

function credentialReady(values: Record<string, string>, prefix: "github" | "google"): boolean {
    return enabled(values, `${prefix}_oauth_enabled`)
        && stringValue(values, `${prefix}_oauth_client_id`).trim() !== ""
        && stringValue(values, `${prefix}_oauth_client_secret`).trim() !== "";
}

function weChatCapabilities(values: Record<string, string>): [boolean, boolean, boolean, boolean] {
    if (!enabled(values, "wechat_connect_enabled")) {
        return [false, false, false, false];
    }
    const legacyId = stringValue(values, "wechat_connect_app_id").trim();
    const legacySecret = stringValue(values, "wechat_connect_app_secret").trim();
    const mode = nonEmpty(stringValue(values, "wechat_connect_mode"), "open").toLowerCase();
    const explicitModes = ["wechat_connect_open_enabled", "wechat_connect_mp_enabled", "wechat_connect_mobile_enabled"]
        .some((key) => Object.hasOwn(values, key));
    const openEnabled = explicitModes ? enabled(values, "wechat_connect_open_enabled") : mode === "open";
    const mpEnabled = explicitModes ? enabled(values, "wechat_connect_mp_enabled") : mode === "mp";
    const mobileEnabled = explicitModes ? enabled(values, "wechat_connect_mobile_enabled") : mode === "mobile";
    const openReady = openEnabled
        && nonEmpty(stringValue(values, "wechat_connect_open_app_id"), legacyId) !== ""
        && nonEmpty(stringValue(values, "wechat_connect_open_app_secret"), legacySecret) !== "";
    const mpReady = mpEnabled
        && nonEmpty(stringValue(values, "wechat_connect_mp_app_id"), legacyId) !== ""
        && nonEmpty(stringValue(values, "wechat_connect_mp_app_secret"), legacySecret) !== "";
    const mobileReady = mobileEnabled
        && nonEmpty(stringValue(values, "wechat_connect_mobile_app_id"), legacyId) !== ""
        && nonEmpty(stringValue(values, "wechat_connect_mobile_app_secret"), legacySecret) !== "";
    return [openReady || mpReady, openReady, mpReady, mobileReady];
}

function runtimeString(value: string | undefined, fallback: string): string {
    return value?.trim() || fallback;
}

export class PublicSettingsService {
    readonly #settings: SettingsReader;
    readonly #runtime: PublicSettingsRuntime;

    constructor(settings: SettingsReader, runtime: PublicSettingsRuntime = {}) {
        this.#settings = settings;
        this.#runtime = runtime;
    }

    async getPublicSettings(): Promise<PublicSettingsPayload> {
        const values = await this.#settings.getMany(PUBLIC_SETTING_KEYS);
        const emailVerifyEnabled = enabled(values, "email_verify_enabled");
        const documents = await parseLoginAgreementDocuments(stringValue(values, "login_agreement_documents"));
        const updatedAt = nonEmpty(stringValue(values, "login_agreement_updated_at"), DEFAULT_LOGIN_AGREEMENT_DATE);
        const revision = (await sha256Hex(goCompatibleJSON({ updated_at: updatedAt, documents }))).slice(0, 16);
        const [tableDefaultPageSize, tablePageSizeOptions] = normalizePagePreferences(
            stringValue(values, "table_default_page_size"),
            stringValue(values, "table_page_size_options")
        );
        const [weChatEnabled, weChatOpenEnabled, weChatMPEnabled, weChatMobileEnabled] = weChatCapabilities(values);

        return {
            registration_enabled: enabled(values, "registration_enabled"),
            email_verify_enabled: emailVerifyEnabled,
            force_email_on_third_party_signup: enabled(values, "force_email_on_third_party_signup"),
            registration_email_suffix_whitelist: normalizeEmailWhitelist(stringValue(values, "registration_email_suffix_whitelist")),
            promo_code_enabled: stringValue(values, "promo_code_enabled") !== "false",
            password_reset_enabled: emailVerifyEnabled && enabled(values, "password_reset_enabled"),
            invitation_code_enabled: enabled(values, "invitation_code_enabled"),
            totp_enabled: enabled(values, "totp_enabled"),
            login_agreement_enabled: enabled(values, "login_agreement_enabled") && documents.length > 0,
            login_agreement_mode: stringValue(values, "login_agreement_mode").trim().toLowerCase() === "checkbox"
                ? "checkbox"
                : DEFAULT_LOGIN_AGREEMENT_MODE,
            login_agreement_updated_at: updatedAt,
            login_agreement_revision: revision,
            login_agreement_documents: documents,
            turnstile_enabled: enabled(values, "turnstile_enabled"),
            turnstile_site_key: stringValue(values, "turnstile_site_key"),
            site_name: valueOrDefault(stringValue(values, "site_name"), "Sub2API"),
            site_logo: stringValue(values, "site_logo"),
            site_subtitle: valueOrDefault(stringValue(values, "site_subtitle"), "Subscription to API Conversion Platform"),
            api_base_url: stringValue(values, "api_base_url"),
            contact_info: stringValue(values, "contact_info"),
            doc_url: stringValue(values, "doc_url"),
            home_content: stringValue(values, "home_content"),
            hide_ccs_import_button: enabled(values, "hide_ccs_import_button"),
            purchase_subscription_enabled: enabled(values, "purchase_subscription_enabled"),
            purchase_subscription_url: stringValue(values, "purchase_subscription_url").trim(),
            table_default_page_size: tableDefaultPageSize,
            table_page_size_options: tablePageSizeOptions,
            custom_menu_items: parseCustomMenuItems(stringValue(values, "custom_menu_items")),
            custom_endpoints: parseCustomEndpoints(stringValue(values, "custom_endpoints")),
            dingtalk_oauth_enabled: enabled(values, "dingtalk_connect_enabled"),
            linuxdo_oauth_enabled: enabled(values, "linuxdo_connect_enabled"),
            wechat_oauth_enabled: weChatEnabled,
            wechat_oauth_open_enabled: weChatOpenEnabled,
            wechat_oauth_mp_enabled: weChatMPEnabled,
            wechat_oauth_mobile_enabled: weChatMobileEnabled,
            oidc_oauth_enabled: enabled(values, "oidc_connect_enabled"),
            oidc_oauth_provider_name: nonEmpty(stringValue(values, "oidc_connect_provider_name"), "OIDC"),
            github_oauth_enabled: credentialReady(values, "github"),
            google_oauth_enabled: credentialReady(values, "google"),
            sora_client_enabled: false,
            backend_mode_enabled: enabled(values, "backend_mode_enabled"),
            payment_enabled: enabled(values, "payment_enabled"),
            version: runtimeString(this.#runtime.version, "dev"),
            server_timezone: runtimeString(this.#runtime.serverTimezone, "UTC"),
            server_utc_offset: runtimeString(this.#runtime.serverUTCOffset, "+00:00"),
            balance_low_notify_enabled: enabled(values, "balance_low_notify_enabled"),
            account_quota_notify_enabled: enabled(values, "account_quota_notify_enabled"),
            balance_low_notify_threshold: parseFiniteNonNegative(stringValue(values, "balance_low_notify_threshold")),
            balance_low_notify_recharge_url: stringValue(values, "balance_low_notify_recharge_url"),
            channel_monitor_enabled: !isFalseSettingValue(stringValue(values, "channel_monitor_enabled")),
            channel_monitor_default_interval_seconds: parseChannelMonitorInterval(
                stringValue(values, "channel_monitor_default_interval_seconds")
            ),
            available_channels_enabled: enabled(values, "available_channels_enabled"),
            affiliate_enabled: enabled(values, "affiliate_enabled"),
            risk_control_enabled: enabled(values, "risk_control_enabled"),
            allow_user_view_error_requests: enabled(values, "allow_user_view_error_requests")
        };
    }
}
