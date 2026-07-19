import type { SettingsReader, SettingsWriter } from "../repositories/settings.ts";

export class AdminSettingsError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "AdminSettingsError";
        this.code = code;
        this.status = status;
    }
}

export interface AdminSettingsUpdateInput {
    [key: string]: unknown;
}

const BOOLEAN_KEYS = new Set([
    "registration_enabled",
    "email_verify_enabled",
    "promo_code_enabled",
    "password_reset_enabled",
    "invitation_code_enabled",
    "totp_enabled",
    "login_agreement_enabled",
    "hide_ccs_import_button",
    "backend_mode_enabled",
    "allow_ungrouped_key_scheduling",
    "enable_model_fallback",
    "enable_identity_patch",
    "allow_user_view_error_requests",
    "linuxdo_connect_enabled",
    "dingtalk_connect_enabled",
    "dingtalk_connect_bypass_registration",
    "dingtalk_connect_sync_corp_email",
    "dingtalk_connect_sync_display_name",
    "dingtalk_connect_sync_dept",
    "wechat_connect_enabled",
    "wechat_connect_open_enabled",
    "wechat_connect_mp_enabled",
    "wechat_connect_mobile_enabled",
    "oidc_connect_enabled",
    "oidc_connect_use_pkce",
    "oidc_connect_validate_id_token",
    "oidc_connect_require_email_verified",
    "github_oauth_enabled",
    "google_oauth_enabled",
    "turnstile_enabled",
    "api_key_acl_trust_forwarded_ip",
    "enable_fingerprint_unification",
    "enable_metadata_passthrough",
    "enable_cch_signing",
    "enable_claude_oauth_system_prompt_injection",
    "enable_anthropic_cache_ttl_1h_injection",
    "rewrite_message_cache_control",
    "enable_client_dateline_normalization",
    "ops_monitoring_enabled",
    "ops_realtime_monitoring_enabled",
    "allow_ungrouped_key_scheduling",
    "payment_enabled",
    "payment_balance_disabled",
    "payment_cancel_rate_limit_enabled",
    "payment_alipay_force_qrcode",
    "channel_monitor_enabled",
    "available_channels_enabled",
    "affiliate_enabled",
    "risk_control_enabled",
    "cyber_session_block_enabled",
    "force_email_on_third_party_signup",
    "smtp_use_tls",
    "subscription_expiry_notify_enabled",
    "account_quota_notify_enabled",
    "balance_low_notify_enabled"
]);

const INTEGER_KEYS = new Set([
    "smtp_port",
    "default_concurrency",
    "default_user_rpm_limit",
    "table_default_page_size",
    "login_agreement_updated_at",
    "affiliate_rebate_freeze_hours",
    "affiliate_rebate_duration_days",
    "payment_order_timeout_minutes",
    "payment_max_pending_orders",
    "payment_cancel_rate_limit_max",
    "payment_cancel_rate_limit_window",
    "channel_monitor_default_interval_seconds",
    "min_codex_version",
    "max_codex_version",
    "min_claude_code_version",
    "max_claude_code_version",
    "oidc_connect_clock_skew_seconds",
    "cyber_session_block_ttl_seconds",
    "ops_metrics_interval_seconds"
]);

const FLOAT_KEYS = new Set([
    "default_balance",
    "affiliate_rebate_rate",
    "affiliate_rebate_per_invitee_cap",
    "payment_min_amount",
    "payment_max_amount",
    "payment_daily_limit",
    "payment_balance_recharge_multiplier",
    "payment_subscription_usd_to_cny_rate",
    "payment_recharge_fee_rate",
    "balance_low_notify_threshold",
    "auth_source_default_email_balance",
    "auth_source_default_linuxdo_balance",
    "auth_source_default_oidc_balance",
    "auth_source_default_wechat_balance",
    "auth_source_default_github_balance",
    "auth_source_default_google_balance",
    "auth_source_default_dingtalk_balance"
]);

const INTEGER_PER_SOURCE_KEYS = new Set([
    "auth_source_default_email_concurrency",
    "auth_source_default_linuxdo_concurrency",
    "auth_source_default_oidc_concurrency",
    "auth_source_default_wechat_concurrency",
    "auth_source_default_github_concurrency",
    "auth_source_default_google_concurrency",
    "auth_source_default_dingtalk_concurrency"
]);

const JSON_ARRAY_KEYS = new Set([
    "registration_email_suffix_whitelist",
    "table_page_size_options",
    "payment_enabled_types",
    "codex_cli_only_blacklist",
    "codex_cli_only_whitelist",
    "codex_cli_only_engine_fingerprint_signals",
    "default_subscriptions",
    "auth_source_default_email_subscriptions",
    "auth_source_default_linuxdo_subscriptions",
    "auth_source_default_oidc_subscriptions",
    "auth_source_default_wechat_subscriptions",
    "auth_source_default_github_subscriptions",
    "auth_source_default_google_subscriptions",
    "auth_source_default_dingtalk_subscriptions",
    "login_agreement_documents",
    "custom_menu_items",
    "custom_endpoints",
    "account_quota_notify_emails"
]);

const JSON_OBJECT_KEYS = new Set([
    "default_platform_quotas",
    "auth_source_default_email_platform_quotas",
    "auth_source_default_linuxdo_platform_quotas",
    "auth_source_default_oidc_platform_quotas",
    "auth_source_default_wechat_platform_quotas",
    "auth_source_default_github_platform_quotas",
    "auth_source_default_google_platform_quotas",
    "auth_source_default_dingtalk_platform_quotas",
    "openai_fast_policy_settings"
]);

const STRINGIFY_KEYS = new Set([
    "default_subscriptions",
    "auth_source_default_email_subscriptions",
    "auth_source_default_linuxdo_subscriptions",
    "auth_source_default_oidc_subscriptions",
    "auth_source_default_wechat_subscriptions",
    "auth_source_default_github_subscriptions",
    "auth_source_default_google_subscriptions",
    "auth_source_default_dingtalk_subscriptions",
    "registration_email_suffix_whitelist",
    "table_page_size_options",
    "payment_enabled_types",
    "codex_cli_only_blacklist",
    "codex_cli_only_whitelist",
    "codex_cli_only_engine_fingerprint_signals",
    "login_agreement_documents",
    "custom_menu_items",
    "custom_endpoints",
    "account_quota_notify_emails",
    "default_platform_quotas",
    "auth_source_default_email_platform_quotas",
    "auth_source_default_linuxdo_platform_quotas",
    "auth_source_default_oidc_platform_quotas",
    "auth_source_default_wechat_platform_quotas",
    "auth_source_default_github_platform_quotas",
    "auth_source_default_google_platform_quotas",
    "auth_source_default_dingtalk_platform_quotas",
    "openai_fast_policy_settings"
]);

function trimIfString(value: unknown): unknown {
    return typeof value === "string" ? value.trim() : value;
}

function normalizeDingTalkCorpPolicy(value: string): string {
    const trimmed = value.trim().toLowerCase();
    if (trimmed === "whitelist" || trimmed === "") {
        return "none";
    }
    if (["none", "whitelist", "internal"].includes(trimmed)) {
        return trimmed;
    }
    return "none";
}

function normalizeLoginAgreementMode(value: unknown): string {
    const trimmed = typeof value === "string" ? value.trim().toLowerCase() : "";
    if (trimmed === "checkbox") {
        return "checkbox";
    }
    return "modal";
}

function normalizeSubscriptions(raw: unknown): string {
    if (!Array.isArray(raw)) {
        return "[]";
    }
    const normalized = raw
        .filter((item): item is Record<string, unknown> =>
            item !== null && typeof item === "object" && !Array.isArray(item))
        .map((item) => {
            const record = item as Record<string, unknown>;
            return {
                group_id: typeof record.group_id === "string" ? record.group_id.trim() : "",
                quota: typeof record.quota === "number" ? record.quota : 0
            };
        })
        .filter((item) => item.group_id !== "");
    return JSON.stringify(normalized);
}

function normalizePlatformQuotas(raw: unknown): string {
    if (raw === null || raw === undefined || typeof raw !== "object" || Array.isArray(raw)) {
        return "{}";
    }
    return JSON.stringify(raw);
}

export class D1AdminSettingsService {
    readonly #settings: SettingsReader & SettingsWriter;

    constructor(settings: SettingsReader & SettingsWriter) {
        this.#settings = settings;
    }

    async updateSettings(input: AdminSettingsUpdateInput): Promise<{ updated: number }> {
        const updates: Record<string, string> = {};

        for (const [rawKey, rawValue] of Object.entries(input)) {
            if (rawKey === "updated_at" || rawKey === "created_at") {
                continue;
            }

            const value = trimIfString(rawValue);

            if (BOOLEAN_KEYS.has(rawKey)) {
                updates[rawKey] = value === true || value === "true" ? "true" : "false";
                continue;
            }

            if (INTEGER_KEYS.has(rawKey)) {
                if (value === null || value === undefined || value === "") {
                    continue;
                }
                const parsed = Number.parseInt(String(value), 10);
                if (Number.isInteger(parsed)) {
                    updates[rawKey] = String(parsed);
                }
                continue;
            }

            if (FLOAT_KEYS.has(rawKey) || INTEGER_PER_SOURCE_KEYS.has(rawKey)) {
                if (value === null || value === undefined || value === "") {
                    continue;
                }
                const parsed = Number.parseFloat(String(value));
                if (Number.isFinite(parsed)) {
                    updates[rawKey] = String(parsed);
                }
                continue;
            }

            if (STRINGIFY_KEYS.has(rawKey)) {
                if (value === null || value === undefined) {
                    continue;
                }
                if (JSON_ARRAY_KEYS.has(rawKey)) {
                    updates[rawKey] = normalizeSubscriptions(value);
                    continue;
                }
                if (JSON_OBJECT_KEYS.has(rawKey)) {
                    updates[rawKey] = normalizePlatformQuotas(value);
                    continue;
                }
                if (typeof value === "string") {
                    updates[rawKey] = value;
                } else {
                    updates[rawKey] = JSON.stringify(value);
                }
                continue;
            }

            if (typeof value === "string") {
                updates[rawKey] = value;
            } else if (typeof value === "number" || typeof value === "boolean") {
                updates[rawKey] = String(value);
            } else if (value !== null && value !== undefined) {
                updates[rawKey] = JSON.stringify(value);
            }
        }

        if (Object.keys(updates).length === 0) {
            return { updated: 0 };
        }

        if (updates.login_agreement_mode !== undefined) {
            updates.login_agreement_mode = normalizeLoginAgreementMode(updates.login_agreement_mode);
        }

        if (updates.dingtalk_connect_corp_restriction_policy !== undefined) {
            updates.dingtalk_connect_corp_restriction_policy =
                normalizeDingTalkCorpPolicy(updates.dingtalk_connect_corp_restriction_policy);
        }

        const now = new Date().toISOString();
        await this.#settings.upsertMany(updates, now);
        return { updated: Object.keys(updates).length };
    }

    async getSettings(): Promise<Record<string, unknown>> {
        const raw = await this.#settings.getAll();
        const result: Record<string, unknown> = {};

        for (const [key, value] of Object.entries(raw)) {
            if (BOOLEAN_KEYS.has(key)) {
                result[key] = value === "true";
            } else if (INTEGER_KEYS.has(key)) {
                const parsed = Number.parseInt(value, 10);
                result[key] = Number.isInteger(parsed) ? parsed : 0;
            } else if (FLOAT_KEYS.has(key) || INTEGER_PER_SOURCE_KEYS.has(key)) {
                const parsed = Number.parseFloat(value);
                result[key] = Number.isFinite(parsed) ? parsed : 0;
            } else if (JSON_ARRAY_KEYS.has(key)) {
                try {
                    result[key] = JSON.parse(value || "[]");
                } catch {
                    result[key] = [];
                }
            } else if (JSON_OBJECT_KEYS.has(key)) {
                try {
                    result[key] = JSON.parse(value || "{}");
                } catch {
                    result[key] = {};
                }
            } else {
                result[key] = value;
            }
        }

        return result;
    }

    async validateAuthSettings(input: AdminSettingsUpdateInput): Promise<void> {
        if (input.totp_enabled === true || input.totp_enabled === "true") {
            if (!input.totp_encryption_key_configured) {
                throw new AdminSettingsError(
                    "totp_key_required",
                    400,
                    "Cannot enable TOTP: TOTP_ENCRYPTION_KEY environment variable must be configured first."
                );
            }
        }

        if (input.turnstile_enabled === true || input.turnstile_enabled === "true") {
            if (!input.turnstile_site_key || String(input.turnstile_site_key).trim() === "") {
                throw new AdminSettingsError(
                    "turnstile_site_key_required",
                    400,
                    "Turnstile Site Key is required when enabled"
                );
            }
        }

        if (input.linuxdo_connect_enabled === true || input.linuxdo_connect_enabled === "true") {
            if (!input.linuxdo_connect_client_id || String(input.linuxdo_connect_client_id).trim() === "") {
                throw new AdminSettingsError(
                    "linuxdo_client_id_required",
                    400,
                    "LinuxDo Client ID is required when enabled"
                );
            }
            if (!input.linuxdo_connect_redirect_url || String(input.linuxdo_connect_redirect_url).trim() === "") {
                throw new AdminSettingsError(
                    "linuxdo_redirect_url_required",
                    400,
                    "LinuxDo Redirect URL is required when enabled"
                );
            }
        }

        if (input.dingtalk_connect_enabled === true || input.dingtalk_connect_enabled === "true") {
            if (!input.dingtalk_connect_client_id || String(input.dingtalk_connect_client_id).trim() === "") {
                throw new AdminSettingsError(
                    "dingtalk_client_id_required",
                    400,
                    "DingTalk Client ID is required when enabled"
                );
            }
            if (!input.dingtalk_connect_redirect_url || String(input.dingtalk_connect_redirect_url).trim() === "") {
                throw new AdminSettingsError(
                    "dingtalk_redirect_url_required",
                    400,
                    "DingTalk Redirect URL is required when enabled"
                );
            }
        }

        if (input.login_agreement_enabled === true || input.login_agreement_enabled === "true") {
            const docs = input.login_agreement_documents;
            if (!Array.isArray(docs) || docs.length === 0) {
                throw new AdminSettingsError(
                    "login_agreement_documents_required",
                    400,
                    "Login agreement documents are required when enabled"
                );
            }
            for (const doc of docs) {
                if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
                    throw new AdminSettingsError(
                        "login_agreement_invalid_document",
                        400,
                        "Login agreement document must be an object"
                    );
                }
                const record = doc as Record<string, unknown>;
                const title = typeof record.title === "string" ? record.title.trim() : "";
                if (title === "") {
                    throw new AdminSettingsError(
                        "login_agreement_title_required",
                        400,
                        "Login agreement document title is required"
                    );
                }
                if (title.length > 80) {
                    throw new AdminSettingsError(
                        "login_agreement_title_too_long",
                        400,
                        "Login agreement document title is too long (max 80 characters)"
                    );
                }
                const contentMd = typeof record.content_md === "string" ? record.content_md : "";
                if (contentMd.length > 200 * 1024) {
                    throw new AdminSettingsError(
                        "login_agreement_content_too_large",
                        400,
                        "Login agreement document content is too large (max 200KB)"
                    );
                }
            }
        }

        if (input.default_concurrency !== undefined) {
            const val = Number(input.default_concurrency);
            if (Number.isFinite(val) && val < 1) {
                input.default_concurrency = 1;
            }
        }

        if (input.default_balance !== undefined) {
            const val = Number(input.default_balance);
            if (Number.isFinite(val) && val < 0) {
                input.default_balance = 0;
            }
        }
    }
}
