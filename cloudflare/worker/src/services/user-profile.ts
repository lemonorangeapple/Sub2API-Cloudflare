import type { D1AuthUserRepository } from "../repositories/auth-users.ts";
import type {
    AuthIdentityRecord,
    AuthIdentitySummary,
    AuthIdentitySummarySet,
    AuthUserProfileResponse,
    AuthUserRecord
} from "../types/auth.ts";
import { mapAuthUser } from "./auth-user.ts";

const PROVIDERS = ["linuxdo", "oidc", "wechat", "dingtalk"] as const;
const RESERVED_EMAIL_DOMAINS = [
    "@linuxdo-connect.invalid",
    "@oidc-connect.invalid",
    "@wechat-connect.invalid",
    "@dingtalk-connect.invalid"
];

export class UserProfileService {
    readonly #users: D1AuthUserRepository;

    constructor(users: D1AuthUserRepository) {
        this.#users = users;
    }

    async getProfile(
        user: AuthUserRecord,
        settings: Record<string, string>,
        runMode: "standard" | "simple" = "standard"
    ): Promise<AuthUserProfileResponse> {
        const records = await this.#users.listIdentities(user.id);
        const identities = buildIdentitySummaries(user, records, settings);
        const bindings = { ...identities };
        const sources = inferProfileSources(user, records, identities);
        return {
            ...mapAuthUser(user),
            ...(user.avatarUrl ? { avatar_url: user.avatarUrl } : {}),
            ...sources,
            identities,
            auth_bindings: bindings,
            identity_bindings: bindings,
            email_bound: identities.email.bound,
            linuxdo_bound: identities.linuxdo.bound,
            oidc_bound: identities.oidc.bound,
            wechat_bound: identities.wechat.bound,
            dingtalk_bound: identities.dingtalk.bound,
            run_mode: runMode
        };
    }
}

export function buildIdentitySummaries(
    user: AuthUserRecord,
    records: AuthIdentityRecord[],
    settings: Record<string, string>
): AuthIdentitySummarySet {
    const email = buildEmailSummary(user, records);
    const summaries = {
        email,
        linuxdo: buildProviderSummary("linuxdo", user, records),
        oidc: buildProviderSummary("oidc", user, records),
        wechat: buildProviderSummary("wechat", user, records),
        dingtalk: buildProviderSummary("dingtalk", user, records)
    };
    applyProviderAvailability(summaries, settings);
    return summaries;
}

function buildEmailSummary(user: AuthUserRecord, records: AuthIdentityRecord[]): AuthIdentitySummary {
    const summary: AuthIdentitySummary = {
        provider: "email",
        bound: false,
        bound_count: 0,
        can_bind: false,
        can_unbind: false,
        note_key: "profile.authBindings.notes.emailManagedFromProfile",
        note: "Primary account email is managed from the profile form."
    };
    const filtered = filterRecords(records, "email");
    if (filtered.length > 0) {
        const primary = selectPrimary(filtered);
        const email = firstMetadataString(primary, "email") ||
            primary.providerSubject.trim() || user.email.trim() || primary.providerKey.trim();
        return {
            ...summary,
            bound: true,
            bound_count: filtered.length,
            display_name: email,
            subject_hint: maskEmail(email),
            provider_key: primary.providerKey.trim() || "email",
            ...(primary.verifiedAt ? { verified_at: primary.verifiedAt } : {})
        };
    }
    if (!isReservedEmail(user.email)) {
        return {
            ...summary,
            bound: true,
            bound_count: 1,
            display_name: user.email.trim(),
            subject_hint: maskEmail(user.email),
            provider_key: "email"
        };
    }
    return summary;
}

function buildProviderSummary(
    provider: typeof PROVIDERS[number],
    user: AuthUserRecord,
    records: AuthIdentityRecord[]
): AuthIdentitySummary {
    const filtered = filterRecords(records, provider);
    if (filtered.length === 0) {
        return {
            provider,
            bound: false,
            bound_count: 0,
            can_bind: true,
            can_unbind: false,
            bind_start_path: `/api/v1/auth/oauth/${provider}/bind/start?redirect=%2Fsettings%2Fprofile&intent=bind_current_user`
        };
    }
    const primary = selectPrimary(filtered);
    const canUnbind = canUnbindProvider(provider, user, records);
    return {
        provider,
        bound: true,
        bound_count: filtered.length,
        display_name: identityDisplayName(primary),
        subject_hint: maskOpaque(primary.providerSubject),
        provider_key: primary.providerKey.trim(),
        ...(primary.verifiedAt ? { verified_at: primary.verifiedAt } : {}),
        can_bind: false,
        can_unbind: canUnbind,
        note_key: canUnbind
            ? "profile.authBindings.notes.canUnbind"
            : "profile.authBindings.notes.bindAnotherBeforeUnbind",
        note: canUnbind
            ? "You can unbind this sign-in method."
            : "Bind another sign-in method before unbinding."
    };
}

function applyProviderAvailability(
    summaries: AuthIdentitySummarySet,
    settings: Record<string, string>
): void {
    const enabledKeys: Record<typeof PROVIDERS[number], string> = {
        linuxdo: "linuxdo_connect_enabled",
        oidc: "oidc_connect_enabled",
        wechat: "wechat_connect_enabled",
        dingtalk: "dingtalk_connect_enabled"
    };
    for (const provider of PROVIDERS) {
        const raw = settings[enabledKeys[provider]]?.trim();
        if (raw !== undefined && raw !== "" && raw !== "true") {
            disableBind(summaries[provider]);
        }
    }
    if (settings.wechat_connect_enabled === "true") {
        const modeValues = [
            settings.wechat_connect_open_enabled,
            settings.wechat_connect_mp_enabled,
            settings.wechat_connect_mobile_enabled
        ].filter((value) => value !== undefined && value.trim() !== "");
        if (modeValues.length > 0 && modeValues.every((value) => value !== "true")) {
            disableBind(summaries.wechat);
        }
    }
}

function disableBind(summary: AuthIdentitySummary): void {
    if (summary.bound) {
        return;
    }
    summary.can_bind = false;
    delete summary.bind_start_path;
}

function canUnbindProvider(
    provider: typeof PROVIDERS[number],
    user: AuthUserRecord,
    records: AuthIdentityRecord[]
): boolean {
    if (canUseEmail(user, records)) {
        return true;
    }
    return PROVIDERS.some((candidate) => (
        candidate !== provider && filterRecords(records, candidate).length > 0
    ));
}

function canUseEmail(user: AuthUserRecord, records: AuthIdentityRecord[]): boolean {
    if (isReservedEmail(user.email)) {
        return false;
    }
    const source = user.signupSource.trim().toLowerCase();
    if (source === "" || source === "email") {
        return true;
    }
    return filterRecords(records, "email").some((record) => {
        const identitySource = firstMetadataString(record, "source");
        return [
            "auth_service_email_bind",
            "auth_service_login_backfill",
            "auth_service_dual_write"
        ].includes(identitySource);
    });
}

function inferProfileSources(
    user: AuthUserRecord,
    records: AuthIdentityRecord[],
    identities: AuthIdentitySummarySet
): Partial<AuthUserProfileResponse> {
    const boundProviders = PROVIDERS.filter((provider) => identities[provider].bound);
    let avatarProvider = "";
    let usernameProvider = "";
    for (const provider of boundProviders) {
        const primary = selectPrimary(filterRecords(records, provider));
        const avatar = firstMetadataString(primary, "avatar_url", "suggested_avatar_url", "headimgurl");
        if (user.avatarUrl && avatar === user.avatarUrl) {
            avatarProvider = provider;
        }
        if (user.username && identityDisplayName(primary) === user.username) {
            usernameProvider = provider;
        }
    }
    const response: Partial<AuthUserProfileResponse> = {};
    const profileSources: Record<string, { provider: string; source: string }> = {};
    if (avatarProvider) {
        const source = { provider: avatarProvider, source: avatarProvider };
        response.avatar_source = source;
        profileSources.avatar = source;
    }
    if (usernameProvider) {
        const source = { provider: usernameProvider, source: usernameProvider };
        response.username_source = source;
        response.display_name_source = source;
        response.nickname_source = source;
        profileSources.username = source;
        profileSources.display_name = source;
        profileSources.nickname = source;
    }
    if (Object.keys(profileSources).length > 0) {
        response.profile_sources = profileSources;
    }
    return response;
}

function filterRecords(records: AuthIdentityRecord[], provider: string): AuthIdentityRecord[] {
    return records.filter((record) => record.providerType.trim().toLowerCase() === provider);
}

function selectPrimary(records: AuthIdentityRecord[]): AuthIdentityRecord {
    if (records.length === 0) {
        throw new RangeError("identity list is empty");
    }
    return [...records].sort((left, right) => {
        const leftTime = Date.parse(left.verifiedAt ?? left.updatedAt ?? left.createdAt) || 0;
        const rightTime = Date.parse(right.verifiedAt ?? right.updatedAt ?? right.createdAt) || 0;
        return rightTime - leftTime || left.providerKey.localeCompare(right.providerKey);
    })[0];
}

function identityDisplayName(record: AuthIdentityRecord): string {
    return firstMetadataString(
        record,
        "display_name",
        "suggested_display_name",
        "username",
        "name",
        "nickname",
        "email"
    ) || record.providerSubject.trim() || record.providerType.trim();
}

function firstMetadataString(record: AuthIdentityRecord, ...keys: string[]): string {
    for (const key of keys) {
        const value = record.metadata[key];
        if (typeof value === "string" && value.trim()) {
            return value.trim();
        }
    }
    return "";
}

function isReservedEmail(value: string): boolean {
    const email = value.trim().toLowerCase();
    return email.length === 0 || RESERVED_EMAIL_DOMAINS.some((domain) => email.endsWith(domain));
}

function maskEmail(value: string): string {
    const email = value.trim();
    const atIndex = email.indexOf("@");
    if (atIndex < 1) {
        return email.length > 0 ? `${email.slice(0, 1)}***` : "***";
    }
    const local = email.slice(0, atIndex);
    const domain = email.slice(atIndex);
    return local.length <= 2
        ? `${local.slice(0, 1)}***${domain}`
        : `${local.slice(0, 1)}***${local.slice(-1)}${domain}`;
}

function maskOpaque(value: string): string {
    const normalized = value.trim();
    if (normalized.length <= 4) {
        return normalized.length === 0 ? "" : `${normalized.slice(0, 1)}***`;
    }
    return `${normalized.slice(0, 2)}***${normalized.slice(-2)}`;
}
