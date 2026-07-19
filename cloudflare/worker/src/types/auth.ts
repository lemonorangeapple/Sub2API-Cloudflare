export interface AuthUserRecord {
    id: number;
    email: string;
    passwordHash: string;
    role: string;
    status: string;
    username: string;
    notes: string;
    balance: number;
    frozenBalance: number;
    concurrency: number;
    createdAt: string;
    updatedAt: string;
    deletedAt: string | null;
    lastLoginAt: string | null;
    lastActiveAt: string | null;
    balanceNotifyEnabled: boolean;
    balanceNotifyThresholdType: string;
    balanceNotifyThreshold: number | null;
    balanceNotifyExtraEmails: unknown[];
    totalRecharged: number;
    rpmLimit: number;
    totpEnabled: boolean;
    totpEnabledAt: string | null;
    totpSecretEncrypted: string | null;
    tokenVersion: bigint;
    signupSource: string;
    allowedGroups: number[] | null;
    groupRates: Record<string, number>;
    avatarUrl: string;
}

export interface AuthIdentityRecord {
    providerType: string;
    providerKey: string;
    providerSubject: string;
    verifiedAt: string | null;
    issuer: string | null;
    metadata: Record<string, unknown>;
    createdAt: string;
    updatedAt: string;
}

export interface AuthIdentitySummary {
    provider: string;
    bound: boolean;
    bound_count: number;
    display_name?: string;
    subject_hint?: string;
    provider_key?: string;
    verified_at?: string;
    bind_start_path?: string;
    can_bind: boolean;
    can_unbind: boolean;
    note_key?: string;
    note?: string;
}

export interface AuthIdentitySummarySet {
    email: AuthIdentitySummary;
    linuxdo: AuthIdentitySummary;
    oidc: AuthIdentitySummary;
    wechat: AuthIdentitySummary;
    dingtalk: AuthIdentitySummary;
}

export interface AuthUserResponse {
    id: number;
    email: string;
    username: string;
    role: string;
    balance: number;
    frozen_balance: number;
    concurrency: number;
    status: string;
    allowed_groups: number[] | null;
    created_at: string;
    updated_at: string;
    balance_notify_enabled: boolean;
    balance_notify_threshold_type: string;
    balance_notify_threshold: number | null;
    balance_notify_extra_emails: unknown[];
    total_recharged: number;
    rpm_limit: number;
    last_active_at?: string;
}

export interface AuthUserProfileResponse extends AuthUserResponse {
    avatar_url?: string;
    avatar_source?: { provider?: string; source?: string };
    username_source?: { provider?: string; source?: string };
    display_name_source?: { provider?: string; source?: string };
    nickname_source?: { provider?: string; source?: string };
    profile_sources?: Record<string, { provider?: string; source?: string }>;
    identities: AuthIdentitySummarySet;
    auth_bindings: Record<string, AuthIdentitySummary>;
    identity_bindings: Record<string, AuthIdentitySummary>;
    email_bound: boolean;
    linuxdo_bound: boolean;
    oidc_bound: boolean;
    wechat_bound: boolean;
    dingtalk_bound: boolean;
    run_mode: "standard" | "simple";
}

export interface AuthTokenPair {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
}

export interface PasswordLoginResponse {
    access_token: string;
    refresh_token: string;
    expires_in: number;
    token_type: "Bearer";
    user: AuthUserResponse;
}

export interface TotpLoginResponse {
    requires_2fa: true;
    temp_token: string;
    user_email_masked: string;
}

export interface JwtClaims {
    userId: number;
    email: string;
    role: string;
    tokenVersion: bigint;
    expiresAt: number;
    issuedAt: number;
    notBefore: number;
}
