import type { AuthUserRecord, AuthUserResponse } from "../types/auth.ts";

export function mapAuthUser(user: AuthUserRecord, lastActiveAt = user.lastActiveAt): AuthUserResponse {
    return {
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
        balance: user.balance,
        frozen_balance: user.frozenBalance,
        concurrency: user.concurrency,
        status: user.status,
        allowed_groups: user.allowedGroups,
        created_at: user.createdAt,
        updated_at: user.updatedAt,
        balance_notify_enabled: user.balanceNotifyEnabled,
        balance_notify_threshold_type: user.balanceNotifyThresholdType,
        balance_notify_threshold: user.balanceNotifyThreshold,
        balance_notify_extra_emails: user.balanceNotifyExtraEmails,
        total_recharged: user.totalRecharged,
        rpm_limit: user.rpmLimit,
        ...(lastActiveAt ? { last_active_at: lastActiveAt } : {})
    };
}
