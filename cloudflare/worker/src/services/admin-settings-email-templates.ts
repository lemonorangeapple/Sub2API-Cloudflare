import type { SettingsReader, SettingsWriter } from "../repositories/settings.ts";

const COMMON_PLACEHOLDERS = ["site_name", "recipient_name", "recipient_email"];

const EVENT_ORDER = [
    "auth.verify_code",
    "auth.password_reset",
    "notification_email.verify_code",
    "subscription.purchase_success",
    "subscription.expiry_reminder",
    "balance.low",
    "balance.recharge_success",
    "account.quota_alert",
    "content_moderation.violation_notice",
    "content_moderation.account_disabled",
    "content_moderation.cyber_policy_notice",
    "ops.alert",
    "ops.scheduled_report",
] as const;

type EventType = typeof EVENT_ORDER[number];

interface EventDef {
    event: EventType;
    label: string;
    description: string;
    category: string;
    optional: boolean;
    placeholders: string[];
}

interface OfficialTemplate {
    subject: string;
    html: string;
}

interface StoredOverride {
    subject: string;
    html: string;
    updated_at: string;
}

export interface EmailTemplateEventInfo {
    value: string;
    label: string;
    description: string;
    category: string;
    optional: boolean;
}

export interface EmailTemplateSummary {
    event: string;
    locale: string;
    subject: string;
    is_custom: boolean;
    updated_at?: string;
}

export interface EmailTemplateDetail {
    event: string;
    locale: string;
    subject: string;
    html: string;
    is_custom: boolean;
    updated_at?: string;
    placeholders: string[];
}

export interface EmailTemplatePreviewInput {
    event: string;
    locale: string;
    subject: string;
    html: string;
    variables?: Record<string, string>;
}

export interface EmailTemplatePreview {
    subject: string;
    html: string;
}

export class AdminSettingsEmailTemplatesError extends Error {
    readonly status: number;
    readonly code: string;
    constructor(status: number, code: string, message: string) {
        super(message);
        this.status = status;
        this.code = code;
        this.name = "AdminSettingsEmailTemplatesError";
    }
}

const EVENT_DEFS: Record<EventType, EventDef> = {
    "auth.verify_code": { event: "auth.verify_code", label: "Email verification code", description: "Sent for registration, email binding, OAuth pending email, and TOTP verification flows.", category: "auth", optional: false, placeholders: [...COMMON_PLACEHOLDERS, "verification_code", "expires_in_minutes"] },
    "auth.password_reset": { event: "auth.password_reset", label: "Password reset", description: "Sent when a user requests a password reset link.", category: "auth", optional: false, placeholders: [...COMMON_PLACEHOLDERS, "reset_url", "expires_in_minutes"] },
    "notification_email.verify_code": { event: "notification_email.verify_code", label: "Notification email verification code", description: "Sent when a user verifies an extra notification email address.", category: "auth", optional: false, placeholders: [...COMMON_PLACEHOLDERS, "verification_code", "expires_in_minutes"] },
    "subscription.purchase_success": { event: "subscription.purchase_success", label: "Subscription purchase success", description: "Sent after a subscription purchase is fulfilled.", category: "subscription", optional: false, placeholders: [...COMMON_PLACEHOLDERS, "subscription_group", "subscription_days", "expiry_time", "order_id"] },
    "subscription.expiry_reminder": { event: "subscription.expiry_reminder", label: "Subscription expiry reminder", description: "Optional reminder sent before an active subscription expires.", category: "subscription", optional: true, placeholders: [...COMMON_PLACEHOLDERS, "subscription_group", "expiry_time", "days_remaining", "unsubscribe_url"] },
    "balance.low": { event: "balance.low", label: "Low balance alert", description: "Optional alert sent when balance crosses the configured low-balance threshold.", category: "billing", optional: true, placeholders: [...COMMON_PLACEHOLDERS, "current_balance", "threshold", "recharge_url", "unsubscribe_url"] },
    "balance.recharge_success": { event: "balance.recharge_success", label: "Balance recharge success", description: "Sent after a balance recharge order is fulfilled.", category: "billing", optional: false, placeholders: [...COMMON_PLACEHOLDERS, "recharge_amount", "current_balance", "order_id"] },
    "account.quota_alert": { event: "account.quota_alert", label: "Account quota alert", description: "Sent to configured admin notification emails when an upstream account quota threshold is crossed.", category: "admin", optional: false, placeholders: [...COMMON_PLACEHOLDERS, "account_id", "account_name", "platform", "quota_dimension", "quota_used", "quota_limit", "quota_remaining", "quota_threshold"] },
    "content_moderation.violation_notice": { event: "content_moderation.violation_notice", label: "Risk control violation notice", description: "Sent to users when a request triggers content moderation/risk control rules.", category: "risk_control", optional: false, placeholders: [...COMMON_PLACEHOLDERS, "triggered_at", "group_name", "moderation_category", "moderation_score", "violation_count", "ban_threshold"] },
    "content_moderation.account_disabled": { event: "content_moderation.account_disabled", label: "Risk control account disabled", description: "Sent to users when content moderation automatically disables their account.", category: "risk_control", optional: false, placeholders: [...COMMON_PLACEHOLDERS, "triggered_at", "group_name", "moderation_category", "moderation_score", "violation_count", "ban_threshold"] },
    "content_moderation.cyber_policy_notice": { event: "content_moderation.cyber_policy_notice", label: "Cyber policy notice", description: "Sent to users when an upstream request is blocked by cyber-security policy.", category: "risk_control", optional: false, placeholders: [...COMMON_PLACEHOLDERS, "triggered_at", "model", "group_name", "upstream_message"] },
    "ops.alert": { event: "ops.alert", label: "Ops alert", description: "Sent to configured operations recipients when an ops alert rule fires.", category: "ops", optional: false, placeholders: [...COMMON_PLACEHOLDERS, "rule_name", "severity", "alert_status", "metric_type", "operator", "metric_value", "threshold_value", "triggered_at", "alert_description"] },
    "ops.scheduled_report": { event: "ops.scheduled_report", label: "Ops scheduled report", description: "Sent to configured operations recipients for scheduled reports.", category: "ops", optional: false, placeholders: [...COMMON_PLACEHOLDERS, "report_name", "report_type", "report_start_time", "report_end_time", "report_html"] },
};

function card(accent: string, title: string, content: string): string {
    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { margin: 0; padding: 24px; background: #f4f4f5; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #18181b; }
    .card { max-width: 520px; margin: 0 auto; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
    .header { padding: 20px 24px; background: ${accent}; }
    .header h1 { margin: 0; font-size: 20px; color: #fff; }
    .body { padding: 24px; font-size: 14px; line-height: 1.6; }
    .body p { margin: 0 0 12px; }
    .button { display: inline-block; padding: 10px 20px; background: ${accent}; color: #fff; text-decoration: none; border-radius: 6px; font-size: 14px; }
    .muted { color: #71717a; font-size: 12px; }
    table { width: 100%; border-collapse: collapse; }
    td { padding: 6px 8px; border-bottom: 1px solid #e4e4e7; font-size: 14px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="header"><h1>${title}</h1></div>
    <div class="body">${content}</div>
  </div>
</body>
</html>`;
}

const OFFICIAL_TEMPLATES: Record<string, Record<string, OfficialTemplate>> = {
    "auth.verify_code": {
        en: { subject: "[{{site_name}}] Email verification code", html: card("#4f46e5", "Email verification code", '<p>Hello {{recipient_name}},</p><p>Your verification code is:</p><p style="font-size:32px;font-weight:700;letter-spacing:8px;text-align:center;">{{verification_code}}</p><p>This code expires in <strong>{{expires_in_minutes}}</strong> minutes.</p><p>If you did not request this code, please ignore this email.</p>') },
        zh: { subject: "[{{site_name}}] 邮箱验证码", html: card("#4f46e5", "邮箱验证码", '<p>{{recipient_name}}，您好：</p><p>您的验证码是：</p><p style="font-size:32px;font-weight:700;letter-spacing:8px;text-align:center;">{{verification_code}}</p><p>验证码将在 <strong>{{expires_in_minutes}}</strong> 分钟后失效。</p><p>如果不是您本人操作，请忽略此邮件。</p>') },
    },
    "auth.password_reset": {
        en: { subject: "[{{site_name}}] Password reset request", html: card("#7c3aed", "Password reset", '<p>Hello {{recipient_name}},</p><p>We received a request to reset your password. Click the button below to set a new password.</p><p><a class="button" href="{{reset_url}}">Reset password</a></p><p>This link expires in <strong>{{expires_in_minutes}}</strong> minutes.</p><p class="muted">If the button does not work, copy this link into your browser:<br>{{reset_url}}</p><p>If you did not request this, you can safely ignore this email.</p>') },
        zh: { subject: "[{{site_name}}] 密码重置请求", html: card("#7c3aed", "密码重置", '<p>{{recipient_name}}，您好：</p><p>我们收到了您的密码重置请求，请点击下方按钮设置新密码。</p><p><a class="button" href="{{reset_url}}">重置密码</a></p><p>此链接将在 <strong>{{expires_in_minutes}}</strong> 分钟后失效。</p><p class="muted">如果按钮无法点击，请复制以下链接到浏览器中打开：<br>{{reset_url}}</p><p>如果不是您本人操作，请忽略此邮件。</p>') },
    },
    "notification_email.verify_code": {
        en: { subject: "[{{site_name}}] Notification email verification code", html: card("#0ea5e9", "Notification email verification", '<p>Hello {{recipient_name}},</p><p>You are adding this address as an extra notification email.</p><p>Your verification code is:</p><p style="font-size:32px;font-weight:700;letter-spacing:8px;text-align:center;">{{verification_code}}</p><p>This code expires in <strong>{{expires_in_minutes}}</strong> minutes.</p><p>If you did not request this code, please ignore this email.</p>') },
        zh: { subject: "[{{site_name}}] 通知邮箱验证码", html: card("#0ea5e9", "通知邮箱验证", '<p>{{recipient_name}}，您好：</p><p>您正在添加额外的通知邮箱，请输入以下验证码完成验证。</p><p style="font-size:32px;font-weight:700;letter-spacing:8px;text-align:center;">{{verification_code}}</p><p>验证码将在 <strong>{{expires_in_minutes}}</strong> 分钟后失效。</p><p>如果不是您本人操作，请忽略此邮件。</p>') },
    },
    "subscription.purchase_success": {
        en: { subject: "[{{site_name}}] Subscription purchase successful", html: card("#2563eb", "Subscription activated", '<p>Hello {{recipient_name}},</p><p>Your subscription for <strong>{{subscription_group}}</strong> has been activated for <strong>{{subscription_days}}</strong> days.</p><p>Expiry time: <strong>{{expiry_time}}</strong></p><p>Order ID: {{order_id}}</p>') },
        zh: { subject: "[{{site_name}}] 订阅购买成功", html: card("#2563eb", "订阅已开通", '<p>{{recipient_name}}，您好：</p><p>您的 <strong>{{subscription_group}}</strong> 订阅已成功开通，有效期 <strong>{{subscription_days}}</strong> 天。</p><p>到期时间：<strong>{{expiry_time}}</strong></p><p>订单号：{{order_id}}</p>') },
    },
    "subscription.expiry_reminder": {
        en: { subject: "[{{site_name}}] Subscription expires in {{days_remaining}} day(s)", html: card("#f97316", "Subscription expiry reminder", '<p>Hello {{recipient_name}},</p><p>Your <strong>{{subscription_group}}</strong> subscription will expire in <strong>{{days_remaining}}</strong> day(s).</p><p>Expiry time: <strong>{{expiry_time}}</strong></p><p class="muted"><a href="{{unsubscribe_url}}">Unsubscribe from optional subscription reminders</a></p>') },
        zh: { subject: "[{{site_name}}] 订阅将在 {{days_remaining}} 天后到期", html: card("#f97316", "订阅到期提醒", '<p>{{recipient_name}}，您好：</p><p>您的 <strong>{{subscription_group}}</strong> 订阅将在 <strong>{{days_remaining}}</strong> 天后到期。</p><p>到期时间：<strong>{{expiry_time}}</strong></p><p class="muted"><a href="{{unsubscribe_url}}">退订此类订阅提醒</a></p>') },
    },
    "balance.low": {
        en: { subject: "[{{site_name}}] Low balance alert", html: card("#d97706", "Low balance alert", '<p>Hello {{recipient_name}},</p><p>Your current balance is <strong>${{current_balance}}</strong>, below the configured alert threshold of <strong>${{threshold}}</strong>.</p><p>Please recharge in time to avoid service interruption.</p><p><a class="button" href="{{recharge_url}}">Recharge now</a></p><p class="muted"><a href="{{unsubscribe_url}}">Unsubscribe from optional balance alerts</a></p>') },
        zh: { subject: "[{{site_name}}] 余额不足提醒", html: card("#d97706", "余额不足提醒", '<p>{{recipient_name}}，您好：</p><p>您当前余额为 <strong>${{current_balance}}</strong>，已低于提醒阈值 <strong>${{threshold}}</strong>。</p><p>请及时充值以免服务中断。</p><p><a class="button" href="{{recharge_url}}">立即充值</a></p><p class="muted"><a href="{{unsubscribe_url}}">退订此类余额提醒</a></p>') },
    },
    "balance.recharge_success": {
        en: { subject: "[{{site_name}}] Balance recharge successful", html: card("#16a34a", "Recharge successful", '<p>Hello {{recipient_name}},</p><p>Your balance recharge of <strong>${{recharge_amount}}</strong> has been completed.</p><p>Current balance: <strong>${{current_balance}}</strong></p><p>Order ID: {{order_id}}</p>') },
        zh: { subject: "[{{site_name}}] 余额充值成功", html: card("#16a34a", "余额充值成功", '<p>{{recipient_name}}，您好：</p><p>您的余额充值 <strong>${{recharge_amount}}</strong> 已完成。</p><p>当前余额：<strong>${{current_balance}}</strong></p><p>订单号：{{order_id}}</p>') },
    },
    "account.quota_alert": {
        en: { subject: "[{{site_name}}] Account quota alert - {{account_name}}", html: card("#dc2626", "Account quota alert", '<p>The upstream account <strong>{{account_name}}</strong> has crossed its configured quota alert threshold.</p><table style="width:100%;border-collapse:collapse;"><tr><td>Account ID</td><td>{{account_id}}</td></tr><tr><td>Platform</td><td>{{platform}}</td></tr><tr><td>Dimension</td><td>{{quota_dimension}}</td></tr><tr><td>Used / Limit</td><td>{{quota_used}} / {{quota_limit}}</td></tr><tr><td>Remaining</td><td>{{quota_remaining}}</td></tr><tr><td>Threshold</td><td>{{quota_threshold}}</td></tr></table>') },
        zh: { subject: "[{{site_name}}] 账号限额告警 - {{account_name}}", html: card("#dc2626", "账号限额告警", '<p>上游账号 <strong>{{account_name}}</strong> 已触发配置的额度告警阈值。</p><table style="width:100%;border-collapse:collapse;"><tr><td>账号 ID</td><td>{{account_id}}</td></tr><tr><td>平台</td><td>{{platform}}</td></tr><tr><td>维度</td><td>{{quota_dimension}}</td></tr><tr><td>已用 / 限额</td><td>{{quota_used}} / {{quota_limit}}</td></tr><tr><td>剩余额度</td><td>{{quota_remaining}}</td></tr><tr><td>告警阈值</td><td>{{quota_threshold}}</td></tr></table>') },
    },
    "content_moderation.violation_notice": {
        en: { subject: "[{{site_name}}] Risk control notice", html: card("#ef4444", "Risk control notice", '<p>Hello {{recipient_name}},</p><p>Your API request triggered the platform content moderation/risk-control policy.</p><table style="width:100%;border-collapse:collapse;"><tr><td>Triggered at</td><td>{{triggered_at}}</td></tr><tr><td>Group</td><td>{{group_name}}</td></tr><tr><td>Category / Score</td><td>{{moderation_category}} / {{moderation_score}}</td></tr><tr><td>Violation count</td><td>{{violation_count}} / {{ban_threshold}}</td></tr></table><p>Please review your request content to avoid future service interruptions.</p>') },
        zh: { subject: "[{{site_name}}] 账户风控提醒", html: card("#ef4444", "账户风控提醒", '<p>{{recipient_name}}，您好：</p><p>您的 API 请求触发了平台内容审核/风控策略。</p><table style="width:100%;border-collapse:collapse;"><tr><td>触发时间</td><td>{{triggered_at}}</td></tr><tr><td>所属分组</td><td>{{group_name}}</td></tr><tr><td>命中类别 / 分数</td><td>{{moderation_category}} / {{moderation_score}}</td></tr><tr><td>累计触发次数</td><td>{{violation_count}} / {{ban_threshold}}</td></tr></table><p>请检查请求内容，避免后续服务受到影响。</p>') },
    },
    "content_moderation.account_disabled": {
        en: { subject: "[{{site_name}}] Account disabled by risk control", html: card("#b91c1c", "Account disabled", '<p>Hello {{recipient_name}},</p><p>Your account has repeatedly triggered platform content moderation/risk-control rules and has been automatically disabled.</p><table style="width:100%;border-collapse:collapse;"><tr><td>Disabled at</td><td>{{triggered_at}}</td></tr><tr><td>Group</td><td>{{group_name}}</td></tr><tr><td>Category / Score</td><td>{{moderation_category}} / {{moderation_score}}</td></tr><tr><td>Violation count</td><td>{{violation_count}} / {{ban_threshold}}</td></tr></table><p>Please contact the administrator if you need to appeal or restore access.</p>') },
        zh: { subject: "[{{site_name}}] 账户已被禁用", html: card("#b91c1c", "账户已被禁用", '<p>{{recipient_name}}，您好：</p><p>您的账户在统计周期内多次触发平台内容审核/风控规则，系统已自动禁用该账户。</p><table style="width:100%;border-collapse:collapse;"><tr><td>禁用时间</td><td>{{triggered_at}}</td></tr><tr><td>所属分组</td><td>{{group_name}}</td></tr><tr><td>命中类别 / 分数</td><td>{{moderation_category}} / {{moderation_score}}</td></tr><tr><td>累计触发次数</td><td>{{violation_count}} / {{ban_threshold}}</td></tr></table><p>如需申诉或恢复账号，请联系平台管理员处理。</p>') },
    },
    "content_moderation.cyber_policy_notice": {
        en: { subject: "[{{site_name}}] Cyber-security policy notice", html: card("#ef4444", "Cyber-security policy notice", '<p>Hello {{recipient_name}},</p><p>Your request was blocked by the upstream provider\'s cyber-security policy.</p><table style="width:100%;border-collapse:collapse;"><tr><td>Triggered at</td><td>{{triggered_at}}</td></tr><tr><td>Model</td><td>{{model}}</td></tr><tr><td>Group</td><td>{{group_name}}</td></tr><tr><td>Upstream message</td><td>{{upstream_message}}</td></tr></table><p>If you believe this is a mistake, try rephrasing your request, or apply for authorized security access.</p>') },
        zh: { subject: "[{{site_name}}] 网络安全策略拦截提醒", html: card("#ef4444", "网络安全策略拦截提醒", '<p>{{recipient_name}}，您好：</p><p>您的请求被上游服务商的网络安全策略（cyber policy）拦截。</p><table style="width:100%;border-collapse:collapse;"><tr><td>触发时间</td><td>{{triggered_at}}</td></tr><tr><td>模型</td><td>{{model}}</td></tr><tr><td>所属分组</td><td>{{group_name}}</td></tr><tr><td>上游说明</td><td>{{upstream_message}}</td></tr></table><p>如认为系误判，可调整请求措辞后重试，或申请获得授权的安全访问权限。</p>') },
    },
    "ops.alert": {
        en: { subject: "[Ops Alert][{{severity}}] {{rule_name}}", html: card("#ea580c", "Ops alert", '<p><strong>Rule</strong>: {{rule_name}}</p><p><strong>Severity</strong>: {{severity}}</p><p><strong>Status</strong>: {{alert_status}}</p><p><strong>Metric</strong>: {{metric_type}} {{operator}} {{metric_value}} (threshold {{threshold_value}})</p><p><strong>Fired at</strong>: {{triggered_at}}</p><p><strong>Description</strong>: {{alert_description}}</p>') },
        zh: { subject: "[运维告警][{{severity}}] {{rule_name}}", html: card("#ea580c", "运维告警", '<p><strong>规则</strong>：{{rule_name}}</p><p><strong>严重级别</strong>：{{severity}}</p><p><strong>状态</strong>：{{alert_status}}</p><p><strong>指标</strong>：{{metric_type}} {{operator}} {{metric_value}}（阈值 {{threshold_value}}）</p><p><strong>触发时间</strong>：{{triggered_at}}</p><p><strong>说明</strong>：{{alert_description}}</p>') },
    },
    "ops.scheduled_report": {
        en: { subject: "[Ops Report] {{report_name}}", html: card("#0891b2", "Ops report", '<p><strong>Report</strong>: {{report_name}}</p><p><strong>Type</strong>: {{report_type}}</p><p><strong>Range</strong>: {{report_start_time}} - {{report_end_time}}</p><div>{{report_html}}</div>') },
        zh: { subject: "[运维报表] {{report_name}}", html: card("#0891b2", "运维报表", '<p><strong>报表</strong>：{{report_name}}</p><p><strong>类型</strong>：{{report_type}}</p><p><strong>时间范围</strong>：{{report_start_time}} - {{report_end_time}}</p><div>{{report_html}}</div>') },
    },
};

const LOCALES = ["en", "zh"];
const MAX_SUBJECT_LENGTH = 200;
const MAX_HTML_LENGTH = 30000;
const TEMPLATE_KEY_PREFIX = "notification_email_template:";

const PLACEHOLDER_RE = /\{\{\s*([a-zA-Z][a-zA-Z0-9_]*)\s*\}\}/g;

function normalizeLocale(raw: string): string {
    const trimmed = raw.trim().toLowerCase();
    if (trimmed === "" || trimmed.startsWith("en")) return "en";
    if (trimmed.startsWith("zh") || trimmed === "cn") return "zh";
    return "en";
}

function templateKey(event: string, locale: string): string {
    return TEMPLATE_KEY_PREFIX + event + ":" + locale;
}

function placeholderSet(def: EventDef): Set<string> {
    return new Set(def.placeholders);
}

function extractPlaceholders(text: string): string[] {
    const set = new Set<string>();
    let m: RegExpExecArray | null;
    const re = new RegExp(PLACEHOLDER_RE.source, "g");
    while ((m = re.exec(text)) !== null) {
        set.add(m[1]);
    }
    return [...set];
}

function validateTemplate(event: string, subject: string, html: string): void {
    const def = EVENT_DEFS[event as EventType];
    if (!def) throw new AdminSettingsEmailTemplatesError(400, "INVALID_EVENT", `Unknown event: ${event}`);
    const s = subject.trim();
    if (s === "") throw new AdminSettingsEmailTemplatesError(400, "EMPTY_SUBJECT", "Email subject cannot be empty");
    if (s.length > MAX_SUBJECT_LENGTH) throw new AdminSettingsEmailTemplatesError(400, "SUBJECT_TOO_LONG", `Email subject cannot exceed ${MAX_SUBJECT_LENGTH} characters`);
    const h = html.trim();
    if (h === "") throw new AdminSettingsEmailTemplatesError(400, "EMPTY_HTML", "Email html cannot be empty");
    if (h.length > MAX_HTML_LENGTH) throw new AdminSettingsEmailTemplatesError(400, "HTML_TOO_LONG", `Email html cannot exceed ${MAX_HTML_LENGTH} bytes`);
    const allowed = placeholderSet(def);
    const found = extractPlaceholders(s + "\n" + h);
    for (const ph of found) {
        if (!allowed.has(ph)) throw new AdminSettingsEmailTemplatesError(400, "INVALID_PLACEHOLDER", `Unsupported placeholder {{${ph}}} for event ${event}`);
    }
}

function renderPreview(subject: string, html: string, variables: Record<string, string>): EmailTemplatePreview {
    const renderedSubject = subject.replace(PLACEHOLDER_RE, (_m, name: string) => variables[name] ?? "");
    const renderedHtml = html.replace(PLACEHOLDER_RE, (_m, name: string) => {
        const val = variables[name];
        if (val === undefined) return "";
        return val.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    });
    return { subject: renderedSubject, html: renderedHtml };
}

function sampleVariables(event: string): Record<string, string> {
    const common: Record<string, string> = {
        site_name: "My API Service",
        recipient_name: "John",
        recipient_email: "user@example.com",
    };
    const perEvent: Record<string, Record<string, string>> = {
        "auth.verify_code": { verification_code: "123456", expires_in_minutes: "30" },
        "auth.password_reset": { reset_url: "https://example.com/reset?token=abc", expires_in_minutes: "30" },
        "notification_email.verify_code": { verification_code: "123456", expires_in_minutes: "30" },
        "subscription.purchase_success": { subscription_group: "Pro Plan", subscription_days: "30", expiry_time: "2026-08-18", order_id: "ORD-001" },
        "subscription.expiry_reminder": { subscription_group: "Pro Plan", expiry_time: "2026-08-18", days_remaining: "7", unsubscribe_url: "https://example.com/unsubscribe" },
        "balance.low": { current_balance: "2.50", threshold: "5.00", recharge_url: "https://example.com/recharge", unsubscribe_url: "https://example.com/unsubscribe" },
        "balance.recharge_success": { recharge_amount: "50.00", current_balance: "52.50", order_id: "ORD-002" },
        "account.quota_alert": { account_id: "acct-1", account_name: "OpenAI-Pro-1", platform: "openai", quota_dimension: "tpm", quota_used: "850000", quota_limit: "1000000", quota_remaining: "150000", quota_threshold: "80" },
        "content_moderation.violation_notice": { triggered_at: "2026-07-18T12:00:00Z", group_name: "Default", moderation_category: "hate_speech", moderation_score: "0.92", violation_count: "3", ban_threshold: "5" },
        "content_moderation.account_disabled": { triggered_at: "2026-07-18T12:00:00Z", group_name: "Default", moderation_category: "hate_speech", moderation_score: "0.95", violation_count: "5", ban_threshold: "5" },
        "content_moderation.cyber_policy_notice": { triggered_at: "2026-07-18T12:00:00Z", model: "gpt-4", group_name: "Default", upstream_message: "Request blocked by cyber policy" },
        "ops.alert": { rule_name: "High Error Rate", severity: "critical", alert_status: "firing", metric_type: "error_rate", operator: ">", metric_value: "15%", threshold_value: "10%", triggered_at: "2026-07-18T12:00:00Z", alert_description: "Error rate exceeded threshold for 5 minutes" },
        "ops.scheduled_report": { report_name: "Daily Summary", report_type: "daily", report_start_time: "2026-07-17T00:00:00Z", report_end_time: "2026-07-18T00:00:00Z", report_html: "<p>Sample report content</p>" },
    };
    return { ...common, ...(perEvent[event] ?? {}) };
}

export class D1AdminSettingsEmailTemplatesService {
    readonly #settings: SettingsReader & SettingsWriter;

    constructor(settings: SettingsReader & SettingsWriter) {
        this.#settings = settings;
    }

    listEvents(): EmailTemplateEventInfo[] {
        return EVENT_ORDER.map((ev) => {
            const def = EVENT_DEFS[ev];
            return { value: def.event, label: def.label, description: def.description, category: def.category, optional: def.optional };
        });
    }

    supportedLocales(): string[] {
        return [...LOCALES];
    }

    allPlaceholders(): string[] {
        const all = new Set<string>();
        for (const ev of EVENT_ORDER) {
            for (const ph of EVENT_DEFS[ev].placeholders) {
                all.add(ph);
            }
        }
        return [...all];
    }

    async getTemplate(event: string, locale: string): Promise<EmailTemplateDetail> {
        const normalizedEvent = event as EventType;
        const def = EVENT_DEFS[normalizedEvent];
        if (!def) throw new AdminSettingsEmailTemplatesError(400, "INVALID_EVENT", `Unknown event: ${event}`);
        const normalizedLocale = normalizeLocale(locale);
        const official = OFFICIAL_TEMPLATES[normalizedEvent]?.[normalizedLocale];
        if (!official) throw new AdminSettingsEmailTemplatesError(400, "TEMPLATE_NOT_FOUND", `Official template not found for ${normalizedEvent}/${normalizedLocale}`);

        const detail: EmailTemplateDetail = {
            event: normalizedEvent,
            locale: normalizedLocale,
            subject: official.subject,
            html: official.html,
            is_custom: false,
            placeholders: [...def.placeholders],
        };

        const raw = await this.#settings.getMany([templateKey(normalizedEvent, normalizedLocale)]);
        const storedJson = raw[templateKey(normalizedEvent, normalizedLocale)];
        if (storedJson && storedJson.trim() !== "") {
            try {
                const stored: StoredOverride = JSON.parse(storedJson);
                if (stored.subject && stored.html) {
                    detail.subject = stored.subject;
                    detail.html = stored.html;
                    detail.is_custom = true;
                    detail.updated_at = stored.updated_at;
                }
            } catch {
                // ignore corrupt override
            }
        }

        return detail;
    }

    async listTemplates(): Promise<EmailTemplateSummary[]> {
        const items: EmailTemplateSummary[] = [];
        for (const event of EVENT_ORDER) {
            for (const locale of LOCALES) {
                const tmpl = await this.getTemplate(event, locale);
                items.push({
                    event: tmpl.event,
                    locale: tmpl.locale,
                    subject: tmpl.subject,
                    is_custom: tmpl.is_custom,
                    updated_at: tmpl.updated_at,
                });
            }
        }
        return items;
    }

    async updateTemplate(event: string, locale: string, subject: string, html: string): Promise<EmailTemplateDetail> {
        const normalizedEvent = event as EventType;
        const def = EVENT_DEFS[normalizedEvent];
        if (!def) throw new AdminSettingsEmailTemplatesError(400, "INVALID_EVENT", `Unknown event: ${event}`);
        const normalizedLocale = normalizeLocale(locale);
        validateTemplate(normalizedEvent, subject, html);

        const stored: StoredOverride = {
            subject: subject.trim(),
            html,
            updated_at: new Date().toISOString(),
        };
        await this.#settings.upsertMany(
            { [templateKey(normalizedEvent, normalizedLocale)]: JSON.stringify(stored) },
            stored.updated_at
        );

        return this.getTemplate(normalizedEvent, normalizedLocale);
    }

    async restoreOfficial(event: string, locale: string): Promise<EmailTemplateDetail> {
        const normalizedEvent = event as EventType;
        if (!EVENT_DEFS[normalizedEvent]) throw new AdminSettingsEmailTemplatesError(400, "INVALID_EVENT", `Unknown event: ${event}`);
        const normalizedLocale = normalizeLocale(locale);
        await this.#settings.delete(templateKey(normalizedEvent, normalizedLocale));
        return this.getTemplate(normalizedEvent, normalizedLocale);
    }

    async preview(input: EmailTemplatePreviewInput): Promise<EmailTemplatePreview> {
        const normalizedEvent = input.event as EventType;
        const def = EVENT_DEFS[normalizedEvent];
        if (!def) throw new AdminSettingsEmailTemplatesError(400, "INVALID_EVENT", `Unknown event: ${input.event}`);
        const normalizedLocale = normalizeLocale(input.locale);
        let subject = input.subject.trim();
        let html = input.html.trim();
        if (subject === "" || html === "") {
            const tmpl = await this.getTemplate(normalizedEvent, normalizedLocale);
            if (subject === "") subject = tmpl.subject;
            if (html === "") html = tmpl.html;
        }
        validateTemplate(normalizedEvent, subject, html);
        const variables = { ...sampleVariables(normalizedEvent), ...(input.variables ?? {}) };
        return renderPreview(subject, html, variables);
    }
}
