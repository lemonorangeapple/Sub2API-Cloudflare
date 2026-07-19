import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement } from "./d1.ts";

export interface OpsErrorLog {
    id: number;
    requestId: string | null;
    clientRequestId: string | null;
    userId: number | null;
    apiKeyId: number | null;
    accountId: number | null;
    groupId: number | null;
    clientIp: string | null;
    platform: string | null;
    model: string | null;
    requestPath: string | null;
    stream: boolean;
    userAgent: string | null;
    errorPhase: string;
    errorType: string;
    severity: string;
    statusCode: number | null;
    isBusinessLimited: boolean;
    errorMessage: string | null;
    errorBody: string | null;
    errorSource: string | null;
    errorOwner: string | null;
    accountStatus: string | null;
    upstreamStatusCode: number | null;
    upstreamErrorMessage: string | null;
    upstreamErrorDetail: string | null;
    providerErrorCode: string | null;
    providerErrorType: string | null;
    networkErrorType: string | null;
    retryAfterSeconds: number | null;
    durationMs: number | null;
    timeToFirstTokenMs: number | null;
    authLatencyMs: number | null;
    routingLatencyMs: number | null;
    upstreamLatencyMs: number | null;
    responseLatencyMs: number | null;
    createdAt: string;
    upstreamErrors: string | null;
    isCountTokens: boolean;
    resolved: boolean;
    resolvedAt: string | null;
    resolvedByUserId: number | null;
    inboundEndpoint: string | null;
    upstreamEndpoint: string | null;
    requestedModel: string | null;
    upstreamModel: string | null;
    requestType: number | null;
    attemptedKeyPrefix: string | null;
    deletedKeyOwnerUserId: number | null;
    deletedKeyName: string | null;
    apiKeyPrefix: string | null;
}

export interface OpsSystemLog {
    id: number;
    level: string;
    component: string;
    message: string;
    details: string | null;
    requestId: string | null;
    clientRequestId: string | null;
    userId: number | null;
    accountId: number | null;
    platform: string | null;
    model: string | null;
    host: string | null;
    apiKeyId: number | null;
    createdAt: string;
}

export interface OpsAlertRule {
    id: number;
    name: string;
    description: string | null;
    enabled: boolean;
    severity: string;
    metricType: string;
    operator: string;
    threshold: number;
    windowMinutes: number;
    sustainedMinutes: number;
    cooldownMinutes: number;
    filters: string | null;
    lastTriggeredAt: string | null;
    createdAt: string;
    updatedAt: string;
    notifyEmail: boolean;
}

export interface OpsAlertEvent {
    id: number;
    ruleId: number;
    severity: string;
    status: string;
    title: string | null;
    description: string | null;
    metricValue: number | null;
    thresholdValue: number | null;
    dimensions: string | null;
    firedAt: string;
    resolvedAt: string | null;
    emailSent: boolean;
    createdAt: string;
}

export interface OpsAlertSilence {
    id: number;
    ruleId: number;
    platform: string;
    groupId: number | null;
    region: string | null;
    until: string;
    reason: string | null;
    createdBy: number;
    createdAt: string;
}

export interface OpsConcurrencyStats {
    totalConcurrency: number;
    usedConcurrency: number;
    availableConcurrency: number;
    queueDepth: number;
    activeAccounts: number;
}

export interface OpsUserConcurrencyStats {
    userId: number;
    username: string;
    concurrencyLimit: number;
    currentUsage: number;
}

export interface OpsAccountAvailability {
    accountId: number;
    accountName: string;
    platform: string;
    status: string;
    availableConcurrency: number;
    totalConcurrency: number;
    healthScore: number;
}

export interface OpsRealtimeTrafficSummary {
    qps: number;
    tps: number;
    activeUsers: number;
    activeAccounts: number;
    errorRate: number;
    avgLatencyMs: number;
    p50LatencyMs: number;
    p95LatencyMs: number;
    p99LatencyMs: number;
}

export interface OpsEmailNotificationConfig {
    enabled: boolean;
    recipients: string[];
    alertTypes: string[];
    throttleMinutes: number;
}

export interface OpsRuntimeAlertSettings {
    checkIntervalMinutes: number;
    evaluationWindowMinutes: number;
    maxConcurrentAlerts: number;
}

export interface OpsRuntimeLogConfig {
    level: string;
    components: string[];
    retentionDays: number;
    samplingRate: number;
}

export interface OpsAdvancedSettings {
    featureFlags: Record<string, boolean>;
    experimentalFeatures: Record<string, boolean>;
}

export interface OpsMetricThresholds {
    errorRatePct: number;
    latencyP95Ms: number;
    latencyP99Ms: number;
    queueDepth: number;
    cpuUsagePct: number;
    memoryUsagePct: number;
}

export interface OpsDashboardSnapshotV2 {
    timestamp: string;
    qps: number;
    tps: number;
    activeRequests: number;
    errorRate: number;
    latencyP50: number;
    latencyP95: number;
    latencyP99: number;
    topErrors: Array<{ error: string; count: number }>;
    topModels: Array<{ model: string; requests: number }>;
    topAccounts: Array<{ account: string; requests: number }>;
}

export interface OpsDashboardOverview {
    totalRequests: number;
    successRate: number;
    avgLatency: number;
    errorBreakdown: Record<string, number>;
    trafficTrend: Array<{ time: string; requests: number }>;
}

export interface OpsThroughputTrend {
    trend: Array<{ time: string; qps: number; tps: number }>;
}

export interface OpsLatencyHistogram {
    buckets: Array<{ range: string; count: number }>;
    percentiles: Record<string, number>;
}

export interface OpsErrorTrend {
    trend: Array<{ time: string; errorRate: number; errorCount: number }>;
}

export interface OpsErrorDistribution {
    byType: Record<string, number>;
    byPhase: Record<string, number>;
    byPlatform: Record<string, number>;
}

export interface OpsOpenAITokenStats {
    totalTokens: number;
    promptTokens: number;
    completionTokens: number;
    estimatedCost: number;
    byModel: Record<string, { prompt: number; completion: number; cost: number }>;
}

export interface D1OpsRepository {
    getConcurrencyStats(): Promise<OpsConcurrencyStats>;
    getUserConcurrencyStats(): Promise<OpsUserConcurrencyStats[]>;
    getAccountAvailability(): Promise<OpsAccountAvailability[]>;
    getRealtimeTrafficSummary(): Promise<OpsRealtimeTrafficSummary>;

    listAlertRules(): Promise<OpsAlertRule[]>;
    createAlertRule(rule: Omit<OpsAlertRule, "id" | "createdAt" | "updatedAt" | "lastTriggeredAt">): Promise<number>;
    updateAlertRule(id: number, rule: Partial<OpsAlertRule>): Promise<boolean>;
    deleteAlertRule(id: number): Promise<boolean>;

    listAlertEvents(filters?: { status?: string; ruleId?: number; limit?: number; offset?: number }): Promise<OpsAlertEvent[]>;
    getAlertEvent(id: number): Promise<OpsAlertEvent | null>;
    updateAlertEventStatus(id: number, status: string): Promise<boolean>;

    createAlertSilence(silence: Omit<OpsAlertSilence, "id" | "createdAt">): Promise<number>;

    getEmailNotificationConfig(): Promise<OpsEmailNotificationConfig>;
    updateEmailNotificationConfig(config: OpsEmailNotificationConfig): Promise<boolean>;

    getAlertRuntimeSettings(): Promise<OpsRuntimeAlertSettings>;
    updateAlertRuntimeSettings(settings: OpsRuntimeAlertSettings): Promise<boolean>;
    getRuntimeLogConfig(): Promise<OpsRuntimeLogConfig>;
    updateRuntimeLogConfig(config: OpsRuntimeLogConfig): Promise<boolean>;
    resetRuntimeLogConfig(): Promise<boolean>;

    getAdvancedSettings(): Promise<OpsAdvancedSettings>;
    updateAdvancedSettings(settings: OpsAdvancedSettings): Promise<boolean>;

    getMetricThresholds(): Promise<OpsMetricThresholds>;
    updateMetricThresholds(thresholds: OpsMetricThresholds): Promise<boolean>;

    listErrorLogs(filters?: { statusCode?: number; platform?: string; userId?: number; resolved?: boolean; limit?: number; offset?: number }): Promise<OpsErrorLog[]>;
    getErrorLog(id: number): Promise<OpsErrorLog | null>;
    updateErrorResolution(id: number, resolved: boolean, userId: number): Promise<boolean>;

    listRequestErrors(filters?: { statusCode?: number; platform?: string; limit?: number; offset?: number }): Promise<OpsErrorLog[]>;
    getRequestError(id: number): Promise<OpsErrorLog | null>;
    listRequestErrorUpstreamErrors(requestErrorId: number): Promise<OpsErrorLog[]>;
    resolveRequestError(id: number): Promise<boolean>;

    listUpstreamErrors(filters?: { platform?: string; limit?: number; offset?: number }): Promise<OpsErrorLog[]>;
    getUpstreamError(id: number): Promise<OpsErrorLog | null>;
    resolveUpstreamError(id: number): Promise<boolean>;

    listRequestDetails(filters?: { statusCode?: number; platform?: string; userId?: number; limit?: number; offset?: number }): Promise<OpsErrorLog[]>;

    listSystemLogs(filters?: { level?: string; component?: string; limit?: number; offset?: number }): Promise<OpsSystemLog[]>;
    cleanupSystemLogs(beforeDate: string): Promise<number>;
    getSystemLogIngestionHealth(): Promise<{ totalLogs: number; latestLog: string | null; errorsLastHour: number }>;

    getDashboardSnapshotV2(): Promise<OpsDashboardSnapshotV2>;
    getDashboardOverview(): Promise<OpsDashboardOverview>;
    getDashboardThroughputTrend(): Promise<OpsThroughputTrend>;
    getDashboardLatencyHistogram(): Promise<OpsLatencyHistogram>;
    getDashboardErrorTrend(): Promise<OpsErrorTrend>;
    getDashboardErrorDistribution(): Promise<OpsErrorDistribution>;
    getDashboardOpenAITokenStats(): Promise<OpsOpenAITokenStats>;
}

export class D1OpsRepositoryImpl implements D1OpsRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async getConcurrencyStats() {
        const totalRow = await firstRow<{ total: number }>(this.#db, "SELECT SUM(concurrency) as total FROM users WHERE deleted_at IS NULL AND status = 'active'");
        const activeRow = await firstRow<{ count: number }>(this.#db, "SELECT COUNT(*) as count FROM users WHERE deleted_at IS NULL AND status = 'active' AND concurrency > 0");
        const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
        const recentAccounts = await firstRow<{ cnt: number }>(this.#db, "SELECT COUNT(DISTINCT account_id) as cnt FROM usage_logs WHERE created_at >= ?", [fiveMinAgo]);
        const recentUsage = await firstRow<{ cnt: number }>(this.#db, "SELECT COUNT(DISTINCT api_key_id) as cnt FROM usage_logs WHERE created_at >= ?", [fiveMinAgo]);
        return {
            totalConcurrency: totalRow?.total ?? 0,
            usedConcurrency: recentUsage?.cnt ?? 0,
            availableConcurrency: (totalRow?.total ?? 0) - (recentUsage?.cnt ?? 0),
            queueDepth: 0,
            activeAccounts: recentAccounts?.cnt ?? 0,
        };
    }

    async getUserConcurrencyStats() {
        const rows = await allRows<{ id: number; username: string; concurrency: number }>(
            this.#db, "SELECT id, username, concurrency FROM users WHERE deleted_at IS NULL AND status = 'active' AND concurrency > 0 ORDER BY concurrency DESC"
        );
        const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
        const result: OpsUserConcurrencyStats[] = [];
        for (const r of rows) {
            const usageRow = await firstRow<{ cnt: number }>(this.#db, "SELECT COUNT(DISTINCT api_key_id) as cnt FROM usage_logs WHERE user_id = ? AND created_at >= ?", [r.id, fiveMinAgo]);
            result.push({ userId: r.id, username: r.username, concurrencyLimit: r.concurrency, currentUsage: usageRow?.cnt ?? 0 });
        }
        return result;
    }

    async getAccountAvailability() {
        const rows = await allRows<{ id: number; name: string; platform: string; status: string; concurrency: number }>(
            this.#db, "SELECT id, name, platform, status, concurrency FROM accounts WHERE deleted_at IS NULL ORDER BY name"
        );
        const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
        const result: OpsAccountAvailability[] = [];
        for (const r of rows) {
            const recentRow = await firstRow<{ cnt: number }>(this.#db, "SELECT COUNT(*) as cnt FROM usage_logs WHERE account_id = ? AND created_at >= ?", [r.id, fiveMinAgo]);
            const usageCount = recentRow?.cnt ?? 0;
            const available = Math.max(0, r.concurrency - usageCount);
            result.push({
                accountId: r.id,
                accountName: r.name,
                platform: r.platform,
                status: r.status,
                availableConcurrency: r.status === "active" ? available : 0,
                totalConcurrency: r.concurrency,
                healthScore: r.status === "active" ? (usageCount === 0 ? 100 : Math.max(0, 100 - usageCount)) : 0,
            });
        }
        return result;
    }

    async getRealtimeTrafficSummary() {
        const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
        const oneMinAgo = new Date(Date.now() - 60 * 1000).toISOString();
        const recentLogs = await allRows<{ duration_ms: number | null; created_at: string }>(
            this.#db, `SELECT duration_ms, created_at FROM usage_logs WHERE created_at >= ? ORDER BY created_at DESC LIMIT 5000`, [fiveMinAgo]
        );
        const recentErrors = await firstRow<{ cnt: number }>(this.#db, "SELECT COUNT(*) as cnt FROM ops_error_logs WHERE created_at >= ?", [fiveMinAgo]);
        const total = recentLogs.length;
        const latencies = recentLogs.map((l) => l.duration_ms).filter((l): l is number => l !== null).sort((a, b) => a - b);
        const recentMinute = recentLogs.filter((l) => l.created_at >= oneMinAgo).length;
        const activeUsers = await firstRow<{ cnt: number }>(this.#db, "SELECT COUNT(DISTINCT user_id) as cnt FROM usage_logs WHERE created_at >= ?", [fiveMinAgo]);
        const activeAccounts = await firstRow<{ cnt: number }>(this.#db, "SELECT COUNT(DISTINCT account_id) as cnt FROM usage_logs WHERE created_at >= ?", [fiveMinAgo]);
        return {
            qps: recentMinute / 60,
            tps: recentLogs.reduce((sum, l) => sum + (l.duration_ms ?? 0), 0) / 300,
            activeUsers: activeUsers?.cnt ?? 0,
            activeAccounts: activeAccounts?.cnt ?? 0,
            errorRate: total > 0 ? (recentErrors?.cnt ?? 0) / total : 0,
            avgLatencyMs: latencies.length > 0 ? latencies.reduce((a, b) => a + b, 0) / latencies.length : 0,
            p50LatencyMs: latencies[Math.floor(latencies.length * 0.5)] ?? 0,
            p95LatencyMs: latencies[Math.floor(latencies.length * 0.95)] ?? 0,
            p99LatencyMs: latencies[Math.floor(latencies.length * 0.99)] ?? 0,
        };
    }

    async listAlertRules() {
        const rows = await allRows<any>(this.#db, "SELECT * FROM ops_alert_rules ORDER BY created_at DESC");
        return rows.map((r) => ({
            id: r.id, name: r.name, description: r.description, enabled: r.enabled === 1,
            severity: r.severity, metricType: r.metric_type, operator: r.operator, threshold: r.threshold,
            windowMinutes: r.window_minutes, sustainedMinutes: r.sustained_minutes, cooldownMinutes: r.cooldown_minutes,
            filters: r.filters, lastTriggeredAt: r.last_triggered_at, createdAt: r.created_at, updatedAt: r.updated_at, notifyEmail: r.notify_email === 1,
        }));
    }

    async createAlertRule(rule: Omit<OpsAlertRule, "id" | "createdAt" | "updatedAt" | "lastTriggeredAt">) {
        const now = new Date().toISOString();
        const result = await runStatement(
            this.#db,
            `INSERT INTO ops_alert_rules (name, description, enabled, severity, metric_type, operator, threshold, window_minutes, sustained_minutes, cooldown_minutes, filters, notify_email, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [rule.name, rule.description ?? null, rule.enabled ? 1 : 0, rule.severity, rule.metricType, rule.operator, rule.threshold,
                rule.windowMinutes, rule.sustainedMinutes, rule.cooldownMinutes, rule.filters ?? null, rule.notifyEmail ? 1 : 0, now, now]
        );
        return Number(result.meta?.last_row_id ?? 0);
    }

    async updateAlertRule(id: number, updates: Partial<OpsAlertRule>) {
        const fields: string[] = [];
        const values: any[] = [];
        const now = new Date().toISOString();
        if (updates.name !== undefined) { fields.push("name = ?"); values.push(updates.name); }
        if (updates.description !== undefined) { fields.push("description = ?"); values.push(updates.description); }
        if (updates.enabled !== undefined) { fields.push("enabled = ?"); values.push(updates.enabled ? 1 : 0); }
        if (updates.severity !== undefined) { fields.push("severity = ?"); values.push(updates.severity); }
        if (updates.metricType !== undefined) { fields.push("metric_type = ?"); values.push(updates.metricType); }
        if (updates.operator !== undefined) { fields.push("operator = ?"); values.push(updates.operator); }
        if (updates.threshold !== undefined) { fields.push("threshold = ?"); values.push(updates.threshold); }
        if (updates.windowMinutes !== undefined) { fields.push("window_minutes = ?"); values.push(updates.windowMinutes); }
        if (updates.sustainedMinutes !== undefined) { fields.push("sustained_minutes = ?"); values.push(updates.sustainedMinutes); }
        if (updates.cooldownMinutes !== undefined) { fields.push("cooldown_minutes = ?"); values.push(updates.cooldownMinutes); }
        if (updates.filters !== undefined) { fields.push("filters = ?"); values.push(updates.filters); }
        if (updates.notifyEmail !== undefined) { fields.push("notify_email = ?"); values.push(updates.notifyEmail ? 1 : 0); }
        fields.push("updated_at = ?"); values.push(now);
        values.push(id);
        const result = await runStatement(this.#db, `UPDATE ops_alert_rules SET ${fields.join(", ")} WHERE id = ?`, values);
        return (result.meta?.changes ?? 0) > 0;
    }

    async deleteAlertRule(id: number) {
        const result = await runStatement(this.#db, "DELETE FROM ops_alert_rules WHERE id = ?", [id]);
        return (result.meta?.changes ?? 0) > 0;
    }

    async listAlertEvents(filters?: { status?: string; ruleId?: number; limit?: number; offset?: number }) {
        const conditions: string[] = [];
        const values: any[] = [];
        if (filters?.status) { conditions.push("status = ?"); values.push(filters.status); }
        if (filters?.ruleId) { conditions.push("rule_id = ?"); values.push(filters.ruleId); }
        const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
        const limit = filters?.limit ?? 50;
        const offset = filters?.offset ?? 0;
        values.push(limit, offset);
        const rows = await allRows<any>(this.#db, `SELECT * FROM ops_alert_events ${where} ORDER BY fired_at DESC LIMIT ? OFFSET ?`, values);
        return rows.map((r) => ({
            id: r.id, ruleId: r.rule_id, severity: r.severity, status: r.status,
            title: r.title, description: r.description, metricValue: r.metric_value,
            thresholdValue: r.threshold_value, dimensions: r.dimensions, firedAt: r.fired_at,
            resolvedAt: r.resolved_at, emailSent: r.email_sent === 1, createdAt: r.created_at,
        }));
    }

    async getAlertEvent(id: number) {
        const row = await firstRow<any>(this.#db, "SELECT * FROM ops_alert_events WHERE id = ?", [id]);
        if (!row) return null;
        return {
            id: row.id, ruleId: row.rule_id, severity: row.severity, status: row.status,
            title: row.title, description: row.description, metricValue: row.metric_value,
            thresholdValue: row.threshold_value, dimensions: row.dimensions, firedAt: row.fired_at,
            resolvedAt: row.resolved_at, emailSent: row.email_sent === 1, createdAt: row.created_at,
        };
    }

    async updateAlertEventStatus(id: number, status: string) {
        const result = await runStatement(this.#db, "UPDATE ops_alert_events SET status = ?, resolved_at = CASE WHEN ? = 'resolved' THEN datetime('now') ELSE resolved_at END WHERE id = ?", [status, status, id]);
        return (result.meta?.changes ?? 0) > 0;
    }

    async createAlertSilence(silence: Omit<OpsAlertSilence, "id" | "createdAt">) {
        const now = new Date().toISOString();
        const result = await runStatement(
            this.#db,
            "INSERT INTO ops_alert_silences (rule_id, platform, group_id, region, until, reason, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [silence.ruleId, silence.platform, silence.groupId ?? null, silence.region ?? null, silence.until, silence.reason ?? null, silence.createdBy ?? 0, now]
        );
        return Number(result.meta?.last_row_id ?? 0);
    }

    async getEmailNotificationConfig(): Promise<OpsEmailNotificationConfig> {
        const row = await firstRow<{ value: string }>(this.#db, "SELECT value FROM settings WHERE key = ?", ["ops_email_notification_config"]);
        if (!row) return { enabled: false, recipients: [], alertTypes: [], throttleMinutes: 60 };
        return JSON.parse(row.value) as OpsEmailNotificationConfig;
    }
    async updateEmailNotificationConfig(config: OpsEmailNotificationConfig): Promise<boolean> {
        const now = new Date().toISOString();
        const result = await runStatement(this.#db, "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)", ["ops_email_notification_config", JSON.stringify(config), now]);
        return (result.meta?.changes ?? 0) > 0;
    }
    async getAlertRuntimeSettings(): Promise<OpsRuntimeAlertSettings> {
        const row = await firstRow<{ value: string }>(this.#db, "SELECT value FROM settings WHERE key = ?", ["ops_alert_runtime_settings"]);
        if (!row) return { checkIntervalMinutes: 5, evaluationWindowMinutes: 10, maxConcurrentAlerts: 100 };
        return JSON.parse(row.value) as OpsRuntimeAlertSettings;
    }
    async updateAlertRuntimeSettings(settings: OpsRuntimeAlertSettings): Promise<boolean> {
        const now = new Date().toISOString();
        const result = await runStatement(this.#db, "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)", ["ops_alert_runtime_settings", JSON.stringify(settings), now]);
        return (result.meta?.changes ?? 0) > 0;
    }
    async getRuntimeLogConfig(): Promise<OpsRuntimeLogConfig> {
        const row = await firstRow<{ value: string }>(this.#db, "SELECT value FROM settings WHERE key = ?", ["ops_runtime_log_config"]);
        if (!row) return { level: "info", components: [], retentionDays: 30, samplingRate: 1.0 };
        return JSON.parse(row.value) as OpsRuntimeLogConfig;
    }
    async updateRuntimeLogConfig(config: OpsRuntimeLogConfig): Promise<boolean> {
        const now = new Date().toISOString();
        const result = await runStatement(this.#db, "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)", ["ops_runtime_log_config", JSON.stringify(config), now]);
        return (result.meta?.changes ?? 0) > 0;
    }
    async resetRuntimeLogConfig(): Promise<boolean> {
        const defaults: OpsRuntimeLogConfig = { level: "info", components: [], retentionDays: 30, samplingRate: 1.0 };
        const now = new Date().toISOString();
        const result = await runStatement(this.#db, "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)", ["ops_runtime_log_config", JSON.stringify(defaults), now]);
        return (result.meta?.changes ?? 0) > 0;
    }
    async getAdvancedSettings(): Promise<OpsAdvancedSettings> {
        const row = await firstRow<{ value: string }>(this.#db, "SELECT value FROM settings WHERE key = ?", ["ops_advanced_settings"]);
        if (!row) return { featureFlags: {}, experimentalFeatures: {} };
        return JSON.parse(row.value) as OpsAdvancedSettings;
    }
    async updateAdvancedSettings(settings: OpsAdvancedSettings): Promise<boolean> {
        const now = new Date().toISOString();
        const result = await runStatement(this.#db, "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)", ["ops_advanced_settings", JSON.stringify(settings), now]);
        return (result.meta?.changes ?? 0) > 0;
    }
    async getMetricThresholds(): Promise<OpsMetricThresholds> {
        const row = await firstRow<{ value: string }>(this.#db, "SELECT value FROM settings WHERE key = ?", ["ops_metric_thresholds"]);
        if (!row) return { errorRatePct: 5, latencyP95Ms: 2000, latencyP99Ms: 5000, queueDepth: 100, cpuUsagePct: 85, memoryUsagePct: 90 };
        return JSON.parse(row.value) as OpsMetricThresholds;
    }
    async updateMetricThresholds(thresholds: OpsMetricThresholds): Promise<boolean> {
        const now = new Date().toISOString();
        const result = await runStatement(this.#db, "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)", ["ops_metric_thresholds", JSON.stringify(thresholds), now]);
        return (result.meta?.changes ?? 0) > 0;
    }

    async listErrorLogs(filters?: { statusCode?: number; platform?: string; userId?: number; resolved?: boolean; errorPhase?: string; limit?: number; offset?: number }) {
        const conditions: string[] = [];
        const values: any[] = [];
        if (filters?.statusCode) { conditions.push("status_code = ?"); values.push(filters.statusCode); }
        if (filters?.platform) { conditions.push("platform = ?"); values.push(filters.platform); }
        if (filters?.userId) { conditions.push("user_id = ?"); values.push(filters.userId); }
        if (filters?.resolved !== undefined) { conditions.push("resolved = ?"); values.push(filters.resolved ? 1 : 0); }
        if (filters?.errorPhase) { conditions.push("error_phase = ?"); values.push(filters.errorPhase); }
        const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
        const limit = filters?.limit ?? 50;
        const offset = filters?.offset ?? 0;
        values.push(limit, offset);
        const rows = await allRows<any>(this.#db, `SELECT * FROM ops_error_logs ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`, values);
        return rows.map(this.mapErrorLog);
    }

    async getErrorLog(id: number) {
        const row = await firstRow<any>(this.#db, "SELECT * FROM ops_error_logs WHERE id = ?", [id]);
        return row ? this.mapErrorLog(row) : null;
    }

    async updateErrorResolution(id: number, resolved: boolean, userId: number) {
        const now = new Date().toISOString();
        const result = await runStatement(this.#db, "UPDATE ops_error_logs SET resolved = ?, resolved_at = ?, resolved_by_user_id = ? WHERE id = ?", [resolved ? 1 : 0, now, userId, id]);
        return (result.meta?.changes ?? 0) > 0;
    }

    async listRequestErrors(filters?: { statusCode?: number; platform?: string; limit?: number; offset?: number }) {
        return this.listErrorLogs({ ...filters, errorPhase: "request" });
    }

    async getRequestError(id: number) { return this.getErrorLog(id); }

    async listRequestErrorUpstreamErrors(requestErrorId: number) {
        const rows = await allRows<any>(this.#db, "SELECT * FROM ops_error_logs WHERE request_id = (SELECT request_id FROM ops_error_logs WHERE id = ?) AND error_phase = 'upstream'", [requestErrorId]);
        return rows.map(this.mapErrorLog);
    }

    async resolveRequestError(id: number) { return this.updateErrorResolution(id, true, 0); }

    async listUpstreamErrors(filters?: { platform?: string; limit?: number; offset?: number }) {
        return this.listErrorLogs({ ...filters, errorPhase: "upstream" });
    }

    async getUpstreamError(id: number) { return this.getErrorLog(id); }

    async resolveUpstreamError(id: number) { return this.updateErrorResolution(id, true, 0); }

    async listRequestDetails(filters?: { statusCode?: number; platform?: string; userId?: number; limit?: number; offset?: number }) {
        return this.listErrorLogs(filters);
    }

    async listSystemLogs(filters?: { level?: string; component?: string; limit?: number; offset?: number }) {
        const conditions: string[] = [];
        const values: any[] = [];
        if (filters?.level) { conditions.push("level = ?"); values.push(filters.level); }
        if (filters?.component) { conditions.push("component = ?"); values.push(filters.component); }
        const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
        const limit = filters?.limit ?? 50;
        const offset = filters?.offset ?? 0;
        values.push(limit, offset);
        const rows = await allRows<any>(this.#db, `SELECT * FROM ops_system_logs ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`, values);
        return rows.map((r) => ({
            id: r.id, level: r.level, component: r.component, message: r.message, details: r.details,
            requestId: r.request_id, clientRequestId: r.client_request_id, userId: r.user_id,
            accountId: r.account_id, platform: r.platform, model: r.model, host: r.host,
            apiKeyId: r.api_key_id, createdAt: r.created_at,
        }));
    }

    async cleanupSystemLogs(beforeDate: string) {
        const result = await runStatement(this.#db, "DELETE FROM ops_system_logs WHERE created_at < ?", [beforeDate]);
        return result.meta?.changes ?? 0;
    }

    async getSystemLogIngestionHealth() {
        const totalRow = await firstRow<{ cnt: number }>(this.#db, "SELECT COUNT(*) as cnt FROM ops_system_logs");
        const latestRow = await firstRow<{ created_at: string }>(this.#db, "SELECT created_at FROM ops_system_logs ORDER BY created_at DESC LIMIT 1");
        const hourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
        const errorRow = await firstRow<{ cnt: number }>(this.#db, "SELECT COUNT(*) as cnt FROM ops_system_logs WHERE level IN ('error', 'fatal') AND created_at >= ?", [hourAgo]);
        return { totalLogs: totalRow?.cnt ?? 0, latestLog: latestRow?.created_at ?? null, errorsLastHour: errorRow?.cnt ?? 0 };
    }

    async getDashboardSnapshotV2() {
        const hourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
        const recentLogs = await allRows<{ model: string; account_id: number; duration_ms: number | null }>(
            this.#db, `SELECT model, account_id, duration_ms FROM usage_logs WHERE created_at >= ? LIMIT 5000`, [hourAgo]
        );
        const recentErrors = await allRows<{ error_message: string | null }>(
            this.#db, `SELECT error_message FROM ops_error_logs WHERE created_at >= ? LIMIT 100`, [hourAgo]
        );
        const latencies = recentLogs.map((l) => l.duration_ms).filter((l): l is number => l !== null).sort((a, b) => a - b);
        const modelCounts: Record<string, number> = {};
        const accountCounts: Record<string, number> = {};
        for (const l of recentLogs) {
            modelCounts[l.model] = (modelCounts[l.model] ?? 0) + 1;
            accountCounts[String(l.account_id)] = (accountCounts[String(l.account_id)] ?? 0) + 1;
        }
        const errorCounts: Record<string, number> = {};
        for (const e of recentErrors) {
            const msg = e.error_message ?? "unknown";
            errorCounts[msg] = (errorCounts[msg] ?? 0) + 1;
        }

        const accountIds = Object.keys(accountCounts).map(Number);
        const accountNames = accountIds.length > 0 ? await this.getAccountNames(accountIds) : {};

        return {
            timestamp: new Date().toISOString(),
            qps: recentLogs.length / 3600,
            tps: latencies.reduce((a, b) => a + b, 0) / 3600,
            activeRequests: recentLogs.length,
            errorRate: recentLogs.length > 0 ? recentErrors.length / recentLogs.length : 0,
            latencyP50: latencies[Math.floor(latencies.length * 0.5)] ?? 0,
            latencyP95: latencies[Math.floor(latencies.length * 0.95)] ?? 0,
            latencyP99: latencies[Math.floor(latencies.length * 0.99)] ?? 0,
            topErrors: Object.entries(errorCounts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([error, count]) => ({ error, count })),
            topModels: Object.entries(modelCounts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([model, requests]) => ({ model, requests })),
            topAccounts: Object.entries(accountCounts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([id, requests]) => ({ account: accountNames[Number(id)] ?? `account_${id}`, requests })),
        };
    }

    async getDashboardOverview() {
        const hourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
        const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

        const hourlyRows = await allRows<any>(this.#db, `SELECT * FROM usage_dashboard_hourly WHERE bucket_start >= ?`, [dayAgo]);
        const dailyRows = await allRows<any>(this.#db, `SELECT * FROM usage_dashboard_daily WHERE bucket_date >= ?`, [dayAgo.split("T")[0]]);
        const errorRows = await allRows<{ error_type: string; cnt: number }>(
            this.#db, `SELECT error_type, COUNT(*) as cnt FROM ops_error_logs WHERE created_at >= ? GROUP BY error_type`, [dayAgo]
        );

        const totalRequests = hourlyRows.reduce((s, r) => s + r.total_requests, 0) + dailyRows.reduce((s, r) => s + r.total_requests, 0);
        const totalDuration = hourlyRows.reduce((s, r) => s + r.total_duration_ms, 0) + dailyRows.reduce((s, r) => s + r.total_duration_ms, 0);
        const totalErrors = errorRows.reduce((s, r) => s + r.cnt, 0);
        const successCount = totalRequests - totalErrors;

        const trend = hourlyRows.slice(-24).map((r) => ({ time: r.bucket_start, requests: r.total_requests }));

        return {
            totalRequests,
            successRate: totalRequests > 0 ? successCount / totalRequests : 0,
            avgLatency: totalRequests > 0 ? totalDuration / totalRequests : 0,
            errorBreakdown: Object.fromEntries(errorRows.map((r) => [r.error_type, r.cnt])),
            trafficTrend: trend,
        };
    }

    async getDashboardThroughputTrend() {
        const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        const rows = await allRows<any>(this.#db,
            `SELECT bucket_start, success_count, error_count_total, duration_p50_ms, duration_p95_ms, duration_p99_ms
             FROM ops_metrics_hourly WHERE bucket_start >= ? ORDER BY bucket_start`, [dayAgo]
        );
        const trend = rows.map((r) => ({
            time: r.bucket_start,
            qps: r.success_count / 3600,
            tps: r.success_count,
        }));
        return { trend };
    }

    async getDashboardLatencyHistogram() {
        const hourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
        const rows = await allRows<{ duration_ms: number }>(
            this.#db, `SELECT duration_ms FROM usage_logs WHERE created_at >= ? AND duration_ms IS NOT NULL`, [hourAgo]
        );
        const latencies = rows.map((r) => r.duration_ms).sort((a, b) => a - b);
        if (latencies.length === 0) return { buckets: [], percentiles: {} };

        const ranges = [0, 100, 200, 500, 1000, 2000, 5000, 10000, 30000];
        const buckets = ranges.map((min, i) => {
            const max = ranges[i + 1] ?? Number.POSITIVE_INFINITY;
            const count = latencies.filter((l) => l >= min && l < max).length;
            return { range: max === Number.POSITIVE_INFINITY ? `${min}+` : `${min}-${max}`, count };
        }).filter((b) => b.count > 0);

        return {
            buckets,
            percentiles: {
                p50: latencies[Math.floor(latencies.length * 0.5)] ?? 0,
                p75: latencies[Math.floor(latencies.length * 0.75)] ?? 0,
                p90: latencies[Math.floor(latencies.length * 0.9)] ?? 0,
                p95: latencies[Math.floor(latencies.length * 0.95)] ?? 0,
                p99: latencies[Math.floor(latencies.length * 0.99)] ?? 0,
            },
        };
    }

    async getDashboardErrorTrend() {
        const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        const rows = await allRows<{ hour: string; error_count: number }>(
            this.#db, `SELECT strftime('%Y-%m-%dT%H:00:00.000Z', created_at) as hour, COUNT(*) as error_count
                       FROM ops_error_logs WHERE created_at >= ? GROUP BY hour ORDER BY hour`, [dayAgo]
        );
        const totalLogsHourly = await allRows<{ hour: string; total: number }>(
            this.#db, `SELECT strftime('%Y-%m-%dT%H:00:00.000Z', created_at) as hour, COUNT(*) as total
                       FROM usage_logs WHERE created_at >= ? GROUP BY hour ORDER BY hour`, [dayAgo]
        );
        const totalMap = new Map(totalLogsHourly.map((r) => [r.hour, r.total]));
        const trend = rows.map((r) => ({
            time: r.hour,
            errorRate: (totalMap.get(r.hour) ?? 0) > 0 ? r.error_count / (totalMap.get(r.hour) ?? 1) : 0,
            errorCount: r.error_count,
        }));
        return { trend };
    }

    async getDashboardErrorDistribution() {
        const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        const byType = await allRows<{ key: string; cnt: number }>(
            this.#db, `SELECT error_type as key, COUNT(*) as cnt FROM ops_error_logs WHERE created_at >= ? GROUP BY error_type ORDER BY cnt DESC`, [dayAgo]
        );
        const byPhase = await allRows<{ key: string; cnt: number }>(
            this.#db, `SELECT error_phase as key, COUNT(*) as cnt FROM ops_error_logs WHERE created_at >= ? GROUP BY error_phase ORDER BY cnt DESC`, [dayAgo]
        );
        const byPlatform = await allRows<{ key: string; cnt: number }>(
            this.#db, `SELECT platform as key, COUNT(*) as cnt FROM ops_error_logs WHERE created_at >= ? AND platform IS NOT NULL AND platform != '' GROUP BY platform ORDER BY cnt DESC`, [dayAgo]
        );
        return {
            byType: Object.fromEntries(byType.map((r) => [r.key, r.cnt])),
            byPhase: Object.fromEntries(byPhase.map((r) => [r.key, r.cnt])),
            byPlatform: Object.fromEntries(byPlatform.map((r) => [r.key, r.cnt])),
        };
    }

    async getDashboardOpenAITokenStats() {
        const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        const rows = await allRows<any>(this.#db,
            `SELECT model,
                    SUM(input_tokens) as prompt_tokens, SUM(output_tokens) as completion_tokens,
                    SUM(total_cost) as cost
             FROM usage_logs WHERE created_at >= ? GROUP BY model`, [dayAgo]
        );
        const totalTokens = rows.reduce((s, r) => s + r.prompt_tokens + r.completion_tokens, 0);
        const byModel: Record<string, { prompt: number; completion: number; cost: number }> = {};
        for (const r of rows) {
            byModel[r.model] = { prompt: r.prompt_tokens ?? 0, completion: r.completion_tokens ?? 0, cost: r.cost ?? 0 };
        }
        return {
            totalTokens,
            promptTokens: rows.reduce((s, r) => s + (r.prompt_tokens ?? 0), 0),
            completionTokens: rows.reduce((s, r) => s + (r.completion_tokens ?? 0), 0),
            estimatedCost: rows.reduce((s, r) => s + (r.cost ?? 0), 0),
            byModel,
        };
    }

    private async getAccountNames(ids: number[]): Promise<Record<number, string>> {
        if (ids.length === 0) return {};
        const placeholders = ids.map(() => "?").join(",");
        const rows = await allRows<{ id: number; name: string }>(this.#db, `SELECT id, name FROM accounts WHERE id IN (${placeholders})`, ids);
        return Object.fromEntries(rows.map((r) => [r.id, r.name]));
    }

    private mapErrorLog(r: any): OpsErrorLog {
        return {
            id: r.id, requestId: r.request_id, clientRequestId: r.client_request_id, userId: r.user_id,
            apiKeyId: r.api_key_id, accountId: r.account_id, groupId: r.group_id, clientIp: r.client_ip,
            platform: r.platform, model: r.model, requestPath: r.request_path, stream: r.stream === 1,
            userAgent: r.user_agent, errorPhase: r.error_phase, errorType: r.error_type, severity: r.severity,
            statusCode: r.status_code, isBusinessLimited: r.is_business_limited === 1,
            errorMessage: r.error_message, errorBody: r.error_body, errorSource: r.error_source,
            errorOwner: r.error_owner, accountStatus: r.account_status, upstreamStatusCode: r.upstream_status_code,
            upstreamErrorMessage: r.upstream_error_message, upstreamErrorDetail: r.upstream_error_detail,
            providerErrorCode: r.provider_error_code, providerErrorType: r.provider_error_type,
            networkErrorType: r.network_error_type, retryAfterSeconds: r.retry_after_seconds,
            durationMs: r.duration_ms, timeToFirstTokenMs: r.time_to_first_token_ms,
            authLatencyMs: r.auth_latency_ms, routingLatencyMs: r.routing_latency_ms,
            upstreamLatencyMs: r.upstream_latency_ms, responseLatencyMs: r.response_latency_ms,
            createdAt: r.created_at, upstreamErrors: r.upstream_errors, isCountTokens: r.is_count_tokens === 1,
            resolved: r.resolved === 1, resolvedAt: r.resolved_at, resolvedByUserId: r.resolved_by_user_id,
            inboundEndpoint: r.inbound_endpoint, upstreamEndpoint: r.upstream_endpoint,
            requestedModel: r.requested_model, upstreamModel: r.upstream_model,
            requestType: r.request_type, attemptedKeyPrefix: r.attempted_key_prefix,
            deletedKeyOwnerUserId: r.deleted_key_owner_user_id, deletedKeyName: r.deleted_key_name,
            apiKeyPrefix: r.api_key_prefix,
        };
    }
}
