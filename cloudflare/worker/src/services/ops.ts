import type {
    D1OpsRepository,
    OpsAlertRule, OpsAlertEvent, OpsAlertSilence,
    OpsEmailNotificationConfig, OpsRuntimeAlertSettings, OpsRuntimeLogConfig,
    OpsAdvancedSettings, OpsMetricThresholds,
    OpsDashboardSnapshotV2, OpsDashboardOverview, OpsThroughputTrend,
    OpsLatencyHistogram, OpsErrorTrend, OpsErrorDistribution, OpsOpenAITokenStats,
} from "../repositories/ops.ts";

export class OpsError extends Error {
    readonly status: number;
    readonly code: string;

    constructor(status: number, code: string, message: string) {
        super(message);
        this.name = "OpsError";
        this.status = status;
        this.code = code;
    }
}

export class D1OpsService {
    readonly #repo: D1OpsRepository;

    constructor(repo: D1OpsRepository) {
        this.#repo = repo;
    }

    async getConcurrencyStats() {
        return this.#repo.getConcurrencyStats();
    }

    async getUserConcurrencyStats() {
        return this.#repo.getUserConcurrencyStats();
    }

    async getAccountAvailability() {
        return this.#repo.getAccountAvailability();
    }

    async getRealtimeTrafficSummary() {
        return this.#repo.getRealtimeTrafficSummary();
    }

    async listAlertRules() {
        return this.#repo.listAlertRules();
    }

    async createAlertRule(rule: Omit<OpsAlertRule, "id" | "createdAt" | "updatedAt" | "lastTriggeredAt">) {
        if (!rule.name) throw new OpsError(400, "MISSING_NAME", "Alert rule name is required");
        if (!rule.metricType) throw new OpsError(400, "MISSING_METRIC_TYPE", "Metric type is required");
        if (!rule.operator) throw new OpsError(400, "MISSING_OPERATOR", "Operator is required");
        if (typeof rule.threshold !== "number") throw new OpsError(400, "MISSING_THRESHOLD", "Threshold is required");
        const normalizedRule = {
            ...rule,
            description: rule.description ?? null,
            filters: rule.filters ?? null,
            notifyEmail: rule.notifyEmail ?? false,
            windowMinutes: rule.windowMinutes ?? 5,
            sustainedMinutes: rule.sustainedMinutes ?? 5,
            cooldownMinutes: rule.cooldownMinutes ?? 10,
        };
        return this.#repo.createAlertRule(normalizedRule);
    }

    async updateAlertRule(id: number, rule: Partial<OpsAlertRule>) {
        return this.#repo.updateAlertRule(id, rule);
    }

    async deleteAlertRule(id: number) {
        return this.#repo.deleteAlertRule(id);
    }

    async listAlertEvents(filters?: { status?: string; ruleId?: number; limit?: number; offset?: number }) {
        return this.#repo.listAlertEvents(filters);
    }

    async getAlertEvent(id: number) {
        return this.#repo.getAlertEvent(id);
    }

    async updateAlertEventStatus(id: number, status: string) {
        return this.#repo.updateAlertEventStatus(id, status);
    }

    async createAlertSilence(silence: Omit<OpsAlertSilence, "id" | "createdAt">) {
        if (!silence.ruleId) throw new OpsError(400, "MISSING_RULE_ID", "Rule ID is required");
        if (!silence.until) throw new OpsError(400, "MISSING_UNTIL", "Until date is required");
        const normalizedSilence = {
            ...silence,
            platform: silence.platform ?? "",
            groupId: silence.groupId ?? null,
            region: silence.region ?? null,
            createdBy: silence.createdBy ?? 0,
        };
        return this.#repo.createAlertSilence(normalizedSilence);
    }

    async getEmailNotificationConfig() {
        return this.#repo.getEmailNotificationConfig();
    }

    async updateEmailNotificationConfig(config: OpsEmailNotificationConfig) {
        return this.#repo.updateEmailNotificationConfig(config);
    }

    async getAlertRuntimeSettings() {
        return this.#repo.getAlertRuntimeSettings();
    }

    async updateAlertRuntimeSettings(settings: OpsRuntimeAlertSettings) {
        return this.#repo.updateAlertRuntimeSettings(settings);
    }

    async getRuntimeLogConfig() {
        return this.#repo.getRuntimeLogConfig();
    }

    async updateRuntimeLogConfig(config: OpsRuntimeLogConfig) {
        return this.#repo.updateRuntimeLogConfig(config);
    }

    async resetRuntimeLogConfig() {
        return this.#repo.resetRuntimeLogConfig();
    }

    async getAdvancedSettings() {
        return this.#repo.getAdvancedSettings();
    }

    async updateAdvancedSettings(settings: OpsAdvancedSettings) {
        return this.#repo.updateAdvancedSettings(settings);
    }

    async getMetricThresholds() {
        return this.#repo.getMetricThresholds();
    }

    async updateMetricThresholds(thresholds: OpsMetricThresholds) {
        return this.#repo.updateMetricThresholds(thresholds);
    }

    async listErrorLogs(filters?: { statusCode?: number; platform?: string; userId?: number; resolved?: boolean; limit?: number; offset?: number }) {
        return this.#repo.listErrorLogs(filters);
    }

    async getErrorLog(id: number) {
        return this.#repo.getErrorLog(id);
    }

    async updateErrorResolution(id: number, resolved: boolean, userId: number) {
        return this.#repo.updateErrorResolution(id, resolved, userId);
    }

    async listRequestErrors(filters?: { statusCode?: number; platform?: string; limit?: number; offset?: number }) {
        return this.#repo.listRequestErrors(filters);
    }

    async getRequestError(id: number) {
        return this.#repo.getRequestError(id);
    }

    async listRequestErrorUpstreamErrors(requestErrorId: number) {
        return this.#repo.listRequestErrorUpstreamErrors(requestErrorId);
    }

    async resolveRequestError(id: number) {
        return this.#repo.resolveRequestError(id);
    }

    async listUpstreamErrors(filters?: { platform?: string; limit?: number; offset?: number }) {
        return this.#repo.listUpstreamErrors(filters);
    }

    async getUpstreamError(id: number) {
        return this.#repo.getUpstreamError(id);
    }

    async resolveUpstreamError(id: number) {
        return this.#repo.resolveUpstreamError(id);
    }

    async listRequestDetails(filters?: { statusCode?: number; platform?: string; userId?: number; limit?: number; offset?: number }) {
        return this.#repo.listRequestDetails(filters);
    }

    async listSystemLogs(filters?: { level?: string; component?: string; limit?: number; offset?: number }) {
        return this.#repo.listSystemLogs(filters);
    }

    async cleanupSystemLogs(beforeDate: string) {
        if (!beforeDate) throw new OpsError(400, "MISSING_DATE", "beforeDate is required");
        return this.#repo.cleanupSystemLogs(beforeDate);
    }

    async getSystemLogIngestionHealth() {
        return this.#repo.getSystemLogIngestionHealth();
    }

    async getDashboardSnapshotV2() {
        return this.#repo.getDashboardSnapshotV2();
    }

    async getDashboardOverview() {
        return this.#repo.getDashboardOverview();
    }

    async getDashboardThroughputTrend() {
        return this.#repo.getDashboardThroughputTrend();
    }

    async getDashboardLatencyHistogram() {
        return this.#repo.getDashboardLatencyHistogram();
    }

    async getDashboardErrorTrend() {
        return this.#repo.getDashboardErrorTrend();
    }

    async getDashboardErrorDistribution() {
        return this.#repo.getDashboardErrorDistribution();
    }

    async getDashboardOpenAITokenStats() {
        return this.#repo.getDashboardOpenAITokenStats();
    }
}