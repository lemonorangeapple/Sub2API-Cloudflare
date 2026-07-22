import { type CORSEnv, buildCORSHeaders, isOriginAllowed } from "./middleware/cors.ts";
import { routePublicSettings, type PublicSettingsEnv } from "./router/public-settings.ts";
import { jsonResponse, ROUTER_RESPONSE_HEADER, routerError } from "./router/responses.ts";
import { routeSetupStatus, type SetupStatusEnv } from "./router/setup-status.ts";
import { routeStagedAdminSettings, type StagedAdminSettingsEnv } from "./router/staged-admin-settings.ts";
import { routeStagedApiKeys, type StagedApiKeysEnv } from "./router/staged-api-keys.ts";
import { routeStagedProxies, type StagedProxiesEnv } from "./router/staged-proxies.ts";
import { routeStagedTLSFingerprintProfiles, type StagedTLSFingerprintProfilesEnv } from "./router/staged-tls-fingerprint-profiles.ts";
import { routeStagedAnnouncements, type StagedAnnouncementsEnv } from "./router/staged-announcements.ts";
import { routeStagedAnnouncementsUser, type StagedAnnouncementsUserEnv } from "./router/staged-announcements-user.ts";
import { routeStagedUserAttributes, type StagedUserAttributesEnv } from "./router/staged-user-attributes.ts";
import { routeStagedGroups, type StagedGroupsEnv } from "./router/staged-groups.ts";
import { routeStagedAccounts, type StagedAccountsEnv } from "./router/staged-accounts.ts";
import { routeStagedSubscriptions, type StagedSubscriptionsEnv } from "./router/staged-subscriptions.ts";
import { routeStagedChannels, type StagedChannelsEnv } from "./router/staged-channels.ts";
import { routeStagedChannelsUser, type StagedChannelsUserEnv } from "./router/staged-channels-user.ts";
import { routeStagedErrorPassthroughRules, type StagedErrorPassthroughRulesEnv } from "./router/staged-error-passthrough-rules.ts";
import { routeStagedScheduledTestPlans, type StagedScheduledTestPlansEnv } from "./router/staged-scheduled-test-plans.ts";
import { routeStagedAdminCompliance, isCompliancePath, type StagedAdminComplianceEnv } from "./router/staged-admin-compliance.ts";
import { routeStagedChannelMonitors, isChannelMonitorPath, type StagedChannelMonitorsEnv } from "./router/staged-channel-monitors.ts";
import { routeStagedChannelMonitorTemplates, isChannelMonitorTemplatePath, type StagedChannelMonitorTemplatesEnv } from "./router/staged-channel-monitor-templates.ts";
import { routeStagedAffiliates, isAffiliatePath, type StagedAffiliatesEnv } from "./router/staged-affiliates.ts";
import { routeStagedUsageCleanup, isUsageCleanupPath, type StagedUsageCleanupEnv } from "./router/staged-usage-cleanup.ts";
import { routeStagedUsageUser, type StagedUsageUserEnv } from "./router/staged-usage-user.ts";
import { routeStagedAdminSystem, type StagedAdminSystemEnv } from "./router/staged-admin-system.ts";
import { routeStagedRiskControl, isRiskControlPath, type StagedRiskControlEnv } from "./router/staged-risk-control.ts";
import { routeStagedChannelMonitorsUser, isChannelMonitorsUserPath, type StagedChannelMonitorsUserEnv } from "./router/staged-channel-monitors-user.ts";
import { routeStagedAdminOAuth, isAdminOAuthPath, type StagedAdminOAuthEnv } from "./router/staged-admin-oauth.ts";
import { routeStagedAdminBackups, isAdminBackupsPath, type StagedAdminBackupsEnv } from "./router/staged-admin-backups.ts";
import { routeStagedDataManagement, isDataManagementPath, type StagedDataManagementEnv } from "./router/staged-data-management.ts";
import { routeStagedAdminUserRoutes, isAdminUserRoutesPath, type StagedAdminUserRoutesEnv } from "./router/staged-admin-user-routes.ts";
import { routeStagedDashboard, isDashboardPath, type StagedDashboardEnv } from "./router/staged-dashboard.ts";
import { routeStagedOps, isOpsPath, type StagedOpsEnv } from "./router/staged-ops.ts";
import { routeStagedPromoCodes, type StagedPromoCodesEnv } from "./router/staged-promo-codes.ts";
import { routeStagedRedeemCodes, type StagedRedeemCodesEnv } from "./router/staged-redeem-codes.ts";
import { routeStagedRedeemUser, type StagedRedeemUserEnv } from "./router/staged-redeem-user.ts";
import { routeStagedAffiliatesUser, type StagedAffiliatesUserEnv } from "./router/staged-affiliates-user.ts";
import { routeStagedPaymentPlans, type StagedPaymentPlansEnv } from "./router/staged-payment-plans.ts";
import { routeStagedPaymentProviders, type StagedPaymentProvidersEnv } from "./router/staged-payment-providers.ts";
import { routeStagedPaymentOrders, type StagedPaymentOrdersEnv } from "./router/staged-payment-orders.ts";
import { routeStagedPaymentConfigDashboard, type StagedPaymentConfigDashboardEnv } from "./router/staged-payment-config-dashboard.ts";
import { routeStagedPaymentUser, type StagedPaymentUserEnv } from "./router/staged-payment-user.ts";
import { routeStagedSubscriptionsUser, type StagedSubscriptionsUserEnv } from "./router/staged-subscriptions-user.ts";
import { routeStagedAuth, type StagedAuthEnv } from "./router/staged-auth.ts";
import { routeStagedDingTalkOAuth, type StagedDingTalkOAuthEnv } from "./router/staged-dingtalk-oauth.ts";
import { routeStagedEmailOAuth, type StagedEmailOAuthEnv } from "./router/staged-email-oauth.ts";
import { routeStagedLinuxDoOAuth, type StagedLinuxDoOAuthEnv } from "./router/staged-linuxdo-oauth.ts";
import { routeStagedOIDCOAuth, type StagedOIDCOAuthEnv } from "./router/staged-oidc-oauth.ts";
import { routeStagedPendingOAuth, type StagedPendingOAuthEnv } from "./router/staged-pending-oauth.ts";
import { routeStagedSecurity, type StagedSecurityEnv } from "./router/staged-security.ts";
import {
    routeStagedUserDomain,
    type StagedUserDomainEnv
} from "./router/staged-user-domain.ts";
import { routeStagedWeChatOAuth, type StagedWeChatOAuthEnv } from "./router/staged-wechat-oauth.ts";
import { PROXY_HOP_HEADER } from "./routes.ts";
import { routeGateway } from "./router/gateway.ts";
import { routeStagedPaymentWebhook, type StagedPaymentWebhookEnv } from "./router/staged-payment-webhook.ts";
import { AuthenticationEmailTaskConsumer, type EmailConsumerResult } from "./services/email-task-consumer.ts";
import { AesGcmEmailSecretCipher } from "./services/email-task-producer.ts";
import { WorkerSmtpEmailSender, type SmtpSocketConnector } from "./services/smtp-email-sender.ts";

export interface Env extends
    CORSEnv,
    PublicSettingsEnv,
    SetupStatusEnv,
    StagedAdminSettingsEnv,
    StagedApiKeysEnv,
    StagedProxiesEnv,
    StagedTLSFingerprintProfilesEnv,
    StagedAnnouncementsEnv,
    StagedAnnouncementsUserEnv,
    StagedUserAttributesEnv,
    StagedGroupsEnv,
    StagedAccountsEnv,
    StagedSubscriptionsEnv,
    StagedRedeemCodesEnv,
    StagedRedeemUserEnv,
    StagedAffiliatesUserEnv,
    StagedPromoCodesEnv,
    StagedPaymentPlansEnv,
    StagedPaymentProvidersEnv,
    StagedPaymentOrdersEnv,
    StagedPaymentConfigDashboardEnv,
    StagedPaymentUserEnv,
    StagedSubscriptionsUserEnv,
    StagedChannelsEnv,
    StagedChannelsUserEnv,
    StagedErrorPassthroughRulesEnv,
    StagedScheduledTestPlansEnv,
    StagedAdminComplianceEnv,
    StagedChannelMonitorsEnv,
    StagedChannelMonitorTemplatesEnv,
    StagedAffiliatesEnv,
    StagedUsageCleanupEnv,
    StagedUsageUserEnv,
    StagedAdminUserRoutesEnv,
    StagedDashboardEnv,
    StagedOpsEnv,
    StagedAdminSystemEnv,
    StagedRiskControlEnv,
    StagedAdminOAuthEnv,
    StagedAdminBackupsEnv,
    StagedDataManagementEnv,
    StagedChannelMonitorsUserEnv,
    StagedAuthEnv,
    StagedSecurityEnv,
    StagedUserDomainEnv,
    StagedPendingOAuthEnv,
    StagedLinuxDoOAuthEnv,
    StagedOIDCOAuthEnv,
    StagedEmailOAuthEnv,
    StagedWeChatOAuthEnv,
    StagedDingTalkOAuthEnv
    , StagedPaymentWebhookEnv
{
    EMAIL_TASK_ENCRYPTION_KEY?: string;
    EMAIL_TASK_BATCH_SIZE?: string;
    SMTP_PASSWORD?: string;
}

export interface ScheduledController {
    scheduledTime: number;
    cron: string;
}

export interface ExecutionContextLike {
    waitUntil(promise: Promise<unknown>): void;
}

function addCORSHeaders(response: Response, request: Request, env: Env): Response {
    const origin = request.headers.get("Origin") ?? "";
    if (!isOriginAllowed(origin, env)) {
        return response;
    }
    const allowAll = env.CORS_ALLOWED_ORIGINS?.includes("*") ?? false;
    const newHeaders = new Headers(response.headers);
    const corsHeaders = buildCORSHeaders(origin, allowAll, true);
    for (const [key, value] of Object.entries(corsHeaders)) {
        newHeaders.set(key, value);
    }
    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders,
    });
}

function healthResponse(method: string): Response {
    const body = method === "HEAD" ? null : JSON.stringify({ status: "ok" });

    return new Response(body, {
        status: 200,
        headers: {
            "cache-control": "no-store",
            "content-type": "application/json; charset=utf-8",
            [ROUTER_RESPONSE_HEADER]: "sub2api-router",
            "x-content-type-options": "nosniff"
        }
    });
}

export async function routeRequest(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Handle CORS preflight (OPTIONS) early before any routing
    if (request.method === "OPTIONS") {
        const origin = request.headers.get("Origin") ?? "";
        if (isOriginAllowed(origin, env)) {
            return new Response(null, {
                status: 204,
                headers: buildCORSHeaders(origin, env.CORS_ALLOWED_ORIGINS?.includes("*") ?? false, true),
            });
        }
        // If origin not allowed or no CORS config, fall through to normal routing
    }

    if (url.pathname === "/health" && (request.method === "GET" || request.method === "HEAD")) {
        return addCORSHeaders(healthResponse(request.method), request, env);
    }

    const publicSettingsResponse = await routePublicSettings(request, env);
    if (publicSettingsResponse !== null) {
        return addCORSHeaders(publicSettingsResponse, request, env);
    }

    const setupStatusResponse = await routeSetupStatus(request, env);
    if (setupStatusResponse !== null) {
        return addCORSHeaders(setupStatusResponse, request, env);
    }

    if (request.headers.has(PROXY_HOP_HEADER)) {
        return addCORSHeaders(routerError(508, "proxy_loop_detected", "The request has already passed through this router"), request, env);
    }

    const gatewayResponse = await routeGateway(request, env);
    if (gatewayResponse !== null) return addCORSHeaders(gatewayResponse, request, env);

    const paymentWebhookResponse = await routeStagedPaymentWebhook(request, env);
    if (paymentWebhookResponse !== null) return addCORSHeaders(paymentWebhookResponse, request, env);

    // D1-native staged routes: authentication, security, user domain, OAuth providers
    const stagedResponse = await routeStagedAuth(request, env)
        ?? await routeStagedAdminUserRoutes(request, env)
        ?? await routeStagedSecurity(request, env)
        ?? await routeStagedUserDomain(request, env)
        ?? await routeStagedPendingOAuth(request, env)
        ?? await routeStagedLinuxDoOAuth(request, env)
        ?? await routeStagedOIDCOAuth(request, env)
        ?? await routeStagedEmailOAuth(request, env)
        ?? await routeStagedWeChatOAuth(request, env)
        ?? await routeStagedDingTalkOAuth(request, env)
        ?? await routeStagedAdminSettings(request, env)
        ?? await routeStagedApiKeys(request, env)
        ?? await routeStagedProxies(request, env)
        ?? await routeStagedTLSFingerprintProfiles(request, env)
        ?? await routeStagedAnnouncements(request, env)
        ?? await routeStagedUserAttributes(request, env)
        ?? await routeStagedGroups(request, env)
        ?? await routeStagedAccounts(request, env)
        ?? await routeStagedSubscriptions(request, env)
        ?? await routeStagedRedeemCodes(request, env)
         ?? await routeStagedPromoCodes(request, env)
         ?? await routeStagedPaymentPlans(request, env)
         ?? await routeStagedPaymentProviders(request, env)
         ?? await routeStagedPaymentOrders(request, env)
         ?? await routeStagedPaymentConfigDashboard(request, env)
         ?? await routeStagedPaymentUser(request, env)
         ?? await routeStagedSubscriptionsUser(request, env)
         ?? await routeStagedAnnouncementsUser(request, env)
         ?? await routeStagedRedeemUser(request, env)
         ?? await routeStagedAffiliatesUser(request, env)
         ?? await routeStagedChannelsUser(request, env)
         ?? await routeStagedChannels(request, env)
        ?? await routeStagedErrorPassthroughRules(request, env)
        ?? await routeStagedScheduledTestPlans(request, env)
        ?? await routeStagedAdminCompliance(request, env)
         ?? await routeStagedAdminOAuth(request, env)
         ?? await routeStagedAdminBackups(request, env)
         ?? await routeStagedDataManagement(request, env)
         ?? await routeStagedChannelMonitorsUser(request, env)
         ?? await routeStagedChannelMonitors(request, env)
         ?? await routeStagedChannelMonitorTemplates(request, env)
        ?? await routeStagedAffiliates(request, env)
        ?? await routeStagedUsageUser(request, env)
        ?? await routeStagedUsageCleanup(request, env)
        ?? await routeStagedDashboard(request, env)
         ?? await routeStagedAdminSystem(request, env)
         ?? await routeStagedRiskControl(request, env)
         ?? await routeStagedOps(request, env);
    if (stagedResponse !== null) {
        return addCORSHeaders(stagedResponse, request, env);
    }

    return addCORSHeaders(routerError(404, "route_not_found", "This path is not owned by the worker"), request, env);
}

export async function runScheduledEmailTasks(
    env: Env,
    scheduledTime = Date.now(),
    connector?: SmtpSocketConnector
): Promise<EmailConsumerResult> {
    if (env.DB === undefined) {
        throw new Error("scheduled email delivery requires the D1 DB binding");
    }
    if (env.EMAIL_TASK_ENCRYPTION_KEY === undefined || env.EMAIL_TASK_ENCRYPTION_KEY.trim() === "") {
        throw new Error("scheduled email delivery requires EMAIL_TASK_ENCRYPTION_KEY");
    }
    const batchSize = readBatchSize(env.EMAIL_TASK_BATCH_SIZE);
    const socketConnector = connector ?? await loadSocketConnector();
    const consumer = new AuthenticationEmailTaskConsumer(
        env.DB,
        new AesGcmEmailSecretCipher(env.EMAIL_TASK_ENCRYPTION_KEY.trim()),
        new WorkerSmtpEmailSender(socketConnector),
        {
            owner: `email-cron:${scheduledTime}:${crypto.randomUUID()}`,
            batchSize,
            smtpPassword: env.SMTP_PASSWORD
        }
    );
    return consumer.processBatch();
}

async function loadSocketConnector(): Promise<SmtpSocketConnector> {
    const sockets = await import("cloudflare:sockets");
    return { connect: sockets.connect };
}

function readBatchSize(value: string | undefined): number {
    if (value === undefined || value.trim() === "") {
        return 10;
    }
    const batchSize = Number(value);
    if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > 50) {
        throw new RangeError("EMAIL_TASK_BATCH_SIZE must be an integer between 1 and 50");
    }
    return batchSize;
}

export default {
    fetch(request: Request, env: Env): Promise<Response> {
        return routeRequest(request, env);
    },

    scheduled(controller: ScheduledController, env: Env, context: ExecutionContextLike): void {
        context.waitUntil(
            runScheduledEmailTasks(env, controller.scheduledTime)
                .then((result) => {
                    console.log("scheduled email batch completed", result);
                })
                .catch(() => {
                    console.error("scheduled email batch failed");
                })
        );
    }
};

export { jsonResponse };
