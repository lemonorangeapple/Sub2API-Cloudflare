import { D1SettingsRepository } from "../repositories/settings.ts";
import { PublicSettingsService } from "../services/public-settings.ts";
import type { D1Database } from "../types/d1.ts";
import { legacyInternalError, legacySuccess, routerError } from "./responses.ts";

export const PUBLIC_SETTINGS_PATH = "/api/v1/settings/public";

export interface PublicSettingsEnv {
    DB?: D1Database;
    APP_VERSION?: string;
    SERVER_TIMEZONE?: string;
    SERVER_UTC_OFFSET?: string;
}

export async function routePublicSettings(request: Request, env: PublicSettingsEnv): Promise<Response | null> {
    const url = new URL(request.url);
    if (url.pathname !== PUBLIC_SETTINGS_PATH) {
        return null;
    }
    if (request.method !== "GET") {
        return routerError(405, "method_not_allowed", "Public settings require GET", { allow: "GET" });
    }
    if (env.DB === undefined) {
        return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");
    }

    try {
        const service = new PublicSettingsService(
            new D1SettingsRepository(env.DB),
            {
                version: env.APP_VERSION,
                serverTimezone: env.SERVER_TIMEZONE,
                serverUTCOffset: env.SERVER_UTC_OFFSET
            }
        );
        return legacySuccess(await service.getPublicSettings());
    } catch {
        return legacyInternalError();
    }
}
