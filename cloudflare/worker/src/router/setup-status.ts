import { D1SetupRepository } from "../repositories/setup.ts";
import { SetupStatusService } from "../services/setup-status.ts";
import type { D1Database } from "../types/d1.ts";
import { legacyInternalError, legacySuccess, routerError } from "./responses.ts";

export const SETUP_STATUS_PATH = "/setup/status";

export interface SetupStatusEnv {
    DB?: D1Database;
}

export async function routeSetupStatus(request: Request, env: SetupStatusEnv): Promise<Response | null> {
    const url = new URL(request.url);
    if (url.pathname !== SETUP_STATUS_PATH) {
        return null;
    }
    if (request.method !== "GET") {
        return routerError(405, "method_not_allowed", "Setup status requires GET", { allow: "GET" });
    }
    if (env.DB === undefined) {
        return routerError(503, "database_not_configured", "Configure the Cloudflare D1 DB binding");
    }

    try {
        const service = new SetupStatusService(new D1SetupRepository(env.DB));
        return legacySuccess(await service.getStatus());
    } catch {
        return legacyInternalError();
    }
}
