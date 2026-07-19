export class AdminSystemError extends Error {
    readonly status: number;
    readonly code: string;

    constructor(status: number, code: string, message: string) {
        super(message);
        this.name = "AdminSystemError";
        this.status = status;
        this.code = code;
    }
}

export class D1AdminSystemService {
    readonly #version: string;

    constructor(env?: Record<string, unknown>) {
        const cfVer = typeof env?.CF_PAGES_VERSION === "string" ? env.CF_PAGES_VERSION : undefined;
        const workerVer = typeof env?.CF_WORKER_VERSION === "string" ? env.CF_WORKER_VERSION : undefined;
        this.#version = workerVer ?? cfVer ?? "1.0.0-d1";
    }

    async getVersion(): Promise<{ version: string }> {
        return { version: this.#version };
    }

    async checkUpdates(force: boolean): Promise<{
        currentVersion: string;
        latestVersion: string;
        hasUpdate: boolean;
        cached: boolean;
        buildType: string;
        warning: string;
    }> {
        try {
            const res = await fetch("https://api.github.com/repos/anomalyco/sub2api/releases/latest", {
                signal: AbortSignal.timeout(10000),
                headers: { accept: "application/json", "user-agent": "sub2api-d1" },
            });
            if (res.ok) {
                const data = await res.json() as Record<string, unknown>;
                const latest = typeof data.tag_name === "string" ? data.tag_name.replace(/^v/u, "") : this.#version;
                const hasUpdate = latest !== this.#version;
                return {
                    currentVersion: this.#version,
                    latestVersion: latest,
                    hasUpdate,
                    cached: false,
                    buildType: "d1-serverless",
                    warning: hasUpdate ? `Version ${latest} is available. Deploy via CI/CD to update.` : "You are on the latest version.",
                };
            }
        } catch {
            // Fall through to cached/default response
        }
        return {
            currentVersion: this.#version,
            latestVersion: this.#version,
            hasUpdate: false,
            cached: !force,
            buildType: "d1-serverless",
            warning: "Auto-update not available in serverless mode; deploy a new Worker version via CI/CD.",
        };
    }

    async getRollbackVersions(): Promise<{ versions: unknown[] }> {
        try {
            const res = await fetch("https://api.github.com/repos/anomalyco/sub2api/releases?per_page=10", {
                signal: AbortSignal.timeout(10000),
                headers: { accept: "application/json", "user-agent": "sub2api-d1" },
            });
            if (res.ok) {
                const data = await res.json() as Record<string, unknown>[];
                const versions = data.map((r) => ({
                    version: typeof r.tag_name === "string" ? r.tag_name.replace(/^v/u, "") : "unknown",
                    name: r.name ?? "",
                    published_at: r.published_at ?? "",
                }));
                return { versions };
            }
        } catch {
            // Fall through
        }
        return { versions: [] };
    }

    async performUpdate(): Promise<{ message: string; needRestart: boolean }> {
        return {
            message: "Update not applicable in serverless mode. Deploy a new Worker version via CI/CD.",
            needRestart: false,
        };
    }

    async rollback(version?: string): Promise<{ message: string; needRestart: boolean; version?: string }> {
        return {
            message: "Rollback not applicable in serverless mode. Deploy a previous Worker version via CI/CD.",
            needRestart: false,
            version: version ?? "previous",
        };
    }

    async restart(): Promise<{ message: string }> {
        return { message: "Restart not applicable in serverless mode. The Worker is stateless." };
    }
}
