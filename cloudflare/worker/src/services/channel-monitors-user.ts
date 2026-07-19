import type { D1ChannelMonitorRepository, ChannelMonitorRecord, ChannelMonitorHistoryRecord } from "../repositories/channel-monitors.ts";

export class ChannelMonitorsUserError extends Error {
    readonly status: number;
    readonly code: string;
    constructor(status: number, code: string, message: string) {
        super(message);
        this.status = status;
        this.code = code;
    }
}

export interface UserMonitorItem {
    id: number;
    name: string;
    provider: string;
    group_name: string;
    primary_model: string;
    primary_status: string;
    primary_latency_ms: number | null;
    primary_ping_latency_ms: number | null;
    availability_7d: number;
    extra_models: { model: string; status: string; latency_ms: number | null }[];
    timeline: { status: string; latency_ms: number | null; ping_latency_ms: number | null; checked_at: string }[];
}

export interface UserMonitorDetail {
    id: number;
    name: string;
    provider: string;
    group_name: string;
    models: {
        model: string;
        latest_status: string;
        latest_latency_ms: number | null;
        availability_7d: number;
        availability_15d: number;
        availability_30d: number;
        avg_latency_7d_ms: number | null;
    }[];
}

const TIMELINE_LIMIT = 20;

export class D1ChannelMonitorsUserService {
    readonly #repo: D1ChannelMonitorRepository;

    constructor(repo: D1ChannelMonitorRepository) {
        this.#repo = repo;
    }

    async list(): Promise<{ items: UserMonitorItem[] }> {
        const monitors = await this.#repo.listEnabledMonitors();
        const items: UserMonitorItem[] = await Promise.all(
            monitors.map((m) => this.#monitorToItem(m))
        );
        return { items };
    }

    async getDetail(id: number): Promise<UserMonitorDetail> {
        const monitor = await this.#repo.findById(id);
        if (!monitor || !monitor.enabled) {
            throw new ChannelMonitorsUserError(404, "NOT_FOUND", "Channel monitor not found");
        }
        const allModels = [monitor.primaryModel, ...monitor.extraModels];
        const models = await Promise.all(
            allModels.map((model) => this.#modelToDetail(monitor.id, model))
        );
        return {
            id: monitor.id,
            name: monitor.name,
            provider: monitor.provider,
            group_name: monitor.groupName,
            models,
        };
    }

    async #monitorToItem(m: ChannelMonitorRecord): Promise<UserMonitorItem> {
        const latest = await this.#repo.getLatestHistory(m.id, m.primaryModel);
        const avail7d = await this.#repo.getAvailability7d(m.id, m.primaryModel);
        const timelineRaw = await this.#repo.getTimeline(m.id, m.primaryModel, TIMELINE_LIMIT);

        const extraModels = await Promise.all(
            m.extraModels.map(async (model) => {
                const h = await this.#repo.getLatestHistory(m.id, model);
                return {
                    model,
                    status: h?.status ?? "unknown",
                    latency_ms: h?.latencyMs ?? null,
                };
            })
        );

        return {
            id: m.id,
            name: m.name,
            provider: m.provider,
            group_name: m.groupName,
            primary_model: m.primaryModel,
            primary_status: latest?.status ?? "unknown",
            primary_latency_ms: latest?.latencyMs ?? null,
            primary_ping_latency_ms: latest?.pingLatencyMs ?? null,
            availability_7d: avail7d,
            extra_models: extraModels,
            timeline: timelineRaw.map((h) => ({
                status: h.status,
                latency_ms: h.latencyMs,
                ping_latency_ms: h.pingLatencyMs,
                checked_at: h.checkedAt,
            })),
        };
    }

    async #modelToDetail(monitorId: number, model: string) {
        const latest = await this.#repo.getLatestHistory(monitorId, model);
        const [avail7d, avail15d, avail30d, avgLat7d] = await Promise.all([
            this.#repo.getMultiModelAvailability(monitorId, model, 7),
            this.#repo.getMultiModelAvailability(monitorId, model, 15),
            this.#repo.getMultiModelAvailability(monitorId, model, 30),
            this.#repo.getAvgLatency7d(monitorId, model),
        ]);
        return {
            model,
            latest_status: latest?.status ?? "unknown",
            latest_latency_ms: latest?.latencyMs ?? null,
            availability_7d: avail7d,
            availability_15d: avail15d,
            availability_30d: avail30d,
            avg_latency_7d_ms: avgLat7d !== null ? Math.round(avgLat7d) : null,
        };
    }
}
