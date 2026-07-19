import type { D1Database } from "../types/d1.ts";
import { D1SettingsRepository } from "../repositories/settings.ts";

export const COMPLIANCE_VERSION = "v2026.06.10";
const DOC_PATH_ZH = "docs/legal/admin-compliance.zh.md";
const DOC_PATH_EN = "docs/legal/admin-compliance.en.md";
const DOC_URL_ZH = "https://github.com/Wei-Shaw/sub2api/blob/main/docs/legal/admin-compliance.zh.md";
const DOC_URL_EN = "https://github.com/Wei-Shaw/sub2api/blob/main/docs/legal/admin-compliance.en.md";
const ACK_PHRASE_ZH = "我已阅读、理解并同意 Sub2API 部署与运营合规承诺";
const ACK_PHRASE_EN = "I have read, understood, and agree to the Sub2API Deployment and Operation Compliance Commitment";
const SETTING_KEY_PREFIX = "admin_compliance_acknowledgement";

interface ComplianceAcknowledgement {
    version: string;
    document_zh: string;
    document_en: string;
    admin_user_id: number;
    ip_address?: string;
    user_agent?: string;
    accepted_at: string;
}

export interface ComplianceStatus {
    required: boolean;
    version: string;
    document_path_zh: string;
    document_path_en: string;
    document_url_zh: string;
    document_url_en: string;
    ack_phrase_zh: string;
    ack_phrase_en: string;
    acknowledgement: ComplianceAcknowledgement | null;
}

export class AdminComplianceError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "AdminComplianceError";
        this.code = code;
        this.status = status;
    }
}

export class D1AdminComplianceService {
    readonly #db: D1Database;
    readonly #settings: D1SettingsRepository;

    constructor(db: D1Database) {
        this.#db = db;
        this.#settings = new D1SettingsRepository(db);
    }

    async getStatus(userId: number): Promise<ComplianceStatus> {
        const key = `${SETTING_KEY_PREFIX}:${userId}`;
        const values = await this.#settings.getMany([key]);
        const raw = values[key];

        let ack: ComplianceAcknowledgement | null = null;
        if (raw) {
            try {
                const parsed = JSON.parse(raw) as ComplianceAcknowledgement;
                if (parsed && typeof parsed.version === "string" && parsed.version === COMPLIANCE_VERSION) {
                    ack = parsed;
                }
            } catch { /* ignore parse errors */ }
        }

        return {
            required: ack === null,
            version: COMPLIANCE_VERSION,
            document_path_zh: DOC_PATH_ZH,
            document_path_en: DOC_PATH_EN,
            document_url_zh: DOC_URL_ZH,
            document_url_en: DOC_URL_EN,
            ack_phrase_zh: ACK_PHRASE_ZH,
            ack_phrase_en: ACK_PHRASE_EN,
            acknowledgement: ack,
        };
    }

    async isAcknowledged(userId: number): Promise<boolean> {
        const status = await this.getStatus(userId);
        return !status.required;
    }

    async accept(userId: number, phrase: string, language: string, ipAddress?: string, userAgent?: string): Promise<ComplianceStatus> {
        const lang = (language || "").trim().toLowerCase().startsWith("zh") ? "zh" : "en";
        const expectedPhrase = lang === "zh" ? ACK_PHRASE_ZH : ACK_PHRASE_EN;
        const trimmed = (phrase || "").trim();

        if (trimmed !== expectedPhrase) {
            throw new AdminComplianceError("ADMIN_COMPLIANCE_INVALID_PHRASE", 400, "confirmation phrase does not match");
        }

        const ack: ComplianceAcknowledgement = {
            version: COMPLIANCE_VERSION,
            document_zh: DOC_PATH_ZH,
            document_en: DOC_PATH_EN,
            admin_user_id: userId,
            ip_address: ipAddress,
            user_agent: userAgent,
            accepted_at: new Date().toISOString(),
        };

        const key = `${SETTING_KEY_PREFIX}:${userId}`;
        await this.#settings.upsertMany({ [key]: JSON.stringify(ack) }, new Date().toISOString());

        return this.getStatus(userId);
    }
}
