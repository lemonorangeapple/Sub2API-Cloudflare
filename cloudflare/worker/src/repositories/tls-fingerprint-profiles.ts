import type { D1Database, D1Value } from "../types/d1.ts";
import { allRows, firstRow, runStatement } from "./d1.ts";

export interface TLSFingerprintProfileRecord {
    id: number;
    createdAt: string;
    updatedAt: string;
    name: string;
    description: string | null;
    enableGrease: boolean;
    cipherSuites: number[];
    curves: number[];
    pointFormats: number[];
    signatureAlgorithms: number[];
    alpnProtocols: string[];
    supportedVersions: number[];
    keyShareGroups: number[];
    pskModes: number[];
    extensions: number[];
}

interface ProfileRow {
    id: number;
    created_at: string;
    updated_at: string;
    name: string;
    description: string | null;
    enable_grease: number;
    cipher_suites: string | null;
    curves: string | null;
    point_formats: string | null;
    signature_algorithms: string | null;
    alpn_protocols: string | null;
    supported_versions: string | null;
    key_share_groups: string | null;
    psk_modes: string | null;
    extensions: string | null;
}

function parseUint16Array(raw: string | null): number[] {
    if (!raw) return [];
    try {
        const arr = JSON.parse(raw);
        return Array.isArray(arr) ? arr.filter((n: unknown): n is number => typeof n === "number") : [];
    } catch { return []; }
}

function parseStringArray(raw: string | null): string[] {
    if (!raw) return [];
    try {
        const arr = JSON.parse(raw);
        return Array.isArray(arr) ? arr.filter((s: unknown): s is string => typeof s === "string") : [];
    } catch { return []; }
}

function rowToRecord(row: ProfileRow): TLSFingerprintProfileRecord {
    return {
        id: row.id,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        name: row.name,
        description: row.description,
        enableGrease: row.enable_grease === 1,
        cipherSuites: parseUint16Array(row.cipher_suites),
        curves: parseUint16Array(row.curves),
        pointFormats: parseUint16Array(row.point_formats),
        signatureAlgorithms: parseUint16Array(row.signature_algorithms),
        alpnProtocols: parseStringArray(row.alpn_protocols),
        supportedVersions: parseUint16Array(row.supported_versions),
        keyShareGroups: parseUint16Array(row.key_share_groups),
        pskModes: parseUint16Array(row.psk_modes),
        extensions: parseUint16Array(row.extensions)
    };
}

export interface CreateProfileInput {
    name: string;
    description?: string | null;
    enableGrease?: boolean;
    cipherSuites?: number[];
    curves?: number[];
    pointFormats?: number[];
    signatureAlgorithms?: number[];
    alpnProtocols?: string[];
    supportedVersions?: number[];
    keyShareGroups?: number[];
    pskModes?: number[];
    extensions?: number[];
}

export interface UpdateProfileInput {
    name?: string;
    description?: string | null;
    enableGrease?: boolean;
    cipherSuites?: number[];
    curves?: number[];
    pointFormats?: number[];
    signatureAlgorithms?: number[];
    alpnProtocols?: string[];
    supportedVersions?: number[];
    keyShareGroups?: number[];
    pskModes?: number[];
    extensions?: number[];
}

export class D1TLSFingerprintProfileRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async list(): Promise<TLSFingerprintProfileRecord[]> {
        const rows = await allRows<ProfileRow>(
            this.#db,
            "SELECT * FROM tls_fingerprint_profiles ORDER BY id ASC"
        );
        return rows.map(rowToRecord);
    }

    async findById(id: number): Promise<TLSFingerprintProfileRecord | null> {
        const row = await firstRow<ProfileRow>(
            this.#db,
            "SELECT * FROM tls_fingerprint_profiles WHERE id = ?",
            [id]
        );
        return row === null ? null : rowToRecord(row);
    }

    async findByName(name: string): Promise<TLSFingerprintProfileRecord | null> {
        const row = await firstRow<ProfileRow>(
            this.#db,
            "SELECT * FROM tls_fingerprint_profiles WHERE name = ?",
            [name]
        );
        return row === null ? null : rowToRecord(row);
    }

    async create(input: CreateProfileInput): Promise<TLSFingerprintProfileRecord> {
        const now = new Date().toISOString();
        const result = await runStatement(
            this.#db,
            `INSERT INTO tls_fingerprint_profiles (
                created_at, updated_at, name, description, enable_grease,
                cipher_suites, curves, point_formats, signature_algorithms,
                alpn_protocols, supported_versions, key_share_groups,
                psk_modes, extensions
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                now, now,
                input.name,
                input.description ?? null,
                input.enableGrease ? 1 : 0,
                input.cipherSuites ? JSON.stringify(input.cipherSuites) : null,
                input.curves ? JSON.stringify(input.curves) : null,
                input.pointFormats ? JSON.stringify(input.pointFormats) : null,
                input.signatureAlgorithms ? JSON.stringify(input.signatureAlgorithms) : null,
                input.alpnProtocols ? JSON.stringify(input.alpnProtocols) : null,
                input.supportedVersions ? JSON.stringify(input.supportedVersions) : null,
                input.keyShareGroups ? JSON.stringify(input.keyShareGroups) : null,
                input.pskModes ? JSON.stringify(input.pskModes) : null,
                input.extensions ? JSON.stringify(input.extensions) : null
            ]
        );
        const id = Number(result.meta?.last_row_id);
        return (await this.findById(id))!;
    }

    async update(id: number, input: UpdateProfileInput): Promise<TLSFingerprintProfileRecord | null> {
        const existing = await this.findById(id);
        if (existing === null) return null;

        const now = new Date().toISOString();
        const sets: string[] = ["updated_at = ?"];
        const values: D1Value[] = [now];

        if (input.name !== undefined) {
            sets.push("name = ?");
            values.push(input.name);
        }
        if (input.description !== undefined) {
            sets.push("description = ?");
            values.push(input.description);
        }
        if (input.enableGrease !== undefined) {
            sets.push("enable_grease = ?");
            values.push(input.enableGrease ? 1 : 0);
        }
        if (input.cipherSuites !== undefined) {
            sets.push("cipher_suites = ?");
            values.push(input.cipherSuites.length > 0 ? JSON.stringify(input.cipherSuites) : null);
        }
        if (input.curves !== undefined) {
            sets.push("curves = ?");
            values.push(input.curves.length > 0 ? JSON.stringify(input.curves) : null);
        }
        if (input.pointFormats !== undefined) {
            sets.push("point_formats = ?");
            values.push(input.pointFormats.length > 0 ? JSON.stringify(input.pointFormats) : null);
        }
        if (input.signatureAlgorithms !== undefined) {
            sets.push("signature_algorithms = ?");
            values.push(input.signatureAlgorithms.length > 0 ? JSON.stringify(input.signatureAlgorithms) : null);
        }
        if (input.alpnProtocols !== undefined) {
            sets.push("alpn_protocols = ?");
            values.push(input.alpnProtocols.length > 0 ? JSON.stringify(input.alpnProtocols) : null);
        }
        if (input.supportedVersions !== undefined) {
            sets.push("supported_versions = ?");
            values.push(input.supportedVersions.length > 0 ? JSON.stringify(input.supportedVersions) : null);
        }
        if (input.keyShareGroups !== undefined) {
            sets.push("key_share_groups = ?");
            values.push(input.keyShareGroups.length > 0 ? JSON.stringify(input.keyShareGroups) : null);
        }
        if (input.pskModes !== undefined) {
            sets.push("psk_modes = ?");
            values.push(input.pskModes.length > 0 ? JSON.stringify(input.pskModes) : null);
        }
        if (input.extensions !== undefined) {
            sets.push("extensions = ?");
            values.push(input.extensions.length > 0 ? JSON.stringify(input.extensions) : null);
        }

        if (sets.length === 1) return existing;

        values.push(id);
        await runStatement(
            this.#db,
            `UPDATE tls_fingerprint_profiles SET ${sets.join(", ")} WHERE id = ?`,
            values
        );

        return this.findById(id);
    }

    async delete(id: number): Promise<boolean> {
        const result = await runStatement(
            this.#db,
            "DELETE FROM tls_fingerprint_profiles WHERE id = ?",
            [id]
        );
        return (result.meta?.changes ?? 0) > 0;
    }
}
