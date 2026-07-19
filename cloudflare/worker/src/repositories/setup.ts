import { firstRow } from "./d1.ts";
import type { D1Database } from "../types/d1.ts";

interface AdminPresenceRow {
    hasAdmin: number;
}

export class D1SetupRepository {
    readonly #db: D1Database;

    constructor(db: D1Database) {
        this.#db = db;
    }

    async hasAdminUser(): Promise<boolean> {
        const row = await firstRow<AdminPresenceRow>(this.#db, `
            SELECT EXISTS(
                SELECT 1
                FROM users
                WHERE role = 'admin'
                LIMIT 1
            ) AS hasAdmin
        `);

        if (row === null || (row.hasAdmin !== 0 && row.hasAdmin !== 1)) {
            throw new TypeError("D1 setup status query returned an invalid result");
        }

        return row.hasAdmin === 1;
    }
}
