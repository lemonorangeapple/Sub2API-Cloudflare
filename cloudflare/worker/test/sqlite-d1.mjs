import { DatabaseSync } from "node:sqlite";

class SQLiteD1PreparedStatement {
    constructor(statement, values = []) {
        this.statement = statement;
        this.values = values;
    }

    bind(...values) {
        return new SQLiteD1PreparedStatement(this.statement, values);
    }

    async first() {
        return this.statement.get(...this.values) ?? null;
    }

    async run() {
        if (this.statement.columns().length > 0) {
            const results = this.statement.all(...this.values);
            return {
                success: true,
                results,
                meta: {
                    changes: results.length,
                    rows_read: results.length,
                    rows_written: results.length
                }
            };
        }

        const result = this.statement.run(...this.values);
        return {
            success: true,
            results: [],
            meta: {
                changes: Number(result.changes),
                last_row_id: Number(result.lastInsertRowid),
                rows_read: 0,
                rows_written: Number(result.changes)
            }
        };
    }

    async all() {
        const results = this.statement.all(...this.values);
        return {
            success: true,
            results,
            meta: {
                changes: 0,
                rows_read: results.length,
                rows_written: 0
            }
        };
    }

    executeForBatch() {
        if (this.statement.columns().length > 0) {
            const results = this.statement.all(...this.values);
            return {
                success: true,
                results,
                meta: {
                    changes: results.length,
                    rows_read: results.length,
                    rows_written: results.length
                }
            };
        }

        const result = this.statement.run(...this.values);
        return {
            success: true,
            results: [],
            meta: {
                changes: Number(result.changes),
                last_row_id: Number(result.lastInsertRowid),
                rows_read: 0,
                rows_written: Number(result.changes)
            }
        };
    }
}

export class SQLiteD1Database {
    constructor() {
        this.database = new DatabaseSync(":memory:");
        this.database.exec("PRAGMA foreign_keys = ON");
    }

    prepare(query) {
        return new SQLiteD1PreparedStatement(this.database.prepare(query));
    }

    async batch(statements) {
        this.database.exec("BEGIN IMMEDIATE");
        try {
            const results = statements.map((statement) => statement.executeForBatch());
            this.database.exec("COMMIT");
            return results;
        } catch (error) {
            this.database.exec("ROLLBACK");
            throw error;
        }
    }

    exec(sql) {
        this.database.exec(sql);
    }

    close() {
        this.database.close();
    }
}
