import type { D1Database, D1PreparedStatement, D1Result, D1Value } from "../types/d1.ts";

export interface D1BatchStatement {
    sql: string;
    values?: readonly D1Value[];
}

export class D1OperationError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "D1OperationError";
    }
}

export function prepareStatement(
    db: D1Database,
    sql: string,
    values: readonly D1Value[] = []
): D1PreparedStatement {
    const statement = db.prepare(sql);
    return values.length === 0 ? statement : statement.bind(...values);
}

export async function firstRow<T>(
    db: D1Database,
    sql: string,
    values: readonly D1Value[] = []
): Promise<T | null> {
    return prepareStatement(db, sql, values).first<T>();
}

export async function allRows<T>(
    db: D1Database,
    sql: string,
    values: readonly D1Value[] = []
): Promise<T[]> {
    const result = await prepareStatement(db, sql, values).all<T>();
    requireSuccess(result, "D1 query failed");
    return result.results ?? [];
}

export async function runStatement<T = Record<string, unknown>>(
    db: D1Database,
    sql: string,
    values: readonly D1Value[] = []
): Promise<D1Result<T>> {
    const result = await prepareStatement(db, sql, values).run<T>();
    requireSuccess(result, "D1 statement failed");
    return result;
}

export async function runBatchTransaction(
    db: D1Database,
    statements: readonly D1BatchStatement[]
): Promise<D1Result[]> {
    if (statements.length === 0) {
        return [];
    }

    const results = await db.batch(statements.map((statement) => (
        prepareStatement(db, statement.sql, statement.values)
    )));

    results.forEach((result, index) => {
        requireSuccess(result, `D1 batch statement ${index + 1} failed`);
    });
    return results;
}

export function requireSuccess(result: D1Result<unknown>, fallback: string): void {
    if (!result.success) {
        throw new D1OperationError(result.error || fallback);
    }
}
