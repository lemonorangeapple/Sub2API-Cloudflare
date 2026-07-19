export type D1Value = null | string | number | boolean | ArrayBuffer;

export interface D1ResultMeta {
    changes?: number;
    last_row_id?: number;
    rows_read?: number;
    rows_written?: number;
}

export interface D1Result<T = Record<string, unknown>> {
    success: boolean;
    results?: T[];
    error?: string;
    meta?: D1ResultMeta;
}

export interface D1PreparedStatement {
    bind(...values: D1Value[]): D1PreparedStatement;
    first<T = Record<string, unknown>>(): Promise<T | null>;
    run<T = Record<string, unknown>>(): Promise<D1Result<T>>;
    all<T = Record<string, unknown>>(): Promise<D1Result<T>>;
}

export interface D1Database {
    prepare(query: string): D1PreparedStatement;
    batch<T = Record<string, unknown>>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]>;
}
