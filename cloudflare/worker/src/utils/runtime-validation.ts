const MAX_IDENTIFIER_BYTES = 512;
const MAX_ERROR_BYTES = 8 * 1024;

export type Clock = () => number;
export type TokenFactory = () => string;

export function systemClock(): number {
    return Date.now();
}

export function randomToken(): string {
    return crypto.randomUUID();
}

export function currentTime(clock: Clock): number {
    const value = clock();
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new RangeError("clock must return a non-negative safe integer");
    }
    return value;
}

export function identifier(value: string, label: string, maxBytes = MAX_IDENTIFIER_BYTES): string {
    if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
        throw new TypeError(`${label} must be a non-empty string without surrounding whitespace`);
    }
    if (/[\u0000-\u001f\u007f]/u.test(value)) {
        throw new TypeError(`${label} must not contain control characters`);
    }
    if (new TextEncoder().encode(value).byteLength > maxBytes) {
        throw new RangeError(`${label} is too long`);
    }
    return value;
}

export function positiveInteger(value: number, label: string, maximum = Number.MAX_SAFE_INTEGER): number {
    if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
        throw new RangeError(`${label} must be a positive safe integer no greater than ${maximum}`);
    }
    return value;
}

export function nonNegativeInteger(value: number, label: string): number {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new RangeError(`${label} must be a non-negative safe integer`);
    }
    return value;
}

export function boundedInteger(value: number, label: string): number {
    if (!Number.isSafeInteger(value)) {
        throw new RangeError(`${label} must be a safe integer`);
    }
    return value;
}

export function boundedText(value: string, label: string, maxBytes = MAX_ERROR_BYTES): string {
    if (typeof value !== "string") {
        throw new TypeError(`${label} must be a string`);
    }
    if (new TextEncoder().encode(value).byteLength > maxBytes) {
        throw new RangeError(`${label} is too long`);
    }
    return value;
}

export function jsonText(value: unknown, label: string): string {
    const serialized = JSON.stringify(value);
    if (serialized === undefined) {
        throw new TypeError(`${label} must be JSON serializable`);
    }
    return serialized;
}

export function parseJson<T>(value: string, label: string): T {
    try {
        return JSON.parse(value) as T;
    } catch {
        throw new TypeError(`${label} contains invalid JSON`);
    }
}
