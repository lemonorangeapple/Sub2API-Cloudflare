const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export function utf8(value: string): Uint8Array {
    return textEncoder.encode(value);
}

export function decodeUtf8(value: Uint8Array): string {
    return textDecoder.decode(value);
}

export async function sha256(value: string | Uint8Array): Promise<Uint8Array> {
    const input = typeof value === "string" ? utf8(value) : value;
    return new Uint8Array(await crypto.subtle.digest("SHA-256", input));
}

export async function sha256Hex(value: string | Uint8Array): Promise<string> {
    return bytesToHex(await sha256(value));
}

export function randomHex(byteLength: number): string {
    if (!Number.isInteger(byteLength) || byteLength <= 0 || byteLength > 1024) {
        throw new RangeError("random byte length must be between 1 and 1024");
    }
    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    return bytesToHex(bytes);
}

export function bytesToHex(bytes: Uint8Array): string {
    let output = "";
    for (const byte of bytes) {
        output += byte.toString(16).padStart(2, "0");
    }
    return output;
}

export function hexToBytes(value: string): Uint8Array {
    const normalized = value.trim();
    if (normalized.length === 0 || normalized.length % 2 !== 0 || !/^[a-f0-9]+$/iu.test(normalized)) {
        throw new TypeError("invalid hexadecimal value");
    }
    const output = new Uint8Array(normalized.length / 2);
    for (let index = 0; index < output.length; index += 1) {
        output[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
    }
    return output;
}

export function base64UrlEncode(value: string | Uint8Array): string {
    const bytes = typeof value === "string" ? utf8(value) : value;
    return base64Encode(bytes)
        .replaceAll("+", "-")
        .replaceAll("/", "_")
        .replace(/=+$/u, "");
}

export function base64UrlDecode(value: string): Uint8Array {
    if (!/^[A-Za-z0-9_-]*$/u.test(value)) {
        throw new TypeError("invalid base64url value");
    }
    const padded = value
        .replaceAll("-", "+")
        .replaceAll("_", "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "=");
    return base64Decode(padded);
}

export function base64Encode(bytes: Uint8Array): string {
    let binary = "";
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary);
}

export function base64Decode(value: string): Uint8Array {
    let binary: string;
    try {
        binary = atob(value);
    } catch {
        throw new TypeError("invalid base64 value");
    }
    const output = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
        output[index] = binary.charCodeAt(index);
    }
    return output;
}

export async function legacyTokenVersion(
    email: string,
    passwordHash: string,
    storedVersion = 0n
): Promise<bigint> {
    const digest = await sha256(`${email.trim().toLowerCase()}\n${passwordHash}`);
    let fingerprint = 0n;
    for (let index = 0; index < 8; index += 1) {
        fingerprint = (fingerprint << 8n) | BigInt(digest[index]);
    }
    fingerprint &= 0x7fffffffffffffffn;
    return storedVersion ^ fingerprint;
}
