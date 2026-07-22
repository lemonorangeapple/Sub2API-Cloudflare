export interface CORSEnv {
    CORS_ALLOWED_ORIGINS?: string;
}

const DEFAULT_ALLOW_HEADERS = [
    "Content-Type",
    "Content-Length",
    "Accept-Encoding",
    "Authorization",
    "X-CSRF-Token",
    "X-API-Key",
    "X-Admin-UI-Request",
    "X-User-UI-Request",
    "Accept-Language",
    "accept",
    "origin",
    "Cache-Control",
    "X-Requested-With",
];

const OPENAI_STAINLESS_HEADERS = [
    "lang",
    "package-version",
    "os",
    "arch",
    "retry-count",
    "runtime",
    "runtime-version",
    "async",
    "helper-method",
    "poll-helper",
    "custom-poll-interval",
    "timeout",
];

function buildAllowHeadersValue(): string {
    const headers = [...DEFAULT_ALLOW_HEADERS];
    for (const prop of OPENAI_STAINLESS_HEADERS) {
        headers.push(`x-stainless-${prop}`);
    }
    return headers.join(", ");
}

function normalizeOrigins(raw: string): string[] {
    return raw
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
}

let allowHeadersValue: string | undefined;

function getAllowHeadersValue(): string {
    if (allowHeadersValue === undefined) {
        allowHeadersValue = buildAllowHeadersValue();
    }
    return allowHeadersValue;
}

/**
 * Handle CORS for incoming requests.
 * Returns a Response for OPTIONS preflight or null if the request should continue.
 */
export function handleCORS(request: Request, env: CORSEnv): Response | null {
    const configuredOrigins = env.CORS_ALLOWED_ORIGINS;
    if (!configuredOrigins || configuredOrigins.trim() === "") {
        return null;
    }

    const origins = normalizeOrigins(configuredOrigins);
    if (origins.length === 0) {
        return null;
    }

    const allowAll = origins.includes("*");
    const origin = request.headers.get("Origin") ?? "";
    let originAllowed = allowAll;

    if (!allowAll && origin !== "") {
        originAllowed = origins.includes(origin);
    }

    // Handle OPTIONS preflight
    if (request.method === "OPTIONS") {
        if (originAllowed) {
            return new Response(null, {
                status: 204,
                headers: buildCORSHeaders(origin, allowAll, true),
            });
        }
        return new Response(null, { status: 403 });
    }

    // Non-preflight: return null if origin not allowed (no CORS headers added)
    if (!originAllowed) {
        return null;
    }

    // For actual requests, we need to add CORS headers to the response.
    // Since we can't modify the response after it's created, we return a marker
    // and the caller wraps the response with CORS headers.
    return null;
}

/**
 * Build CORS response headers.
 */
export function buildCORSHeaders(
    origin: string,
    allowAll: boolean,
    allowCredentials: boolean
): HeadersInit {
    const headers = new Headers();

    if (allowAll) {
        headers.set("Access-Control-Allow-Origin", "*");
    } else if (origin !== "") {
        headers.set("Access-Control-Allow-Origin", origin);
        headers.set("Vary", "Origin");
    }

    // Wildcard + credentials are incompatible per spec
    if (allowAll) {
        allowCredentials = false;
    }
    if (allowCredentials) {
        headers.set("Access-Control-Allow-Credentials", "true");
    }

    headers.set("Access-Control-Allow-Headers", getAllowHeadersValue());
    headers.set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH");
    headers.set("Access-Control-Expose-Headers", "ETag, Server-Timing");
    headers.set("Access-Control-Max-Age", "86400");

    return headers;
}

/**
 * Check if the given origin is allowed by CORS config.
 */
export function isOriginAllowed(origin: string, env: CORSEnv): boolean {
    const configuredOrigins = env.CORS_ALLOWED_ORIGINS;
    if (!configuredOrigins || configuredOrigins.trim() === "") {
        return false;
    }

    const origins = normalizeOrigins(configuredOrigins);
    if (origins.length === 0) {
        return false;
    }

    if (origins.includes("*")) {
        return true;
    }

    return origins.includes(origin);
}
