export const ROUTER_RESPONSE_HEADER = "x-sub2api-router";

function responseHeaders(extraHeaders?: HeadersInit): Headers {
    const headers = new Headers(extraHeaders);
    headers.set("cache-control", "no-store");
    headers.set("content-type", "application/json; charset=utf-8");
    headers.set(ROUTER_RESPONSE_HEADER, "sub2api-router");
    headers.set("x-content-type-options", "nosniff");
    return headers;
}

export function jsonResponse(status: number, body: unknown, extraHeaders?: HeadersInit): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: responseHeaders(extraHeaders)
    });
}

export function legacySuccess(data: unknown): Response {
    return jsonResponse(200, {
        code: 0,
        message: "success",
        data
    });
}

export function routerError(status: number, code: string, message: string, extraHeaders?: HeadersInit): Response {
    return jsonResponse(status, {
        error: {
            code,
            message
        }
    }, extraHeaders);
}

export function legacyError(
    status: number,
    message: string,
    reason = "",
    metadata?: Record<string, string>
): Response {
    return jsonResponse(status, {
        code: status,
        message,
        ...(reason ? { reason } : {}),
        ...(metadata && Object.keys(metadata).length > 0 ? { metadata } : {})
    });
}

export function middlewareAuthError(status: number, code: string, message: string): Response {
    return jsonResponse(status, { code, message });
}

export function legacyInternalError(message = "internal server error"): Response {
    return legacyError(500, message);
}
