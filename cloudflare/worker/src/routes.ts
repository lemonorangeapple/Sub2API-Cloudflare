export const PROXY_HOP_HEADER = "x-sub2api-router-hop";

export const BACKEND_ROUTE_BOUNDARIES = [
    { family: "api", path: "/api", descendants: true },
    { family: "v1", path: "/v1", descendants: true },
    { family: "v1beta", path: "/v1beta", descendants: true },
    { family: "backend-api", path: "/backend-api", descendants: true },
    { family: "antigravity", path: "/antigravity", descendants: true },
    { family: "setup", path: "/setup", descendants: true },
    { family: "health", path: "/health", descendants: false },
    { family: "responses", path: "/responses", descendants: true },
    { family: "alpha-search", path: "/alpha/search", descendants: false },
    { family: "images", path: "/images", descendants: true },
    { family: "videos", path: "/videos", descendants: true },
    { family: "chat-completions", path: "/chat/completions", descendants: false },
    { family: "embeddings", path: "/embeddings", descendants: false }
] as const;

export type BackendRouteFamily = typeof BACKEND_ROUTE_BOUNDARIES[number]["family"];

export function classifyBackendRoute(pathname: string): BackendRouteFamily | null {
    for (const boundary of BACKEND_ROUTE_BOUNDARIES) {
        if (pathname === boundary.path) {
            return boundary.family;
        }

        if (boundary.descendants && pathname.startsWith(`${boundary.path}/`)) {
            return boundary.family;
        }
    }

    return null;
}
