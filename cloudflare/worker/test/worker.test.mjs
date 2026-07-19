import assert from "node:assert/strict";
import test from "node:test";

import { routeRequest } from "../src/index.ts";
import { PROXY_HOP_HEADER } from "../src/routes.ts";

test("GET and HEAD /health are served at the edge", async () => {
    const getResponse = await routeRequest(new Request("https://edge.example/health"), {});
    assert.equal(getResponse.status, 200);
    assert.deepEqual(await getResponse.json(), { status: "ok" });
    assert.equal(getResponse.headers.get("cache-control"), "no-store");
    assert.equal(getResponse.headers.get("x-sub2api-router"), "sub2api-router");

    const headResponse = await routeRequest(new Request("https://edge.example/health", {
        method: "HEAD"
    }), {});
    assert.equal(headResponse.status, 200);
    assert.equal(await headResponse.text(), "");
});

test("non-backend paths return 404 without touching the backend binding", async () => {
    let backendCalled = false;
    const response = await routeRequest(new Request("https://edge.example/dashboard"), {
        BACKEND: {
            async fetch() {
                backendCalled = true;
                return new Response("unexpected");
            }
        }
    });

    assert.equal(response.status, 404);
    assert.equal(backendCalled, false);
    assert.equal((await response.json()).error.code, "route_not_found");
});

test("loop markers are rejected before any downstream handling", async () => {
    let backendCalled = false;
    const response = await routeRequest(new Request("https://edge.example/v1/models", {
        headers: { [PROXY_HOP_HEADER]: "1" }
    }), {
        // no downstream binding required
    });

    assert.equal(response.status, 508);
    assert.equal(backendCalled, false);
});

test("an unowned route fails locally", async () => {
    const response = await routeRequest(new Request("https://edge.example/not-owned"), {});
    assert.equal(response.status, 404);
    assert.equal((await response.json()).error.code, "route_not_found");
});
