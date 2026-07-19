import assert from "node:assert/strict";
import test from "node:test";

import {
    BACKEND_ROUTE_BOUNDARIES,
    classifyBackendRoute
} from "../src/routes.ts";

test("classifies every backend route boundary and descendant family", () => {
    for (const boundary of BACKEND_ROUTE_BOUNDARIES) {
        assert.equal(classifyBackendRoute(boundary.path), boundary.family);

        const child = `${boundary.path}/child`;
        assert.equal(
            classifyBackendRoute(child),
            boundary.descendants ? boundary.family : null,
            child
        );
    }
});

test("matches complete path segments instead of lookalike prefixes", () => {
    const frontendPaths = [
        "/",
        "/index.html",
        "/dashboard",
        "/apiary",
        "/v10/models",
        "/v1beta2/models",
        "/backend-apiary/status",
        "/antigravityx/models",
        "/setup-wizard",
        "/healthy",
        "/responsesx",
        "/alpha/search/results",
        "/images2/generations",
        "/videos2/generations",
        "/chat/completions/batch",
        "/embeddings/batch"
    ];

    for (const path of frontendPaths) {
        assert.equal(classifyBackendRoute(path), null, path);
    }
});

test("keeps route matching case-sensitive", () => {
    assert.equal(classifyBackendRoute("/API/v1/users"), null);
    assert.equal(classifyBackendRoute("/Health"), null);
});

