import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const [workerEntry, wranglerConfig, coordinatorTombstone] = await Promise.all([
    readFile(new URL("../src/index.ts", import.meta.url), "utf8"),
    readFile(new URL("../wrangler.toml", import.meta.url), "utf8"),
    readFile(new URL("../src/coordinator.ts", import.meta.url), "utf8")
]);

test("Durable Object coordinator implementation and binding are removed", () => {
    assert.doesNotMatch(workerEntry, /export\s*\{\s*Coordinator/u);
    assert.doesNotMatch(wranglerConfig, /\[durable_objects\]/u);
    assert.doesNotMatch(wranglerConfig, /new_sqlite_classes/u);
    assert.doesNotMatch(coordinatorTombstone, /class\s+Coordinator/u);
    assert.match(coordinatorTombstone, /coordination now lives in D1 repositories/iu);
});
