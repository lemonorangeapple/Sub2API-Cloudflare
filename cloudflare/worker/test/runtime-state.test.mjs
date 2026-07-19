import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { runBatchTransaction } from "../src/repositories/d1.ts";
import { D1ExpiringStateRepository } from "../src/repositories/expiring-state.ts";
import { D1CoordinationRepository } from "../src/repositories/runtime-coordination.ts";
import {
    D1TaskQueueRepository,
    TaskIdempotencyConflictError
} from "../src/repositories/task-queue.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrationUrl = new URL("../../d1/migrations/0004_runtime_state.sql", import.meta.url);
const migrationSql = await readFile(migrationUrl, "utf8");

function createFixture(start = 1_000) {
    const db = new SQLiteD1Database();
    db.exec(migrationSql);
    let now = start;
    let token = 0;
    const options = {
        clock: () => now,
        tokenFactory: () => `token-${++token}`
    };
    return {
        db,
        coordination: new D1CoordinationRepository(db, options),
        expiring: new D1ExpiringStateRepository(db, options),
        tasks: new D1TaskQueueRepository(db, options),
        advance(milliseconds) {
            now += milliseconds;
        },
        now() {
            return now;
        }
    };
}

test("D1 batch helper rolls back the full sequence after a constraint failure", async () => {
    const fixture = createFixture();
    await assert.rejects(() => runBatchTransaction(fixture.db, [
        {
            sql: `INSERT INTO runtime_expiring_values
                (state_key, value_json, expires_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)`,
            values: ["valid", "{}", 2_000, 1_000, 1_000]
        },
        {
            sql: `INSERT INTO runtime_expiring_values
                (state_key, value_json, expires_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)`,
            values: ["invalid", "not-json", 2_000, 1_000, 1_000]
        }
    ]));

    const row = await fixture.db.prepare(
        "SELECT COUNT(*) AS count FROM runtime_expiring_values"
    ).first();
    assert.equal(row.count, 0);
    fixture.db.close();
});

test("D1 leases are exclusive, replay-safe, renewable, releasable, and reusable after expiry", async () => {
    const fixture = createFixture();

    assert.deepEqual(await fixture.coordination.acquireLease({
        key: "billing:user:1",
        owner: "worker-a",
        ttlMs: 500
    }), {
        acquired: true,
        replayed: false,
        expiresAt: 1_500,
        fencingToken: 1
    });

    assert.deepEqual(await fixture.coordination.acquireLease({
        key: "billing:user:1",
        owner: "worker-a",
        ttlMs: 900
    }), {
        acquired: true,
        replayed: true,
        expiresAt: 1_500,
        fencingToken: 1
    });

    assert.deepEqual(await fixture.coordination.acquireLease({
        key: "billing:user:1",
        owner: "worker-b",
        ttlMs: 500
    }), {
        acquired: false,
        replayed: false,
        expiresAt: 1_500,
        fencingToken: 1
    });

    fixture.advance(100);
    assert.deepEqual(await fixture.coordination.renewLease({
        key: "billing:user:1",
        owner: "worker-a",
        ttlMs: 800,
        fencingToken: 1
    }), {
        renewed: true,
        expiresAt: 1_900,
        fencingToken: 1
    });
    assert.equal(await fixture.coordination.releaseLease("billing:user:1", "worker-a", 2), false);
    assert.equal(await fixture.coordination.releaseLease("billing:user:1", "worker-b", 1), false);
    assert.equal(await fixture.coordination.releaseLease("billing:user:1", "worker-a", 1), true);

    assert.equal((await fixture.coordination.acquireLease({
        key: "billing:user:1",
        owner: "worker-b",
        ttlMs: 200
    })).acquired, true);
    fixture.advance(201);
    const replacement = await fixture.coordination.acquireLease({
        key: "billing:user:1",
        owner: "worker-c",
        ttlMs: 300
    });
    assert.equal(replacement.acquired, true);
    assert.equal(replacement.replayed, false);
    assert.equal(replacement.fencingToken, 2);
    fixture.db.close();
});

test("D1 fixed windows enforce limits and reset at the next window", async () => {
    const fixture = createFixture(1_100);

    assert.deepEqual(await fixture.coordination.consumeFixedWindow({
        key: "rpm:key-1",
        limit: 3,
        windowMs: 1_000,
        amount: 2
    }), {
        allowed: true,
        count: 2,
        remaining: 1,
        resetAt: 2_000
    });

    assert.deepEqual(await fixture.coordination.consumeFixedWindow({
        key: "rpm:key-1",
        limit: 3,
        windowMs: 1_000,
        amount: 2
    }), {
        allowed: false,
        count: 2,
        remaining: 1,
        resetAt: 2_000
    });

    fixture.advance(900);
    assert.deepEqual(await fixture.coordination.consumeFixedWindow({
        key: "rpm:key-1",
        limit: 3,
        windowMs: 1_000
    }), {
        allowed: true,
        count: 1,
        remaining: 2,
        resetAt: 3_000
    });
    fixture.db.close();
});

test("D1 reservations preserve idempotency until expiration", async () => {
    const fixture = createFixture();
    const first = await fixture.coordination.reserve({
        key: "payment:order-1",
        reservationId: "request-a",
        ttlMs: 500
    });
    assert.deepEqual(first, { reserved: true, replayed: false, expiresAt: 1_500 });
    assert.deepEqual(await fixture.coordination.reserve({
        key: "payment:order-1",
        reservationId: "request-a",
        ttlMs: 900
    }), { reserved: true, replayed: true, expiresAt: 1_500 });
    assert.equal((await fixture.coordination.reserve({
        key: "payment:order-1",
        reservationId: "request-b",
        ttlMs: 500
    })).reserved, false);

    fixture.advance(501);
    assert.deepEqual(await fixture.coordination.reserve({
        key: "payment:order-1",
        reservationId: "request-b",
        ttlMs: 300
    }), { reserved: true, replayed: false, expiresAt: 1_801 });
    fixture.db.close();
});

test("D1 expiring state supports compare-and-swap, atomic take, expiry, and cleanup", async () => {
    const fixture = createFixture();
    await fixture.expiring.put("oauth:state-1", { verifier: "abc", attempts: 0 }, 100);
    assert.deepEqual(await fixture.expiring.get("oauth:state-1"), {
        value: { verifier: "abc", attempts: 0 },
        expiresAt: 1_100
    });
    assert.equal(await fixture.expiring.compareAndSwap(
        "oauth:state-1",
        { verifier: "stale", attempts: 0 },
        { verifier: "abc", attempts: 1 }
    ), false);
    assert.equal(await fixture.expiring.compareAndSwap(
        "oauth:state-1",
        { verifier: "abc", attempts: 0 },
        { verifier: "abc", attempts: 1 }
    ), true);
    assert.deepEqual(await fixture.expiring.take("oauth:state-1"), {
        value: { verifier: "abc", attempts: 1 },
        expiresAt: 1_100
    });
    assert.equal(await fixture.expiring.take("oauth:state-1"), null);

    await fixture.expiring.put("oauth:state-2", { verifier: "expired" }, 100);
    fixture.advance(100);
    assert.equal(await fixture.expiring.get("oauth:state-2"), null);
    assert.equal(await fixture.expiring.purgeExpired(), 1);
    fixture.db.close();
});

test("D1 task claims are ordered, idempotent, token-guarded, and retry-aware", async () => {
    const fixture = createFixture();

    const low = await fixture.tasks.enqueue({
        queueName: "email",
        idempotencyKey: "welcome:1",
        payload: { template: "welcome" },
        priority: 1,
        maxAttempts: 2
    });
    const replay = await fixture.tasks.enqueue({
        queueName: "email",
        idempotencyKey: "welcome:1",
        payload: { template: "welcome" },
        priority: 1,
        maxAttempts: 2
    });
    assert.equal(replay.replayed, true);
    assert.equal(replay.task.id, low.task.id);
    assert.deepEqual(replay.task.payload, { template: "welcome" });
    await assert.rejects(() => fixture.tasks.enqueue({
        queueName: "email",
        idempotencyKey: "welcome:1",
        payload: { template: "different" },
        priority: 1,
        maxAttempts: 2
    }), TaskIdempotencyConflictError);

    const high = await fixture.tasks.enqueue({
        queueName: "email",
        payload: { template: "urgent" },
        priority: 10,
        maxAttempts: 1
    });

    const claimedHigh = await fixture.tasks.claimNext({
        queueName: "email",
        owner: "cron-1",
        ttlMs: 100
    });
    assert.equal(claimedHigh.id, high.task.id);
    assert.equal(claimedHigh.attempts, 1);
    assert.equal(await fixture.tasks.complete({
        taskId: claimedHigh.id,
        owner: "cron-1",
        claimToken: "wrong-token",
        result: { sent: true }
    }), false);
    assert.equal(await fixture.tasks.complete({
        taskId: claimedHigh.id,
        owner: "cron-1",
        claimToken: claimedHigh.claimToken,
        result: { sent: true }
    }), true);

    const claimedLow = await fixture.tasks.claimNext({
        queueName: "email",
        owner: "cron-1",
        ttlMs: 100
    });
    assert.equal(claimedLow.id, low.task.id);
    assert.equal(await fixture.tasks.fail({
        taskId: claimedLow.id,
        owner: "cron-1",
        claimToken: claimedLow.claimToken,
        error: "temporary",
        retryDelayMs: 50
    }), "pending");
    assert.equal(await fixture.tasks.claimNext({
        queueName: "email",
        owner: "cron-1",
        ttlMs: 100
    }), null);

    fixture.advance(50);
    const retry = await fixture.tasks.claimNext({
        queueName: "email",
        owner: "cron-2",
        ttlMs: 100
    });
    assert.equal(retry.id, low.task.id);
    assert.equal(retry.attempts, 2);
    assert.equal(await fixture.tasks.fail({
        taskId: retry.id,
        owner: "cron-2",
        claimToken: retry.claimToken,
        error: "permanent"
    }), "failed");

    const stored = await fixture.tasks.get(low.task.id);
    assert.equal(stored.status, "failed");
    assert.equal(stored.lastError, "permanent");
    fixture.db.close();
});

test("an expired final task attempt becomes failed instead of remaining stuck", async () => {
    const fixture = createFixture();
    const queued = await fixture.tasks.enqueue({
        queueName: "single-attempt",
        payload: { job: 1 },
        maxAttempts: 1
    });
    const claimed = await fixture.tasks.claimNext({
        queueName: "single-attempt",
        owner: "worker-a",
        ttlMs: 100
    });
    assert.equal(claimed.id, queued.task.id);

    fixture.advance(101);
    assert.equal(await fixture.tasks.claimNext({
        queueName: "single-attempt",
        owner: "worker-b",
        ttlMs: 100
    }), null);
    const stored = await fixture.tasks.get(queued.task.id);
    assert.equal(stored.status, "failed");
    assert.equal(stored.lastError, "claim expired after maximum attempts");
    fixture.db.close();
});

test("expired task claims can be reclaimed by another Worker invocation", async () => {
    const fixture = createFixture();
    const queued = await fixture.tasks.enqueue({
        queueName: "usage",
        payload: { batch: 1 },
        maxAttempts: 2
    });
    const first = await fixture.tasks.claimNext({
        queueName: "usage",
        owner: "worker-a",
        ttlMs: 100
    });
    assert.equal(first.id, queued.task.id);

    fixture.advance(101);
    const replacement = await fixture.tasks.claimNext({
        queueName: "usage",
        owner: "worker-b",
        ttlMs: 100
    });
    assert.equal(replacement.id, queued.task.id);
    assert.equal(replacement.attempts, 2);
    assert.notEqual(replacement.claimToken, first.claimToken);
    fixture.db.close();
});
