import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { D1AuthEmailRepository } from "../src/repositories/auth-email.ts";
import { D1TaskQueueRepository } from "../src/repositories/task-queue.ts";
import { AuthenticationEmailTaskConsumer } from "../src/services/email-task-consumer.ts";
import {
    AesGcmEmailSecretCipher,
    AuthenticationEmailTaskProducer
} from "../src/services/email-task-producer.ts";
import { SQLiteD1Database } from "./sqlite-d1.mjs";

const migrations = await Promise.all([
    "0001_ent_core.sql",
    "0004_runtime_state.sql"
].map((name) => readFile(new URL(`../../d1/migrations/${name}`, import.meta.url), "utf8")));

const FIXED_NOW = Date.parse("2026-07-15T12:00:00.000Z");
const EMAIL_KEY = "22".repeat(32);
const RESET_TOKEN = "ab".repeat(32);
const SMTP_PASSWORD = "smtp-password-must-not-be-persisted";

function createDatabase() {
    const db = new SQLiteD1Database();
    for (const migration of migrations) db.exec(migration);
    return db;
}

async function configureSmtp(db) {
    const values = {
        smtp_host: "smtp.example.com",
        smtp_port: "587",
        smtp_username: "mailer@example.com",
        smtp_password: SMTP_PASSWORD,
        smtp_from_email: "mailer@example.com",
        smtp_from_name: "Sub2API",
        smtp_use_tls: "false"
    };
    for (const [key, value] of Object.entries(values)) {
        await db.prepare(`
            INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        `).bind(key, value, new Date(FIXED_NOW).toISOString()).run();
    }
}

function createProducer(db, cipher, clock) {
    return new AuthenticationEmailTaskProducer(
        new D1AuthEmailRepository(db),
        cipher,
        {
            clock,
            verificationCodeFactory: () => "123456",
            resetTokenFactory: () => RESET_TOKEN
        }
    );
}

function createSender(send) {
    return { send };
}

test("consumer delivers verification and reset emails once without persisting plaintext secrets", async () => {
    const db = createDatabase();
    await configureSmtp(db);
    let now = FIXED_NOW;
    const cipher = new AesGcmEmailSecretCipher(EMAIL_KEY);
    const producer = createProducer(db, cipher, () => now);
    const verification = await producer.enqueueVerification("user@example.com", "Sub2API");
    const reset = await producer.enqueuePasswordReset(
        "user@example.com",
        "Sub2API",
        "https://app.example.com/reset-password"
    );
    const deliveries = [];
    const sender = createSender(async (configuration, message) => {
        deliveries.push({ configuration, message });
        return { messageId: `message-${deliveries.length}` };
    });
    const consumer = new AuthenticationEmailTaskConsumer(db, cipher, sender, {
        clock: () => now,
        tokenFactory: () => `claim-${crypto.randomUUID()}`,
        owner: "email-consumer-test",
        batchSize: 10
    });

    assert.deepEqual(await consumer.processBatch(), {
        claimed: 2,
        sent: 2,
        skipped: 0,
        retried: 0,
        failed: 0
    });
    assert.equal(deliveries.length, 2);
    assert.equal(deliveries.some(({ message }) => message.html.includes("123456")), true);
    assert.equal(deliveries.some(({ message }) => message.html.includes(RESET_TOKEN)), true);
    assert.equal(deliveries[0].configuration.password, SMTP_PASSWORD);

    const tasks = new D1TaskQueueRepository(db, { clock: () => now });
    for (const taskId of [verification.taskId, reset.taskId]) {
        const task = await tasks.get(taskId);
        assert.equal(task.status, "completed");
        const persisted = JSON.stringify({
            payload: task.payload,
            result: task.result,
            error: task.lastError
        });
        assert.doesNotMatch(persisted, /123456/u);
        assert.doesNotMatch(persisted, new RegExp(RESET_TOKEN, "u"));
        assert.doesNotMatch(persisted, new RegExp(SMTP_PASSWORD, "u"));
    }

    assert.deepEqual(await consumer.processBatch(), {
        claimed: 0,
        sent: 0,
        skipped: 0,
        retried: 0,
        failed: 0
    });
    assert.equal(deliveries.length, 2);
    db.close();
});

test("consumer completes an expired-state task without sending", async () => {
    const db = createDatabase();
    await configureSmtp(db);
    let now = FIXED_NOW;
    const cipher = new AesGcmEmailSecretCipher(EMAIL_KEY);
    const producer = createProducer(db, cipher, () => now);
    const created = await producer.enqueueVerification("expired@example.com", "Sub2API");
    now += 16 * 60 * 1000;
    let sendCount = 0;
    const consumer = new AuthenticationEmailTaskConsumer(
        db,
        cipher,
        createSender(async () => {
            sendCount += 1;
            return { messageId: "unexpected" };
        }),
        { clock: () => now, owner: "expired-email-test" }
    );

    assert.deepEqual(await consumer.processBatch(), {
        claimed: 1,
        sent: 0,
        skipped: 1,
        retried: 0,
        failed: 0
    });
    assert.equal(sendCount, 0);
    const task = await new D1TaskQueueRepository(db, { clock: () => now }).get(created.taskId);
    assert.equal(task.status, "completed");
    assert.deepEqual(task.result, { outcome: "state_expired" });
    db.close();
});

test("consumer retries transient SMTP failure with backoff and then completes", async () => {
    const db = createDatabase();
    await configureSmtp(db);
    let now = FIXED_NOW;
    const cipher = new AesGcmEmailSecretCipher(EMAIL_KEY);
    const created = await createProducer(db, cipher, () => now)
        .enqueueVerification("retry@example.com", "Sub2API");
    let attempts = 0;
    const sender = createSender(async () => {
        attempts += 1;
        if (attempts === 1) {
            throw new Error(`provider failure must not echo 123456 or ${SMTP_PASSWORD}`);
        }
        return { messageId: "retry-success" };
    });
    const first = new AuthenticationEmailTaskConsumer(db, cipher, sender, {
        clock: () => now,
        owner: "retry-email-test-1"
    });

    assert.deepEqual(await first.processBatch(), {
        claimed: 1,
        sent: 0,
        skipped: 0,
        retried: 1,
        failed: 0
    });
    let task = await new D1TaskQueueRepository(db, { clock: () => now }).get(created.taskId);
    assert.equal(task.status, "pending");
    assert.equal(task.availableAt, now + 30_000);
    assert.equal(task.lastError, "SMTP delivery failed");

    now += 30_000;
    const second = new AuthenticationEmailTaskConsumer(db, cipher, sender, {
        clock: () => now,
        owner: "retry-email-test-2"
    });
    assert.deepEqual(await second.processBatch(), {
        claimed: 1,
        sent: 1,
        skipped: 0,
        retried: 0,
        failed: 0
    });
    task = await new D1TaskQueueRepository(db, { clock: () => now }).get(created.taskId);
    assert.equal(task.status, "completed");
    assert.equal(task.attempts, 2);
    assert.doesNotMatch(JSON.stringify(task), /123456/u);
    assert.doesNotMatch(JSON.stringify(task), new RegExp(SMTP_PASSWORD, "u"));
    db.close();
});
