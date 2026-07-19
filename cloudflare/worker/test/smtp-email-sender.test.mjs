import assert from "node:assert/strict";
import test from "node:test";

import { WorkerSmtpEmailSender } from "../src/services/smtp-email-sender.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

class FakeSmtpSocket {
    constructor(shared, tls = false, greeting = true) {
        this.shared = shared;
        this.tls = tls;
        this.expectingData = false;
        this.readable = new ReadableStream({
            start: (controller) => {
                this.controller = controller;
                if (greeting) this.respond("220 smtp.example.com ready\r\n");
            }
        });
        this.writable = new WritableStream({
            write: (chunk) => this.handle(decoder.decode(chunk))
        });
    }

    startTls() {
        this.shared.upgrades += 1;
        return new FakeSmtpSocket(this.shared, true, false);
    }

    async close() {
        this.shared.closes += 1;
    }

    handle(value) {
        if (this.expectingData) {
            this.shared.data = value;
            this.expectingData = false;
            this.respond("250 2.0.0 queued\r\n");
            return;
        }
        const command = value.trimEnd();
        this.shared.commands.push(command);
        if (command.startsWith("EHLO ")) {
            const capabilities = this.tls
                ? "250-smtp.example.com\r\n250 AUTH PLAIN\r\n"
                : "250-smtp.example.com\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n";
            this.respond(capabilities);
        } else if (command === "STARTTLS") {
            this.respond("220 2.0.0 begin TLS\r\n");
        } else if (command.startsWith("AUTH PLAIN ")) {
            this.respond("235 2.7.0 authenticated\r\n");
        } else if (command.startsWith("MAIL FROM:")) {
            this.respond("250 2.1.0 sender accepted\r\n");
        } else if (command.startsWith("RCPT TO:")) {
            this.respond("250 2.1.5 recipient accepted\r\n");
        } else if (command === "DATA") {
            this.expectingData = true;
            this.respond("354 send message\r\n");
        } else if (command === "QUIT") {
            this.respond("221 2.0.0 bye\r\n");
        } else {
            this.respond("500 unsupported command\r\n");
        }
    }

    respond(value) {
        this.controller.enqueue(encoder.encode(value));
    }
}

function createConnector() {
    const shared = { commands: [], data: "", upgrades: 0, closes: 0, connections: [] };
    return {
        shared,
        connector: {
            connect(address, options) {
                shared.connections.push({ address, options });
                return new FakeSmtpSocket(shared, options.secureTransport === "on");
            }
        }
    };
}

function configuration(overrides = {}) {
    return {
        host: "smtp.example.com",
        port: 587,
        username: "mailer@example.com",
        password: "smtp-password",
        from: "mailer@example.com",
        fromName: "示例服务",
        useTls: false,
        ...overrides
    };
}

const message = {
    to: "user@example.com",
    from: "mailer@example.com",
    fromName: "示例服务",
    subject: "验证码",
    text: "hello\n.secret",
    html: "<p>hello</p>"
};

test("Worker SMTP sender upgrades port 587 with STARTTLS before authentication", async () => {
    const { shared, connector } = createConnector();
    const sender = new WorkerSmtpEmailSender(connector);

    const result = await sender.send(configuration({ useTls: true }), message);

    assert.match(result.messageId, /@example\.com$/u);
    assert.equal(shared.connections[0].options.secureTransport, "starttls");
    assert.equal(shared.upgrades, 1);
    assert.deepEqual(shared.commands.map((command) => command.split(" ")[0]), [
        "EHLO",
        "STARTTLS",
        "EHLO",
        "AUTH",
        "MAIL",
        "RCPT",
        "DATA",
        "QUIT"
    ]);
    assert.match(shared.data, /Subject: =\?UTF-8\?B\?/u);
    assert.match(shared.data, /\r\n\.\.secret\r\n/u);
    assert.match(shared.data, /Content-Type: multipart\/alternative/u);
});

test("Worker SMTP sender uses implicit TLS for port 465 and rejects blocked port 25", async () => {
    const { shared, connector } = createConnector();
    const sender = new WorkerSmtpEmailSender(connector);

    await sender.send(configuration({ port: 465 }), message);
    assert.equal(shared.connections[0].options.secureTransport, "on");
    assert.equal(shared.upgrades, 0);

    await assert.rejects(
        sender.send(configuration({ port: 25 }), message),
        /cannot connect to SMTP port 25/u
    );
});
