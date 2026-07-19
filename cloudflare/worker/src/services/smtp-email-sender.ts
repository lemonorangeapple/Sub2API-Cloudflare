import type { Socket } from "cloudflare:sockets";
import type {
    EmailMessage,
    EmailSender,
    EmailSendResult,
    SmtpConfiguration
} from "../types/email.ts";

export interface SmtpSocketConnector {
    connect(
        address: { hostname: string; port: number },
        options: { secureTransport: "on" | "starttls"; allowHalfOpen: false }
    ): Socket;
}

interface SmtpResponse {
    code: number;
    lines: string[];
}

export class SmtpProtocolError extends Error {
    readonly retryable: boolean;

    constructor(message: string, retryable: boolean) {
        super(message);
        this.name = "SmtpProtocolError";
        this.retryable = retryable;
    }
}

export class WorkerSmtpEmailSender implements EmailSender {
    readonly #connector: SmtpSocketConnector;

    constructor(connector: SmtpSocketConnector) {
        this.#connector = connector;
    }

    async testConnection(configuration: SmtpConfiguration): Promise<void> {
        validateConfiguration(configuration);

        const implicitTls = configuration.port === 465
            || (configuration.useTls && configuration.port !== 587);
        let socket = this.#connector.connect(
            { hostname: configuration.host, port: configuration.port },
            {
                secureTransport: implicitTls ? "on" : "starttls",
                allowHalfOpen: false
            }
        );
        let session = new SmtpSession(socket);

        try {
            await expectResponse(session, [220], "SMTP greeting");
            let capabilities = await greet(session);

            if (!implicitTls) {
                if (!capabilities.some((line) => /^STARTTLS(?:\s|$)/iu.test(line))) {
                    throw new SmtpProtocolError("SMTP server does not offer STARTTLS", false);
                }
                await session.command("STARTTLS");
                await expectResponse(session, [220], "STARTTLS");
                session.releaseLocks();
                socket = socket.startTls({ expectedServerHostname: configuration.host });
                session = new SmtpSession(socket);
                capabilities = await greet(session);
            }

            if (configuration.username !== "" || configuration.password !== "") {
                if (configuration.username === "" || configuration.password === "") {
                    throw new SmtpProtocolError("SMTP username and password must both be configured", false);
                }
                const auth = base64Encode(`\0${configuration.username}\0${configuration.password}`);
                await session.command(`AUTH PLAIN ${auth}`);
                await expectResponse(session, [235], "SMTP authentication");
            }
        } finally {
            session.releaseLocks();
            await socket.close().catch(() => undefined);
        }
    }

    async send(configuration: SmtpConfiguration, message: EmailMessage): Promise<EmailSendResult> {
        validateConfiguration(configuration);
        validateEmail(message.to, "recipient email");
        validateEmail(message.from, "sender email");

        const implicitTls = configuration.port === 465
            || (configuration.useTls && configuration.port !== 587);
        let socket = this.#connector.connect(
            { hostname: configuration.host, port: configuration.port },
            {
                secureTransport: implicitTls ? "on" : "starttls",
                allowHalfOpen: false
            }
        );
        let session = new SmtpSession(socket);

        try {
            await expectResponse(session, [220], "SMTP greeting");
            let capabilities = await greet(session);

            if (!implicitTls) {
                if (!capabilities.some((line) => /^STARTTLS(?:\s|$)/iu.test(line))) {
                    throw new SmtpProtocolError("SMTP server does not offer STARTTLS", false);
                }
                await session.command("STARTTLS");
                await expectResponse(session, [220], "STARTTLS");
                session.releaseLocks();
                socket = socket.startTls({ expectedServerHostname: configuration.host });
                session = new SmtpSession(socket);
                capabilities = await greet(session);
            }

            if (configuration.username !== "" || configuration.password !== "") {
                if (configuration.username === "" || configuration.password === "") {
                    throw new SmtpProtocolError("SMTP username and password must both be configured", false);
                }
                const auth = base64Encode(`\0${configuration.username}\0${configuration.password}`);
                await session.command(`AUTH PLAIN ${auth}`);
                await expectResponse(session, [235], "SMTP authentication");
            }

            await session.command(`MAIL FROM:<${configuration.from}>`);
            await expectResponse(session, [250], "MAIL FROM");
            await session.command(`RCPT TO:<${message.to}>`);
            await expectResponse(session, [250, 251], "RCPT TO");
            await session.command("DATA");
            await expectResponse(session, [354], "DATA");

            const messageId = createMessageId(configuration.from);
            await session.writeData(serializeMessage(message, messageId));
            await expectResponse(session, [250], "message delivery");
            await session.command("QUIT");
            await expectResponse(session, [221], "QUIT");
            return { messageId };
        } finally {
            session.releaseLocks();
            await socket.close().catch(() => undefined);
        }
    }
}

class SmtpSession {
    readonly #socket: Socket;
    readonly #decoder = new TextDecoder();
    readonly #encoder = new TextEncoder();
    #reader: ReadableStreamDefaultReader<Uint8Array> | null;
    #writer: WritableStreamDefaultWriter<Uint8Array> | null;
    #buffer = "";

    constructor(socket: Socket) {
        this.#socket = socket;
        this.#reader = socket.readable.getReader();
        this.#writer = socket.writable.getWriter();
    }

    async command(value: string): Promise<void> {
        if (/\r|\n/u.test(value)) {
            throw new SmtpProtocolError("SMTP command contains a line break", false);
        }
        await this.#write(`${value}\r\n`);
    }

    async writeData(value: string): Promise<void> {
        const normalized = value.replace(/\r?\n/gu, "\r\n");
        const dotStuffed = normalized
            .split("\r\n")
            .map((line) => line.startsWith(".") ? `.${line}` : line)
            .join("\r\n");
        await this.#write(`${dotStuffed}\r\n.\r\n`);
    }

    async readResponse(): Promise<SmtpResponse> {
        const lines: string[] = [];
        let code: number | null = null;

        while (true) {
            const line = await this.#readLine();
            const match = /^(\d{3})([ -])(.*)$/u.exec(line);
            if (match === null) {
                throw new SmtpProtocolError("SMTP server returned an invalid response", true);
            }
            const lineCode = Number(match[1]);
            if (code === null) {
                code = lineCode;
            } else if (lineCode !== code) {
                throw new SmtpProtocolError("SMTP server returned inconsistent response codes", true);
            }
            lines.push(match[3]);
            if (match[2] === " ") {
                return { code, lines };
            }
        }
    }

    releaseLocks(): void {
        this.#reader?.releaseLock();
        this.#writer?.releaseLock();
        this.#reader = null;
        this.#writer = null;
    }

    async #write(value: string): Promise<void> {
        if (this.#writer === null) {
            throw new SmtpProtocolError("SMTP socket is not writable", true);
        }
        await this.#writer.write(this.#encoder.encode(value));
    }

    async #readLine(): Promise<string> {
        while (true) {
            const newline = this.#buffer.indexOf("\n");
            if (newline >= 0) {
                const line = this.#buffer.slice(0, newline).replace(/\r$/u, "");
                this.#buffer = this.#buffer.slice(newline + 1);
                return line;
            }
            if (this.#reader === null) {
                throw new SmtpProtocolError("SMTP socket is not readable", true);
            }
            const result = await this.#reader.read();
            if (result.done) {
                throw new SmtpProtocolError("SMTP server closed the connection", true);
            }
            this.#buffer += this.#decoder.decode(result.value, { stream: true });
            if (this.#buffer.length > 64 * 1024) {
                throw new SmtpProtocolError("SMTP response is too large", true);
            }
        }
    }
}

async function greet(session: SmtpSession): Promise<string[]> {
    await session.command("EHLO sub2api-worker");
    const response = await expectResponse(session, [250], "EHLO");
    return response.lines;
}

async function expectResponse(
    session: SmtpSession,
    expectedCodes: readonly number[],
    operation: string
): Promise<SmtpResponse> {
    const response = await session.readResponse();
    if (!expectedCodes.includes(response.code)) {
        const retryable = response.code >= 400 && response.code < 500;
        throw new SmtpProtocolError(`${operation} was rejected with SMTP ${response.code}`, retryable);
    }
    return response;
}

function validateConfiguration(configuration: SmtpConfiguration): void {
    if (
        configuration.host === ""
        || configuration.host.length > 253
        || /[\s/:]/u.test(configuration.host)
    ) {
        throw new SmtpProtocolError("SMTP host is invalid", false);
    }
    if (!Number.isInteger(configuration.port) || configuration.port < 1 || configuration.port > 65_535) {
        throw new SmtpProtocolError("SMTP port is invalid", false);
    }
    if (configuration.port === 25) {
        throw new SmtpProtocolError("Cloudflare Workers cannot connect to SMTP port 25", false);
    }
    validateEmail(configuration.from, "SMTP sender email");
}

function validateEmail(value: string, label: string): void {
    if (value.length === 0 || value.length > 254 || !/^[^\s<>@]+@[^\s<>@]+$/u.test(value)) {
        throw new SmtpProtocolError(`${label} is invalid`, false);
    }
}

function serializeMessage(message: EmailMessage, messageId: string): string {
    const fromName = encodeHeader(message.fromName);
    const from = fromName === "" ? message.from : `${fromName} <${message.from}>`;
    const boundary = `sub2api-${crypto.randomUUID()}`;
    return [
        `From: ${from}`,
        `To: ${message.to}`,
        `Subject: ${encodeHeader(message.subject)}`,
        `Message-ID: <${messageId}>`,
        `Date: ${new Date().toUTCString()}`,
        "MIME-Version: 1.0",
        `Content-Type: multipart/alternative; boundary="${boundary}"`,
        "",
        `--${boundary}`,
        "Content-Type: text/plain; charset=UTF-8",
        "Content-Transfer-Encoding: 8bit",
        "",
        message.text,
        `--${boundary}`,
        "Content-Type: text/html; charset=UTF-8",
        "Content-Transfer-Encoding: 8bit",
        "",
        message.html,
        `--${boundary}--`
    ].join("\r\n");
}

function encodeHeader(value: string): string {
    const sanitized = value.replace(/[\r\n]+/gu, " ").trim();
    if (sanitized === "") {
        return "";
    }
    if (/^[\x20-\x7e]+$/u.test(sanitized)) {
        return sanitized;
    }
    return `=?UTF-8?B?${base64Encode(sanitized)}?=`;
}

function createMessageId(from: string): string {
    const domain = from.slice(from.lastIndexOf("@") + 1).replace(/[^a-z0-9.-]/giu, "");
    return `${crypto.randomUUID()}@${domain || "sub2api-worker"}`;
}

function base64Encode(value: string): string {
    const bytes = new TextEncoder().encode(value);
    let binary = "";
    for (let index = 0; index < bytes.length; index += 1) {
        binary += String.fromCharCode(bytes[index]);
    }
    return btoa(binary);
}
