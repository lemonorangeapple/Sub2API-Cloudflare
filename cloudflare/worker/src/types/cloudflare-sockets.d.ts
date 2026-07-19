declare module "cloudflare:sockets" {
    export interface SocketAddress {
        hostname: string;
        port: number;
    }

    export interface SocketOptions {
        secureTransport?: "off" | "on" | "starttls";
        allowHalfOpen?: boolean;
    }

    export interface Socket {
        readonly readable: ReadableStream<Uint8Array>;
        readonly writable: WritableStream<Uint8Array>;
        startTls(options?: { expectedServerHostname?: string }): Socket;
        close(): Promise<void>;
    }

    export function connect(address: SocketAddress, options?: SocketOptions): Socket;
}
