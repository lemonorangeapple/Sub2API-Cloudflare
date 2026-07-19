const SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

interface TurnstileResponse {
    success?: boolean;
    "error-codes"?: string[];
}

export class TurnstileVerificationError extends Error {
    readonly codes: string[];

    constructor(message: string, codes: string[] = []) {
        super(message);
        this.name = "TurnstileVerificationError";
        this.codes = codes;
    }
}

export class TurnstileVerifier {
    readonly #secret: string;
    readonly #fetch: typeof fetch;

    constructor(secret: string, fetchImplementation: typeof fetch = fetch) {
        if (secret.trim().length === 0) {
            throw new RangeError("Turnstile secret is required");
        }
        this.#secret = secret;
        this.#fetch = fetchImplementation;
    }

    async verify(tokenValue: string, remoteIp?: string): Promise<void> {
        const token = tokenValue.trim();
        if (token.length === 0 || token.length > 2048) {
            throw new TurnstileVerificationError("Turnstile verification token is invalid");
        }

        let response: Response;
        try {
            response = await this.#fetch(SITEVERIFY_URL, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({
                    secret: this.#secret,
                    response: token,
                    ...(remoteIp?.trim() ? { remoteip: remoteIp.trim() } : {})
                })
            });
        } catch {
            throw new TurnstileVerificationError("Turnstile verification is temporarily unavailable");
        }

        if (!response.ok) {
            throw new TurnstileVerificationError("Turnstile verification is temporarily unavailable");
        }

        let result: TurnstileResponse;
        try {
            result = await response.json() as TurnstileResponse;
        } catch {
            throw new TurnstileVerificationError("Turnstile verification returned an invalid response");
        }
        if (result.success !== true) {
            throw new TurnstileVerificationError(
                "Turnstile verification failed",
                Array.isArray(result["error-codes"]) ? result["error-codes"] : []
            );
        }
    }
}
