export interface PasswordVerifier {
    verify(password: string, passwordHash: string): Promise<boolean>;
}

export interface PasswordHasher extends PasswordVerifier {
    hash(password: string): Promise<string>;
}

interface BcryptModule {
    compare(password: string, hash: string): Promise<boolean>;
    hash(password: string, rounds: number): Promise<string>;
}

export class BcryptPasswordService implements PasswordHasher {
    readonly #rounds: number;

    constructor(rounds = 10) {
        if (!Number.isInteger(rounds) || rounds < 10 || rounds > 16) {
            throw new RangeError("bcrypt rounds must be an integer between 10 and 16");
        }
        this.#rounds = rounds;
    }

    async verify(password: string, passwordHash: string): Promise<boolean> {
        if (!isSupportedBcryptHash(passwordHash) || utf8Length(password) > 72) {
            return false;
        }
        try {
            const bcrypt = await loadBcrypt();
            return await bcrypt.compare(password, passwordHash);
        } catch {
            return false;
        }
    }

    async hash(password: string): Promise<string> {
        if (password.length < 6) {
            throw new RangeError("password must be at least 6 characters");
        }
        if (utf8Length(password) > 72) {
            throw new RangeError("password must be at most 72 UTF-8 bytes for bcrypt compatibility");
        }
        const bcrypt = await loadBcrypt();
        return bcrypt.hash(password, this.#rounds);
    }
}

async function loadBcrypt(): Promise<BcryptModule> {
    const loaded = await import("bcryptjs");
    return loaded.default;
}

function isSupportedBcryptHash(value: string): boolean {
    return /^\$2[ab]\$\d{2}\$[./A-Za-z0-9]{53}$/u.test(value);
}

function utf8Length(value: string): number {
    return new TextEncoder().encode(value).byteLength;
}
