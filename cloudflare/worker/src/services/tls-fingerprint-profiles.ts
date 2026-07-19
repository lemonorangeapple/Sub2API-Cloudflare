import type { D1TLSFingerprintProfileRepository, TLSFingerprintProfileRecord, CreateProfileInput, UpdateProfileInput } from "../repositories/tls-fingerprint-profiles.ts";

export class ProfileError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "ProfileError";
        this.code = code;
        this.status = status;
    }
}

const MAX_NAME_LENGTH = 100;

export class D1TLSFingerprintProfileService {
    readonly #repository: D1TLSFingerprintProfileRepository;

    constructor(repository: D1TLSFingerprintProfileRepository) {
        this.#repository = repository;
    }

    async list(): Promise<TLSFingerprintProfileRecord[]> {
        return this.#repository.list();
    }

    async getProfileById(id: number): Promise<TLSFingerprintProfileRecord> {
        const profile = await this.#repository.findById(id);
        if (profile === null) {
            throw new ProfileError("profile_not_found", 404, "Profile not found");
        }
        return profile;
    }

    async createProfile(input: {
        name: string;
        description?: string | null;
        enable_grease?: boolean;
        cipher_suites?: number[];
        curves?: number[];
        point_formats?: number[];
        signature_algorithms?: number[];
        alpn_protocols?: string[];
        supported_versions?: number[];
        key_share_groups?: number[];
        psk_modes?: number[];
        extensions?: number[];
    }): Promise<TLSFingerprintProfileRecord> {
        const name = input.name.trim();
        if (name.length === 0) {
            throw new ProfileError("name_required", 400, "Profile name is required");
        }
        if (name.length > MAX_NAME_LENGTH) {
            throw new ProfileError("name_too_long", 400, `Profile name must be at most ${MAX_NAME_LENGTH} characters`);
        }

        const existing = await this.#repository.findByName(name);
        if (existing !== null) {
            throw new ProfileError("name_taken", 409, `Profile name "${name}" already exists`);
        }

        const createInput: CreateProfileInput = {
            name,
            description: input.description ?? null,
            enableGrease: input.enable_grease ?? false,
            cipherSuites: input.cipher_suites,
            curves: input.curves,
            pointFormats: input.point_formats,
            signatureAlgorithms: input.signature_algorithms,
            alpnProtocols: input.alpn_protocols,
            supportedVersions: input.supported_versions,
            keyShareGroups: input.key_share_groups,
            pskModes: input.psk_modes,
            extensions: input.extensions
        };

        return this.#repository.create(createInput);
    }

    async updateProfile(id: number, input: {
        name?: string;
        description?: string | null;
        enable_grease?: boolean;
        cipher_suites?: number[];
        curves?: number[];
        point_formats?: number[];
        signature_algorithms?: number[];
        alpn_protocols?: string[];
        supported_versions?: number[];
        key_share_groups?: number[];
        psk_modes?: number[];
        extensions?: number[];
    }): Promise<TLSFingerprintProfileRecord> {
        if (input.name !== undefined) {
            const name = input.name.trim();
            if (name.length === 0) {
                throw new ProfileError("name_required", 400, "Profile name is required");
            }
            if (name.length > MAX_NAME_LENGTH) {
                throw new ProfileError("name_too_long", 400, `Profile name must be at most ${MAX_NAME_LENGTH} characters`);
            }

            const existing = await this.#repository.findByName(name);
            if (existing !== null && existing.id !== id) {
                throw new ProfileError("name_taken", 409, `Profile name "${name}" already exists`);
            }
        }

        const updateInput: UpdateProfileInput = {
            name: input.name?.trim(),
            description: input.description,
            enableGrease: input.enable_grease,
            cipherSuites: input.cipher_suites,
            curves: input.curves,
            pointFormats: input.point_formats,
            signatureAlgorithms: input.signature_algorithms,
            alpnProtocols: input.alpn_protocols,
            supportedVersions: input.supported_versions,
            keyShareGroups: input.key_share_groups,
            pskModes: input.psk_modes,
            extensions: input.extensions
        };

        const updated = await this.#repository.update(id, updateInput);
        if (updated === null) {
            throw new ProfileError("profile_not_found", 404, "Profile not found");
        }
        return updated;
    }

    async deleteProfile(id: number): Promise<void> {
        const deleted = await this.#repository.delete(id);
        if (!deleted) {
            throw new ProfileError("profile_not_found", 404, "Profile not found");
        }
    }
}
