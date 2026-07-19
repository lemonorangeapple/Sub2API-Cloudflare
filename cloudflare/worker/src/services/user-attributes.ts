import type { D1UserAttributeRepository, UserAttributeDefinitionRecord, UserAttributeValueRecord, CreateDefInput, UpdateDefInput, UpdateUserAttrInput } from "../repositories/user-attributes.ts";

export class UserAttributeError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status: number, message: string) {
        super(message);
        this.name = "UserAttributeError";
        this.code = code;
        this.status = status;
    }
}

const VALID_TYPES = new Set(["text", "textarea", "number", "email", "url", "date", "select", "multi_select"]);
const MAX_KEY_LENGTH = 100;
const MAX_NAME_LENGTH = 255;

export class D1UserAttributeService {
    readonly #repository: D1UserAttributeRepository;

    constructor(repository: D1UserAttributeRepository) {
        this.#repository = repository;
    }

    async listDefinitions(enabledOnly: boolean): Promise<UserAttributeDefinitionRecord[]> {
        return this.#repository.listDefinitions(enabledOnly);
    }

    async getDefinition(id: number): Promise<UserAttributeDefinitionRecord> {
        const def = await this.#repository.findDefById(id);
        if (def === null) throw new UserAttributeError("definition_not_found", 404, "Attribute definition not found");
        return def;
    }

    async createDefinition(input: {
        key: string;
        name: string;
        description?: string;
        type: string;
        options?: string;
        required?: boolean;
        validation?: string;
        placeholder?: string;
        enabled?: boolean;
    }): Promise<UserAttributeDefinitionRecord> {
        const key = input.key.trim();
        if (key.length === 0) throw new UserAttributeError("key_required", 400, "Key is required");
        if (key.length > MAX_KEY_LENGTH) throw new UserAttributeError("key_too_long", 400, `Key must be at most ${MAX_KEY_LENGTH} characters`);

        const name = input.name.trim();
        if (name.length === 0) throw new UserAttributeError("name_required", 400, "Name is required");
        if (name.length > MAX_NAME_LENGTH) throw new UserAttributeError("name_too_long", 400, `Name must be at most ${MAX_NAME_LENGTH} characters`);

        if (!VALID_TYPES.has(input.type)) {
            throw new UserAttributeError("invalid_type", 400, `Type must be one of: ${[...VALID_TYPES].join(", ")}`);
        }

        const exists = await this.#repository.existsByKey(key);
        if (exists) throw new UserAttributeError("key_taken", 409, `Key "${key}" already exists`);

        const createInput: CreateDefInput = {
            key, name,
            description: input.description,
            type: input.type,
            options: input.options ?? "[]",
            required: input.required,
            validation: input.validation ?? "{}",
            placeholder: input.placeholder,
            enabled: input.enabled
        };

        return this.#repository.createDef(createInput);
    }

    async updateDefinition(id: number, input: {
        name?: string;
        description?: string;
        type?: string;
        options?: string;
        required?: boolean;
        validation?: string;
        placeholder?: string;
        enabled?: boolean;
    }): Promise<UserAttributeDefinitionRecord> {
        if (input.name !== undefined) {
            const name = input.name.trim();
            if (name.length === 0) throw new UserAttributeError("name_required", 400, "Name is required");
            if (name.length > MAX_NAME_LENGTH) throw new UserAttributeError("name_too_long", 400, `Name must be at most ${MAX_NAME_LENGTH} characters`);
        }

        if (input.type !== undefined && !VALID_TYPES.has(input.type)) {
            throw new UserAttributeError("invalid_type", 400, `Type must be one of: ${[...VALID_TYPES].join(", ")}`);
        }

        const updateInput: UpdateDefInput = {
            name: input.name?.trim(),
            description: input.description,
            type: input.type,
            options: input.options,
            required: input.required,
            validation: input.validation,
            placeholder: input.placeholder,
            enabled: input.enabled
        };

        const updated = await this.#repository.updateDef(id, updateInput);
        if (updated === null) throw new UserAttributeError("definition_not_found", 404, "Attribute definition not found");
        return updated;
    }

    async deleteDefinition(id: number): Promise<void> {
        const existing = await this.#repository.findDefById(id);
        if (existing === null) throw new UserAttributeError("definition_not_found", 404, "Attribute definition not found");
        await this.#repository.deleteDef(id);
    }

    async reorderDefinitions(ids: number[]): Promise<void> {
        if (ids.length === 0) throw new UserAttributeError("ids_required", 400, "At least one ID is required");
        const orders = new Map<number, number>();
        for (let i = 0; i < ids.length; i++) orders.set(ids[i], i);
        await this.#repository.reorderDefs(orders);
    }

    async getUserAttributes(userId: number): Promise<UserAttributeValueRecord[]> {
        return this.#repository.getUserAttributes(userId);
    }

    async getBatchUserAttributes(userIds: number[]): Promise<Map<number, Map<number, string>>> {
        if (userIds.length === 0) return new Map();
        return this.#repository.getBatchUserAttributes(userIds);
    }

    async updateUserAttributes(userId: number, values: Record<number, string>): Promise<UserAttributeValueRecord[]> {
        const inputs: UpdateUserAttrInput[] = Object.entries(values).map(([k, v]) => ({
            attributeId: Number(k),
            value: v
        }));
        if (inputs.length === 0) throw new UserAttributeError("values_required", 400, "At least one attribute value is required");
        await this.#repository.upsertUserAttributes(userId, inputs);
        return this.#repository.getUserAttributes(userId);
    }
}
