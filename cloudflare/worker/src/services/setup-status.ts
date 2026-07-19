export interface SetupStatusRepository {
    hasAdminUser(): Promise<boolean>;
}

export interface SetupStatus {
    needs_setup: boolean;
    step: "welcome" | "completed";
}

export class SetupStatusService {
    readonly #repository: SetupStatusRepository;

    constructor(repository: SetupStatusRepository) {
        this.#repository = repository;
    }

    async getStatus(): Promise<SetupStatus> {
        const installed = await this.#repository.hasAdminUser();
        return {
            needs_setup: !installed,
            step: installed ? "completed" : "welcome"
        };
    }
}
