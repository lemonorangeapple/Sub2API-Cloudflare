declare module "bcryptjs" {
    interface BcryptModule {
        compare(password: string, hash: string): Promise<boolean>;
        hash(password: string, rounds: number): Promise<string>;
    }

    const bcrypt: BcryptModule;
    export default bcrypt;
}
