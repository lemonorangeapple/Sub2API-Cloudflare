export interface EmailMessage {
    to: string;
    from: string;
    fromName: string;
    subject: string;
    html: string;
    text: string;
}

export interface SmtpConfiguration {
    host: string;
    port: number;
    username: string;
    password: string;
    from: string;
    fromName: string;
    useTls: boolean;
}

export interface EmailSendResult {
    messageId: string;
}

export interface EmailSender {
    send(configuration: SmtpConfiguration, message: EmailMessage): Promise<EmailSendResult>;
}
