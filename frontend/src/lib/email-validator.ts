export interface EmailValidationResult {
    isValid: boolean;
    message: string;
    domain: string;
    isDisposable: boolean;
}

export class EmailValidator {
    private static readonly DISPOSABLE_DOMAINS = [
        'tempmail.com', '10minutemail.com', 'guerrillamail.com', 'mailinator.com',
        'yopmail.com', 'throwawaymail.com', 'fakeinbox.com', 'temp-mail.org',
        'getairmail.com', 'maildrop.cc', 'disposableemail.com'
    ];

    private static readonly SUSPICIOUS_DOMAINS = [
        'example.com', 'test.com', 'admin.com', 'user.com',
        'mail.ru', 'yandex.com', 'rambler.ru', 'list.ru'
    ];

    private static readonly TRUSTED_DOMAINS = [
        'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 
        'icloud.com', 'protonmail.com', 'live.com', 'bol.com.br',
        'uol.com.br', 'ig.com.br', 'globomail.com'
    ];

    static validate(email: string): EmailValidationResult {
        try {
            const domain = email.split('@')[1]?.toLowerCase();
            
            if (!domain) {
                return {
                    isValid: false,
                    message: "Formato de email inválido.",
                    domain: '',
                    isDisposable: false
                };
            }

            // Verificar email descartável
            if (this.DISPOSABLE_DOMAINS.includes(domain)) {
                return {
                    isValid: false,
                    message: "Emails temporários não são aceitos. Use um email permanente.",
                    domain,
                    isDisposable: true
                };
            }

            // Verificar domínio suspeito
            if (this.SUSPICIOUS_DOMAINS.includes(domain)) {
                return {
                    isValid: false,
                    message: "Domínio de email não permitido.",
                    domain,
                    isDisposable: false
                };
            }

            // Verificar se é domínio confiável
            const isTrustedDomain = this.TRUSTED_DOMAINS.includes(domain);
            
            return {
                isValid: true,
                message: isTrustedDomain ? "" : "Domínio não comum detectado.",
                domain,
                isDisposable: false
            };
            
        } catch (error) {
            // Fail open - em caso de erro, permite o email
            console.error("Erro na validação de email:", error);
            return {
                isValid: true,
                message: "",
                domain: 'unknown',
                isDisposable: false
            };
        }
    }

    static isDisposableEmail(email: string): boolean {
        const domain = email.split('@')[1]?.toLowerCase();
        return domain ? this.DISPOSABLE_DOMAINS.includes(domain) : false;
    }
}