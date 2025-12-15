import { supabaseClient } from '@/lib/supabase-client';

export type AuditAction = 
    | 'login_attempt'
    | 'login_success' 
    | 'login_failed'
    | 'signup_attempt'
    | 'signup_success'
    | 'password_reset_request'
    | 'password_reset_success'
    | 'password_change'
    | 'suspicious_activity'
    | 'account_locked';

export interface AuditLogParams {
    userId?: string;
    email?: string;
    action: AuditAction;
    details?: Record<string, any>;
}

export class AuditLogger {
    private static async getClientIP(): Promise<string> {
        try {
            const response = await fetch('https://api.ipify.org?format=json');
            const data = await response.json();
            return data.ip;
        } catch {
            return 'unknown';
        }
    }

    static async log(params: AuditLogParams): Promise<void> {
        try {
            const ipAddress = await this.getClientIP();
            
            const logData = {
                user_id: params.userId || null,
                email: params.email || null,
                action: params.action,
                ip_address: ipAddress,
                user_agent: navigator.userAgent,
                details: params.details || {},
                created_at: new Date().toISOString()
            };

            const { error } = await supabaseClient()
                .from('auth_audit_logs')
                .insert(logData);

            if (error) {
                console.error('Erro ao inserir log de auditoria:', error);
            }

        } catch (error) {
            console.error('Erro no logger de auditoria:', error);
        }
    }

    // Métodos específicos para facilitar o uso
    static async logLoginAttempt(email: string, details?: Record<string, any>) {
        await this.log({
            email,
            action: 'login_attempt',
            details
        });
    }

    static async logLoginSuccess(userId: string, email: string) {
        await this.log({
            userId,
            email,
            action: 'login_success'
        });
    }

    static async logLoginFailed(email: string, errorDetails?: any) {
        await this.log({
            email,
            action: 'login_failed',
            details: { error: errorDetails }
        });
    }

    static async logSignupAttempt(email: string) {
        await this.log({
            email,
            action: 'signup_attempt'
        });
    }

    static async logSignupSuccess(userId: string, email: string) {
        await this.log({
            userId,
            email,
            action: 'signup_success'
        });
    }

    static async logPasswordResetRequest(email: string) {
        await this.log({
            email,
            action: 'password_reset_request'
        });
    }

    static async logPasswordResetSuccess(email: string) {
        await this.log({
            email,
            action: 'password_reset_success'
        });
    }

    static async logSuspiciousActivity(email: string, details: Record<string, any>) {
        await this.log({
            email,
            action: 'suspicious_activity',
            details
        });
    }
}