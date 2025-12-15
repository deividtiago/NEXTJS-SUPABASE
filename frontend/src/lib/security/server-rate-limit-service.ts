// File: lib/security/server-rate-limit-service.ts
// Serviço para integrar com o rate limiting server-side

import { supabaseClient } from '@/lib/supabase-client';

export interface RateLimitResult {
    allowed: boolean;
    remainingAttempts: number;
    resetTime: string;
    blockUntil?: string;
    reason: string;
}

export class ServerRateLimitService {
    /**
     * ✅ Verificar rate limit para login
     */
    static async checkLoginRateLimit(email: string, ipAddress: string): Promise<RateLimitResult> {
        try {
            const { data, error } = await supabaseClient()
                .rpc('check_login_rate_limit', {
                    p_email: email,
                    p_ip_address: ipAddress
                });

            if (error) {
                console.error('Erro ao verificar rate limit de login:', error);
                // Fail open em caso de erro
                return {
                    allowed: true,
                    remainingAttempts: 5,
                    resetTime: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
                    reason: 'error_fallback'
                };
            }

            return data[0] as RateLimitResult;
        } catch (error) {
            console.error('Erro inesperado no rate limiting:', error);
            return {
                allowed: true,
                remainingAttempts: 5,
                resetTime: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
                reason: 'error_fallback'
            };
        }
    }

    /**
     * ✅ Verificar rate limit para password reset
     */
    static async checkPasswordResetRateLimit(email: string, ipAddress: string): Promise<RateLimitResult> {
        try {
            const { data, error } = await supabaseClient()
                .rpc('check_password_reset_rate_limit', {
                    p_email: email,
                    p_ip_address: ipAddress
                });

            if (error) {
                console.error('Erro ao verificar rate limit de password reset:', error);
                return {
                    allowed: true,
                    remainingAttempts: 3,
                    resetTime: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
                    reason: 'error_fallback'
                };
            }

            return data[0] as RateLimitResult;
        } catch (error) {
            console.error('Erro inesperado no rate limiting:', error);
            return {
                allowed: true,
                remainingAttempts: 3,
                resetTime: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
                reason: 'error_fallback'
            };
        }
    }

    /**
     * ✅ Verificar rate limit para signup
     */
    static async checkSignupRateLimit(ipAddress: string): Promise<RateLimitResult> {
        try {
            const { data, error } = await supabaseClient()
                .rpc('check_signup_rate_limit', {
                    p_ip_address: ipAddress
                });

            if (error) {
                console.error('Erro ao verificar rate limit de signup:', error);
                return {
                    allowed: true,
                    remainingAttempts: 3,
                    resetTime: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
                    reason: 'error_fallback'
                };
            }

            return data[0] as RateLimitResult;
        } catch (error) {
            console.error('Erro inesperado no rate limiting:', error);
            return {
                allowed: true,
                remainingAttempts: 3,
                resetTime: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
                reason: 'error_fallback'
            };
        }
    }

    /**
     * ✅ Obter mensagem amigável para o usuário
     */
    static getFriendlyMessage(rateLimitResult: RateLimitResult): string {
        if (rateLimitResult.allowed) {
            return '';
        }

        if (rateLimitResult.blockUntil) {
            const blockUntil = new Date(rateLimitResult.blockUntil);
            const now = new Date();
            const minutesLeft = Math.ceil((blockUntil.getTime() - now.getTime()) / (1000 * 60));
            
            return `🔒 Muitas tentativas. Tente novamente em ${minutesLeft} minutos.`;
        }

        if (rateLimitResult.reason === 'rate_limit_exceeded') {
            const resetTime = new Date(rateLimitResult.resetTime);
            const now = new Date();
            const minutesLeft = Math.ceil((resetTime.getTime() - now.getTime()) / (1000 * 60));
            
            return `⏰ Limite de tentativas atingido. Aguarde ${minutesLeft} minutos.`;
        }

        return 'Muitas tentativas recentes. Aguarde alguns minutos.';
    }
}