// lib/security/suspicious-activity-detector.ts
import { supabaseClient } from '@/lib/supabase-client';

export interface SuspiciousActivityResult {
    isSuspicious: boolean;
    riskLevel: 'low' | 'medium' | 'high';
    reason?: string;
    details: Record<string, any>;
    recommendedAction: 'allow' | 'delay' | 'block';
}

export class SuspiciousActivityDetector {
    private static readonly RATE_LIMITS = {
        ip: { maxAttempts: 10, windowMinutes: 5 },
        email: { maxFailedAttempts: 5, windowMinutes: 60 },
        signups: { maxSignups: 20, windowMinutes: 60 },
        fingerprint: { maxAttempts: 15, windowMinutes: 10 }
    };

    /**
     * ✅ MÉTODO PRINCIPAL - atualizado para lidar com fingerprints
     */
    static async detect(
        email: string, 
        action: string,
        currentIp: string
    ): Promise<SuspiciousActivityResult> {
        try {
            // ✅ Detectar se é fingerprint ou IP real
            const isFingerprint = currentIp.startsWith('fp-');
            
            const checks = await Promise.all([
                this.checkIPRateLimit(currentIp, action, isFingerprint),
                this.checkEmailRateLimit(email, action),
                this.checkMultipleIPs(email, action),
                this.checkSignupPatterns(email, action)
            ]);

            const suspiciousChecks = checks.filter(check => check.isSuspicious);
            
            if (suspiciousChecks.length === 0) {
                return {
                    isSuspicious: false,
                    riskLevel: 'low',
                    details: { ipType: isFingerprint ? 'fingerprint' : 'real' },
                    recommendedAction: 'allow'
                };
            }

            const riskLevel = this.calculateRiskLevel(suspiciousChecks, isFingerprint);
            const recommendedAction = this.getRecommendedAction(riskLevel);

            return {
                isSuspicious: true,
                riskLevel,
                reason: suspiciousChecks.map(check => check.reason).join(', '),
                details: {
                    ...Object.assign({}, ...suspiciousChecks.map(check => check.details)),
                    ipType: isFingerprint ? 'fingerprint' : 'real'
                },
                recommendedAction
            };

        } catch (error) {
            console.error('Erro na detecção de atividade suspeita:', error);
            
            // ✅ Fail secure: em caso de erro crítico, permite mas loga
            return {
                isSuspicious: false,
                riskLevel: 'low',
                details: { error: 'detection_failed', errorDetails: String(error) },
                recommendedAction: 'allow'
            };
        }
    }

    /**
     * ✅ NOVO: Verifica rate limit específico para password reset
     * DEVE SER CHAMADO ANTES de enviar o email
     */
    static async checkPasswordResetRateLimit(
        email: string,
        currentIp: string
    ): Promise<{
        allowed: boolean;
        reason?: string;
        waitSeconds?: number;
    }> {
        try {
            const timeWindow = new Date(Date.now() - 60 * 60 * 1000); // 1 hora

            // ✅ Buscar tentativas de reset deste IP na última hora
            const { data: ipAttempts, error: ipError } = await supabaseClient()
                .from('auth_audit_logs')
                .select('created_at')
                .eq('ip_address', currentIp)
                .eq('action', 'password_reset_request')
                .gte('created_at', timeWindow.toISOString());

            if (ipError) {
                console.error('Erro ao verificar rate limit de IP:', ipError);
                return { allowed: true };
            }

            // ✅ LIMITE: 3 tentativas por hora por IP
            if (ipAttempts && ipAttempts.length >= 3) {
                const oldestAttempt = new Date(ipAttempts[0].created_at);
                const waitTime = Math.ceil((60 * 60 * 1000 - (Date.now() - oldestAttempt.getTime())) / 1000);
                
                return {
                    allowed: false,
                    reason: 'ip_rate_limit_exceeded',
                    waitSeconds: waitTime
                };
            }

            // ✅ Verificar também por email (prevenir spam para mesmo email)
            const emailTimeWindow = new Date(Date.now() - 15 * 60 * 1000); // 15 minutos
            const { data: emailAttempts, error: emailError } = await supabaseClient()
                .from('auth_audit_logs')
                .select('created_at')
                .eq('email', email)
                .eq('action', 'password_reset_request')
                .gte('created_at', emailTimeWindow.toISOString());

            if (!emailError && emailAttempts && emailAttempts.length >= 2) {
                const oldestAttempt = new Date(emailAttempts[0].created_at);
                const waitTime = Math.ceil((15 * 60 * 1000 - (Date.now() - oldestAttempt.getTime())) / 1000);
                
                return {
                    allowed: false,
                    reason: 'email_rate_limit_exceeded',
                    waitSeconds: waitTime
                };
            }

            return { allowed: true };

        } catch (error) {
            console.error('Erro no rate limiting de password reset:', error);
            // ✅ Fail open
            return { allowed: true };
        }
    }

    /**
     * ✅ ATUALIZADO: Rate limit por IP ou fingerprint
     */
    private static async checkIPRateLimit(
        identifier: string, 
        action: string,
        isFingerprint: boolean
    ) {
        // ✅ Usar limites diferentes para fingerprints (mais permissivo)
        const limits = isFingerprint 
            ? this.RATE_LIMITS.fingerprint 
            : this.RATE_LIMITS.ip;
        
        const { maxAttempts, windowMinutes } = limits;
        const timeWindow = new Date(Date.now() - windowMinutes * 60 * 1000);

        const { data: attempts, error } = await supabaseClient()
            .from('auth_audit_logs')
            .select('action, created_at')
            .eq('ip_address', identifier)
            .gte('created_at', timeWindow.toISOString())
            .in('action', ['login_attempt', 'login_failed', 'signup_attempt']);

        if (error) {
            console.error('Erro ao verificar rate limit:', error);
            return { isSuspicious: false, details: {} };
        }

        const isSuspicious = attempts && attempts.length >= maxAttempts;

        return {
            isSuspicious,
            reason: isSuspicious 
                ? (isFingerprint ? 'too_many_attempts_from_browser' : 'too_many_attempts_from_ip')
                : undefined,
            details: isSuspicious ? { 
                attempts: attempts.length, 
                limit: maxAttempts,
                timeframe: `${windowMinutes} minutes`,
                identifierType: isFingerprint ? 'fingerprint' : 'ip'
            } : {}
        };
    }

    /**
     * ✅ Rate limit por email (não mudou)
     */
    private static async checkEmailRateLimit(email: string, action: string) {
        const { maxFailedAttempts, windowMinutes } = this.RATE_LIMITS.email;
        const timeWindow = new Date(Date.now() - windowMinutes * 60 * 1000);

        const { data: attempts, error } = await supabaseClient()
            .from('auth_audit_logs')
            .select('action, created_at')
            .eq('email', email)
            .gte('created_at', timeWindow.toISOString())
            .in('action', ['login_attempt', 'login_failed']);

        if (error || !attempts) {
            return { isSuspicious: false, details: {} };
        }

        const failedAttempts = attempts.filter(a => a.action === 'login_failed');
        const isSuspicious = failedAttempts.length >= maxFailedAttempts;

        return {
            isSuspicious,
            reason: isSuspicious ? 'too_many_failed_attempts' : undefined,
            details: isSuspicious ? {
                failedAttempts: failedAttempts.length,
                limit: maxFailedAttempts,
                timeframe: `${windowMinutes} minutes`
            } : {}
        };
    }

    /**
     * ✅ ATUALIZADO: Detecta múltiplos IPs/fingerprints para mesma conta
     */
    private static async checkMultipleIPs(email: string, action: string) {
        const timeWindow = new Date(Date.now() - 60 * 60 * 1000); // 1 hora

        const { data: attempts, error } = await supabaseClient()
            .from('auth_audit_logs')
            .select('ip_address, created_at')
            .eq('email', email)
            .gte('created_at', timeWindow.toISOString())
            .in('action', ['login_attempt', 'login_failed']);

        if (error || !attempts) {
            return { isSuspicious: false, details: {} };
        }

        const uniqueIdentifiers = new Set(attempts.map(a => a.ip_address));
        
        // ✅ Separar IPs reais de fingerprints
        const realIPs = Array.from(uniqueIdentifiers).filter(id => !id.startsWith('fp-'));
        const fingerprints = Array.from(uniqueIdentifiers).filter(id => id.startsWith('fp-'));
        
        // ✅ Suspeito se: 3+ IPs reais OU 5+ fingerprints diferentes
        const isSuspicious = realIPs.length >= 3 || fingerprints.length >= 5;

        return {
            isSuspicious,
            reason: isSuspicious ? 'multiple_identifiers_for_same_account' : undefined,
            details: isSuspicious ? {
                uniqueRealIPs: realIPs.length,
                uniqueFingerprints: fingerprints.length,
                timeframe: '1 hour'
            } : {}
        };
    }

    /**
     * ✅ Padrões suspeitos de signup (não mudou)
     */
    private static async checkSignupPatterns(email: string, action: string) {
        if (action !== 'signup_attempt') {
            return { isSuspicious: false, details: {} };
        }

        const { maxSignups, windowMinutes } = this.RATE_LIMITS.signups;
        const timeWindow = new Date(Date.now() - windowMinutes * 60 * 1000);

        const { data: signups, error } = await supabaseClient()
            .from('auth_audit_logs')
            .select('email, created_at')
            .eq('action', 'signup_attempt')
            .gte('created_at', timeWindow.toISOString());

        const isSuspicious = !error && signups && signups.length >= maxSignups;

        return {
            isSuspicious,
            reason: isSuspicious ? 'too_many_signups' : undefined,
            details: isSuspicious ? {
                signups: signups.length,
                limit: maxSignups,
                timeframe: `${windowMinutes} minutes`
            } : {}
        };
    }

    /**
     * ✅ ATUALIZADO: Cálculo de risco considera fingerprints
     */
    private static calculateRiskLevel(
        checks: Array<{isSuspicious: boolean; details: any}>,
        isFingerprint: boolean
    ): 'low' | 'medium' | 'high' {
        const highRiskIndicators = [
            'too_many_attempts_from_ip', 
            'multiple_identifiers_for_same_account'
        ];
        
        const mediumRiskIndicators = [
            'too_many_failed_attempts', 
            'too_many_signups',
            'too_many_attempts_from_browser'
        ];

        // ✅ Se é fingerprint, reduzir risco em um nível
        const hasHighRisk = checks.some(check => 
            highRiskIndicators.some(indicator => check.details[indicator])
        );
        
        const hasMediumRisk = checks.some(check =>
            mediumRiskIndicators.some(indicator => check.details[indicator])
        );

        if (hasHighRisk) {
            return isFingerprint ? 'medium' : 'high';
        }

        if (hasMediumRisk) {
            return isFingerprint ? 'low' : 'medium';
        }

        return 'low';
    }

    /**
     * ✅ Ação recomendada baseada no risco
     */
    private static getRecommendedAction(
        riskLevel: 'low' | 'medium' | 'high'
    ): 'allow' | 'delay' | 'block' {
        switch (riskLevel) {
            case 'high':
                return 'block';
            case 'medium':
                return 'delay';
            case 'low':
            default:
                return 'allow';
        }
    }
}