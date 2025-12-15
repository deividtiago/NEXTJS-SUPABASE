// app/auth/page.tsx
'use client'
import { supabaseClient } from "@/lib/supabase-client";
import { ChangeEvent, FormEvent, useState, useEffect } from "react"
import { useRouter } from 'next/navigation'

// Importações de segurança
import { EmailValidator } from '@/lib/email-validator';
import { SuspiciousActivityDetector } from '@/lib/security/suspicious-activity-detector';
import { AuditLogger } from '@/lib/security/audit-logger';
import { PasswordStrengthChecker } from '@/lib/security/password-strength-checker';
import { PASSWORD_REQUIREMENTS, AUTH_MESSAGES, SIGNUP_MESSAGES } from '@/lib/security/password-requirements';
import { getClientIP } from '@/lib/security/ip-detection';
import { ServerRateLimitService } from '@/lib/security/server-rate-limit-service';

// Interfaces
interface AuthState {
  email: string;
  password: string;
  confirmPassword: string;
  message: string;
  loading: boolean;
  showPassword: boolean;
  showConfirmPassword: boolean;
  isSignUp: boolean;
  isForgotPassword: boolean;
  honeypot: string;
}

export default function Auth() {
    const supabase = supabaseClient();
    const router = useRouter();
    
    const [state, setState] = useState<AuthState>({
        email: "",
        password: "",
        confirmPassword: "",
        message: "",
        loading: false,
        showPassword: false,
        showConfirmPassword: false,
        isSignUp: false,
        isForgotPassword: false,
        honeypot: ""
    });

    // ✅ ESTADOS DE RATE LIMIT SERVER-SIDE
    const [serverRateLimit, setServerRateLimit] = useState<{
        login?: any;
        reset?: any;
        signup?: any;
    }>({});

    const updateState = (updates: Partial<AuthState>) => {
        setState(prev => ({ ...prev, ...updates }));
    };

    const resetAuthState = (options: { preserveEmail?: boolean } = {}) => {
        const baseReset = {
            message: "",
            password: "",
            confirmPassword: "",
            honeypot: "",
            showPassword: false,
            showConfirmPassword: false,
            loading: false
        };
        
        if (options.preserveEmail) {
            updateState(baseReset);
        } else {
            updateState({ ...baseReset, email: "" });
        }
    };

    // ✅ FUNÇÕES DE RATE LIMIT SERVER-SIDE
    const checkResetRateLimit = async (): Promise<{ allowed: boolean; message?: string }> => {
        try {
            const currentIp = await getClientIP();
            const rateLimitResult = await ServerRateLimitService.checkPasswordResetRateLimit(
                state.email, 
                currentIp
            );

            if (!rateLimitResult.allowed) {
                const message = ServerRateLimitService.getFriendlyMessage(rateLimitResult);
                return { allowed: false, message };
            }

            return { allowed: true };
        } catch (error) {
            console.error('Erro no rate limiting:', error);
            // Fail open em caso de erro
            return { allowed: true };
        }
    };

    const checkLoginRateLimit = async (): Promise<{ allowed: boolean; message?: string; locked?: boolean }> => {
        try {
            const currentIp = await getClientIP();
            const rateLimitResult = await ServerRateLimitService.checkLoginRateLimit(
                state.email, 
                currentIp
            );

            if (!rateLimitResult.allowed) {
                const message = ServerRateLimitService.getFriendlyMessage(rateLimitResult);
                const isLocked = !!rateLimitResult.blockUntil;
                return { 
                    allowed: false, 
                    message,
                    locked: isLocked
                };
            }

            return { allowed: true };
        } catch (error) {
            console.error('Erro no rate limiting:', error);
            return { allowed: true };
        }
    };

    const checkSignupRateLimit = async (): Promise<{ allowed: boolean; message?: string }> => {
        try {
            const currentIp = await getClientIP();
            const rateLimitResult = await ServerRateLimitService.checkSignupRateLimit(currentIp);

            if (!rateLimitResult.allowed) {
                const message = ServerRateLimitService.getFriendlyMessage(rateLimitResult);
                return { allowed: false, message };
            }

            return { allowed: true };
        } catch (error) {
            console.error('Erro no rate limiting:', error);
            return { allowed: true };
        }
    };

    // ✅ FUNÇÃO MELHORADA: Verificar signups recentes
    const checkRecentSignups = async (email: string): Promise<{ blocked: boolean; waitTime?: number }> => {
        try {
            const { data: attempts, error } = await supabase
                .from('auth_audit_logs')
                .select('created_at')
                .eq('email', email)
                .eq('action', 'signup_attempt')
                .gte('created_at', new Date(Date.now() - 60 * 60 * 1000).toISOString())
                .order('created_at', { ascending: true });

            if (error || !attempts) {
                return { blocked: false };
            }

            if (attempts.length >= 3) {
                const oldest = new Date(attempts[0].created_at);
                const waitTime = Math.ceil((60 - (Date.now() - oldest.getTime()) / (60 * 1000)));
                
                return { blocked: true, waitTime: Math.max(1, waitTime) };
            }
            
            return { blocked: false };
        } catch (error) {
            console.error('Erro ao verificar signups recentes:', error);
            return { blocked: false };
        }
    };

    // ✅ FUNÇÃO CORRIGIDA: handleForgotPassword com Rate Limit SERVER-SIDE
    const handleForgotPassword = async (e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        
        // ✅ VERIFICAR RATE LIMIT SERVER-SIDE
        const rateLimitCheck = await checkResetRateLimit();
        if (!rateLimitCheck.allowed) {
            updateState({ 
                message: rateLimitCheck.message || "Aguarde antes de solicitar outro email.",
                loading: false 
            });
            return;
        }

        updateState({ loading: true, message: "" });

        try {
            const { email, honeypot } = state;
            
            // ✅ 1. Honeypot check
            if (honeypot.trim() !== '') {
                await new Promise(resolve => setTimeout(resolve, 2000));
                updateState({ 
                    message: "Se o email existir em nosso sistema, enviaremos instruções de recuperação.",
                    loading: false 
                });
                return;
            }

            // ✅ 2. Email validation
            const emailValidation = EmailValidator.validate(email);
            
            if (!emailValidation.isValid) {
                updateState({ 
                    message: "Email inválido. Verifique e tente novamente.",
                    loading: false 
                });
                return;
            }

            // ✅ 3. Obter IP para log
            const currentIp = await getClientIP();
            
            // ✅ 4. CHAMAR SUPABASE
            const { data, error } = await supabase.auth.resetPasswordForEmail(email, {
                redirectTo: `${window.location.origin}/auth/reset-password`
            });

            // ✅ 5. LOGAR a tentativa
            supabase.from('auth_audit_logs').insert({
                email,
                action: error ? 'password_reset_failed' : 'password_reset_request',
                ip_address: currentIp,
                user_agent: navigator.userAgent,
                details: {
                    success: !error,
                    error_message: error?.message,
                    brevo_smtp: true,
                    timestamp: new Date().toISOString()
                }
            }).catch(console.error);

            // ✅ 6. Tratar erros específicos
            if (error) {
                if (error.message?.includes('rate limit')) {
                    updateState({ 
                        message: "Muitas solicitações recentes. Aguarde 1 hora antes de tentar novamente.",
                        loading: false 
                    });
                    return;
                }
            }

            // ✅ 7. MENSAGEM DE SUCESSO
            updateState({ 
                message: `✅ Email enviado! Verifique sua caixa de entrada (e spam).`,
                loading: false 
            });

            // Limpar formulário após 8 segundos
            setTimeout(() => {
                updateState({ 
                    isForgotPassword: false,
                    email: '',
                    message: "" 
                });
            }, 8000);

        } catch (error) {
            console.error('❌ ERRO INESPERADO:', error);
            
            updateState({ 
                message: AUTH_MESSAGES.genericError,
                loading: false 
            });
        }
    };

    const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        
        // ✅ VERIFICAR RATE LIMIT SERVER-SIDE PARA LOGIN/SIGNUP
        let rateLimitCheck;
        if (!state.isSignUp) {
            rateLimitCheck = await checkLoginRateLimit();
            if (!rateLimitCheck.allowed) {
                updateState({ 
                    message: rateLimitCheck.message || AUTH_MESSAGES.rateLimitExceeded,
                    loading: false 
                });
                return;
            }
        } else {
            rateLimitCheck = await checkSignupRateLimit();
            if (!rateLimitCheck.allowed) {
                updateState({ 
                    message: rateLimitCheck.message || "Muitas tentativas de cadastro recentes.",
                    loading: false 
                });
                return;
            }
        }

        updateState({ loading: true, message: "" });

        try {
            const { email, password, confirmPassword, isSignUp, honeypot } = state;

            // ✅ 1. Validações básicas
            if (!email || !password) {
                updateState({ 
                    message: "Preencha email e senha.",
                    loading: false 
                });
                return;
            }

            // ✅ 2. Honeypot
            if (honeypot.trim() !== '') {
                await new Promise(resolve => setTimeout(resolve, 2000));
                updateState({ 
                    message: isSignUp ? "Processando cadastro..." : AUTH_MESSAGES.invalidCredentials,
                    loading: false 
                });
                return;
            }

            // ✅ 3. Email validation
            const emailValidation = EmailValidator.validate(email);
            if (!emailValidation.isValid) {
                updateState({ 
                    message: isSignUp ? emailValidation.message : AUTH_MESSAGES.invalidCredentials,
                    loading: false 
                });
                return;
            }

            // ✅ 4. Validações específicas para SIGNUP
            if (isSignUp) {
                const recentSignups = await checkRecentSignups(email);
                if (recentSignups.blocked) {
                    updateState({ 
                        message: `Muitas tentativas recentes. Aguarde ${recentSignups.waitTime} minutos antes de tentar novamente.`,
                        loading: false 
                    });
                    return;
                }

                if (password.length < PASSWORD_REQUIREMENTS.minLength) {
                    updateState({ 
                        message: SIGNUP_MESSAGES.passwordTooShort,
                        loading: false 
                    });
                    return;
                }

                if (password !== confirmPassword) {
                    updateState({ 
                        message: SIGNUP_MESSAGES.passwordMismatch,
                        loading: false 
                    });
                    return;
                }

                const passwordStrength = PasswordStrengthChecker.check(password);
                if (!passwordStrength.isStrong) {
                    updateState({ 
                        message: `${SIGNUP_MESSAGES.passwordWeak}. ${passwordStrength.feedback}`,
                        loading: false 
                    });
                    return;
                }
            } else {
                // LOGIN: Genérico sempre
                if (password.length < PASSWORD_REQUIREMENTS.minLength) {
                    updateState({ 
                        message: AUTH_MESSAGES.invalidCredentials,
                        loading: false 
                    });
                    return;
                }
            }

            // ✅ 5. Suspicious activity detection
            const currentIp = await getClientIP();
            const suspiciousActivity = await SuspiciousActivityDetector.detect(
                email,
                isSignUp ? 'signup_attempt' : 'login_attempt',
                currentIp
            );

            if (suspiciousActivity.isSuspicious) {
                await AuditLogger.logSuspiciousActivity(email, suspiciousActivity.details);
                
                const message = suspiciousActivity.recommendedAction === 'block' 
                    ? AUTH_MESSAGES.suspiciousActivity
                    : AUTH_MESSAGES.rateLimitExceeded;
                
                updateState({ message, loading: false });
                return;
            }

            // ✅ 6. Log attempt (async)
            const logPromise = isSignUp 
                ? AuditLogger.logSignupAttempt(email)
                : AuditLogger.logLoginAttempt(email);
            logPromise.catch(console.error);

            // ✅ 7. Execute auth
            if (isSignUp) {
                await handleSignUp();
            } else {
                await handleLogin();
            }

        } catch (error) {
            console.error('❌ Erro inesperado no submit:', error);
            AuditLogger.logSuspiciousActivity(state.email, { 
                error: 'unexpected_error',
                details: String(error)
            }).catch(console.error);
            
            updateState({ 
                message: AUTH_MESSAGES.genericError,
                loading: false 
            });
        }
    };

    const handleSignUp = async () => {
        const { email, password } = state;

        const { data, error: signUpError } = await supabase.auth.signUp({
            email, 
            password,
            options: {
                emailRedirectTo: `${window.location.origin}/auth/callback`,
                data: {
                    signup_method: 'email',
                    signup_timestamp: new Date().toISOString()
                }
            }
        });
        
        if (signUpError) {
            let userMessage = AUTH_MESSAGES.genericError;
            
            if (signUpError.message.includes('rate limit')) {
                userMessage = "Muitas tentativas recentes. Aguarde 1 hora antes de tentar novamente.";
            } else if (signUpError.message.includes('already registered')) {
                userMessage = "Este email já está cadastrado. Faça login ou recupere sua senha.";
            } else if (signUpError.message.includes('email')) {
                userMessage = "Erro com o email. Verifique se está correto e tente novamente.";
            }
            
            AuditLogger.logSuspiciousActivity(email, { 
                error: signUpError.message,
                type: 'signup_failed' 
            }).catch(console.error);
            
            updateState({ 
                message: userMessage,
                loading: false 
            });
        } else {
            if (data.user) {
                AuditLogger.logSignupSuccess(data.user.id, email).catch(console.error);
            }
            
            if (data.user && !data.user.email_confirmed_at) {
                updateState({ 
                    message: "✅ Cadastro realizado! Verifique sua caixa de entrada (e spam) para confirmar seu email.",
                    loading: false 
                });
                
                setTimeout(() => {
                    updateState({ 
                        email: "",
                        password: "",
                        confirmPassword: "",
                        isSignUp: false
                    });
                }, 5000);
            } else {
                updateState({ 
                    message: "✅ Cadastro realizado com sucesso!",
                    loading: false 
                });
            }
        }
    };

    const handleLogin = async () => {
        const { email, password } = state;

        // ✅ Logout prévio para limpar sessões antigas
        await supabase.auth.signOut();
        
        const { data, error: signInError } = await supabase.auth.signInWithPassword({
            email, 
            password
        });
        
        if (signInError) {
            let userMessage = AUTH_MESSAGES.invalidCredentials;
            
            if (signInError.message.includes('Email not confirmed')) {
                userMessage = "Confirme seu email antes de fazer login.";
            } else if (signInError.message.includes('rate limit')) {
                userMessage = AUTH_MESSAGES.rateLimitExceeded;
            }
            
            AuditLogger.logLoginFailed(email, signInError.message).catch(console.error);
            
            updateState({ 
                message: userMessage,
                loading: false 
            });
        } else if (data.session) {
            if (data.user) {
                AuditLogger.logLoginSuccess(data.user.id, email).catch(console.error);
            }
            
            updateState({ 
                message: "✅ Login realizado com sucesso!",
                loading: false 
            });
            
            setTimeout(() => {
                window.location.reload();
            }, 1000);
        } else {
            AuditLogger.logLoginFailed(email, 'no_session_created').catch(console.error);
            
            updateState({ 
                message: AUTH_MESSAGES.genericError,
                loading: false 
            });
        }
    };

    const clearSession = async () => {
        updateState({ loading: true });
        
        try {
            await supabase.auth.signOut();
            localStorage.clear();
            sessionStorage.clear();
            
            updateState({ 
                message: "Sessão limpa com sucesso!",
                loading: false 
            });
            
            setTimeout(() => {
                router.push('/auth');
                router.refresh();
            }, 1000);
            
        } catch (error) {
            console.error('Erro ao limpar sessão:', error);
            window.location.href = '/auth';
        }
    };

    const passwordStrength = PasswordStrengthChecker.check(state.password);

    // ============================================
    // UI: FORGOT PASSWORD - ATUALIZADA
    // ============================================
    if (state.isForgotPassword) {
        return (
            <div className="w-full max-w-md mx-auto">
                <h2 className="text-2xl font-bold mb-6 text-center dark:text-white">
                    Recuperar Senha
                </h2>
                
                {state.message && (
                    <div className={`p-3 mb-4 rounded-lg ${
                        state.message.includes("Aguarde") || state.message.includes("Muitas tentativas") || state.message.includes("inválido")
                            ? "bg-red-50 border border-red-200 text-red-800 dark:bg-red-900/20 dark:border-red-800 dark:text-red-200"
                            : state.message.includes("✅") || state.message.includes("enviado")
                            ? "bg-green-50 border border-green-200 text-green-800 dark:bg-green-900/20 dark:border-green-800 dark:text-green-200"
                            : "bg-blue-50 border border-blue-200 text-blue-800 dark:bg-blue-900/20 dark:border-blue-800 dark:text-blue-200"
                    }`}>
                        {state.message}
                    </div>
                )}
                
                <form onSubmit={handleForgotPassword} className="space-y-4">
                    <input
                        type="text"
                        name="website"
                        value={state.honeypot}
                        onChange={(e) => updateState({ honeypot: e.target.value })}
                        className="hidden"
                        tabIndex={-1}
                        autoComplete="off"
                    />
                    
                    <div>
                        <label className="block text-sm font-medium mb-1 dark:text-gray-300">
                            Email
                        </label>
                        <input
                            type="email"
                            placeholder="seu@email.com"
                            value={state.email}
                            onChange={(e: ChangeEvent<HTMLInputElement>) => 
                                updateState({ email: e.target.value })
                            }
                            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-800 dark:border-gray-700 dark:text-white"
                            required
                            disabled={state.loading}
                        />
                        <p className="text-sm text-gray-600 dark:text-gray-400 mt-2">
                            Enviaremos um link de recuperação se este email existir em nosso sistema.
                        </p>
                    </div>
                    
                    <button
                        type="submit"
                        className="w-full px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed"
                        disabled={state.loading}
                    >
                        {state.loading ? "Enviando..." : "Enviar Email de Recuperação"}
                    </button>
                </form>
                
                <div className="mt-4 text-center">
                    <button
                        onClick={() => {
                            resetAuthState({ preserveEmail: true });
                            updateState({ isForgotPassword: false });
                        }}
                        className="text-blue-500 hover:text-blue-600 dark:text-blue-400 dark:hover:text-blue-300"
                        disabled={state.loading}
                    >
                        ← Voltar para login
                    </button>
                </div>
            </div>
        );
    }

    // ============================================
    // UI: LOGIN / SIGNUP - ATUALIZADA
    // ============================================
    return (
        <div className="w-full max-w-md mx-auto">
            <h2 className="text-2xl font-bold mb-6 text-center dark:text-white">
                {state.isSignUp ? "Criar Conta" : "Entrar"}
            </h2>
            
            {state.message && (
                <div className={`p-3 mb-4 rounded-lg ${
                    state.message.includes("✅") || state.message.includes("sucesso") || state.message.includes("criada")
                        ? "bg-green-50 border border-green-200 text-green-800 dark:bg-green-900/20 dark:border-green-800 dark:text-green-200" 
                        : state.message.includes("Erro") || state.message.includes("incorretos") || state.message.includes("inválido") || state.message.includes("Aguarde") || state.message.includes("Muitas")
                        ? "bg-red-50 border border-red-200 text-red-800 dark:bg-red-900/20 dark:border-red-800 dark:text-red-200"
                        : "bg-blue-50 border border-blue-200 text-blue-800 dark:bg-blue-900/20 dark:border-blue-800 dark:text-blue-200"
                }`}>
                    {state.message}
                </div>
            )}
            
            <form onSubmit={handleSubmit} className="space-y-4">
                <input
                    type="text"
                    name="website"
                    value={state.honeypot}
                    onChange={(e) => updateState({ honeypot: e.target.value })}
                    className="hidden"
                    tabIndex={-1}
                    autoComplete="off"
                />
                
                <div>
                    <label className="block text-sm font-medium mb-1 dark:text-gray-300">
                        Email
                    </label>
                    <input
                        type="email"
                        placeholder="seu@email.com"
                        value={state.email}
                        onChange={(e: ChangeEvent<HTMLInputElement>) => 
                            updateState({ email: e.target.value })
                        }
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-800 dark:border-gray-700 dark:text-white"
                        required
                        disabled={state.loading}
                    />
                </div>
                
                <div>
                    <label className="block text-sm font-medium mb-1 dark:text-gray-300">
                        Senha
                    </label>
                    <div className="relative">
                        <input
                            type={state.showPassword ? "text" : "password"}
                            placeholder="••••••••"
                            value={state.password}
                            onChange={(e: ChangeEvent<HTMLInputElement>) =>
                                updateState({ password: e.target.value })
                            }
                            className="w-full px-4 py-2 pr-10 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-800 dark:border-gray-700 dark:text-white"
                            required
                            disabled={state.loading}
                        />
                        <button
                            type="button"
                            onClick={() => updateState({ showPassword: !state.showPassword })}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
                            disabled={state.loading}
                        >
                            {state.showPassword ? "👁️" : "👁️‍🗨️"}
                        </button>
                    </div>
                    
                    {state.isSignUp && state.password && (
                        <div className="mt-2">
                            <div className="flex space-x-1 mb-1">
                                {[1, 2, 3, 4, 5].map((i) => (
                                    <div
                                        key={i}
                                        className={`h-1 flex-1 rounded ${
                                            i <= passwordStrength.passedChecks
                                                ? PasswordStrengthChecker.getStrengthColor(passwordStrength.passedChecks)
                                                : 'bg-gray-200'
                                        }`}
                                    />
                                ))}
                            </div>
                            <p className="text-xs text-gray-500">
                                Força: {PasswordStrengthChecker.getStrengthText(passwordStrength.passedChecks)}
                                {passwordStrength.feedback && ` - ${passwordStrength.feedback}`}
                            </p>
                        </div>
                    )}
                    
                    {!state.isSignUp && (
                        <div className="text-right mt-1">
                            <button
                                type="button"
                                onClick={() => updateState({ 
                                    isForgotPassword: true,
                                    message: ""
                                })}
                                className="text-sm text-blue-500 hover:text-blue-600 dark:text-blue-400 dark:hover:text-blue-300"
                                disabled={state.loading}
                            >
                                Esqueceu a senha?
                            </button>
                        </div>
                    )}
                </div>
                
                {state.isSignUp && (
                    <div>
                        <label className="block text-sm font-medium mb-1 dark:text-gray-300">
                            Confirmar Senha
                        </label>
                        <div className="relative">
                            <input
                                type={state.showConfirmPassword ? "text" : "password"}
                                placeholder="••••••••"
                                value={state.confirmPassword}
                                onChange={(e: ChangeEvent<HTMLInputElement>) =>
                                    updateState({ confirmPassword: e.target.value })
                                }
                                className="w-full px-4 py-2 pr-10 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-800 dark:border-gray-700 dark:text-white"
                                required
                                disabled={state.loading}
                            />
                            <button
                                type="button"
                                onClick={() => updateState({ showConfirmPassword: !state.showConfirmPassword })}
                                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
                                disabled={state.loading}
                            >
                                {state.showConfirmPassword ? "👁️" : "👁️‍🗨️"}
                            </button>
                        </div>
                    </div>
                )}
                
                <button
                    type="submit"
                    className="w-full px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed"
                    disabled={state.loading}
                >
                    {state.loading ? "Aguarde..." : (state.isSignUp ? "Criar Conta" : "Entrar")}
                </button>
            </form>
            
            <div className="mt-4 text-center">
                <button
                    onClick={() => {
                        resetAuthState({ preserveEmail: true });
                        updateState({ isSignUp: !state.isSignUp });
                    }}
                    className="text-blue-500 hover:text-blue-600 dark:text-blue-400 dark:hover:text-blue-300"
                    disabled={state.loading}
                >
                    {state.isSignUp ? "Já tem conta? Faça login" : "Não tem conta? Cadastre-se"}
                </button>
            </div>
            
            <div className="mt-6 pt-6 border-t border-gray-200 dark:border-gray-700">
                <button
                    onClick={clearSession}
                    className="w-full px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors text-sm"
                    disabled={state.loading}
                >
                    Limpar Sessão (usar se tiver problemas)
                </button>
            </div>
        </div>
    );
}