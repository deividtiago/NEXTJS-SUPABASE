'use client'
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import styles from "./Nav.module.css";
import { getSupabaseBrowserClient } from "@/supabase-utils/browserClient";
import { useEffect, useState, useCallback, useRef } from "react";

interface AuditLog {
  action: string;
  timestamp: string;
  user_agent: string;
  reason?: string;
}

// Utility: Validar se uma URL é segura (mesma origem)
function isSafeRedirectUrl(url: string): boolean {
    try {
        const parsed = new URL(url, window.location.origin);
        
        // Permitir apenas URLs do mesmo domínio
        if (parsed.origin !== window.location.origin) {
            console.warn('Blocked external redirect attempt:', url);
            return false;
        }
        
        // Bloquear protocolos perigosos
        if (!['http:', 'https:'].includes(parsed.protocol)) {
            console.warn('Blocked non-HTTP redirect:', url);
            return false;
        }
        
        return true;
    } catch {
        // URL inválida
        console.warn('Invalid redirect URL:', url);
        return false;
    }
}

// Utility: Obter returnUrl validada dos query params
function getSafeReturnUrl(): string {
    if (typeof window === 'undefined') return '/login';
    
    const params = new URLSearchParams(window.location.search);
    const returnUrl = params.get('returnUrl');
    
    if (!returnUrl) return '/login';
    
    // Validar segurança da URL
    if (!isSafeRedirectUrl(returnUrl)) {
        return '/login'; // Fallback seguro
    }
    
    return returnUrl;
}

export default function Nav() {
    const pathname = usePathname();
    const supabase = getSupabaseBrowserClient();
    const router = useRouter();
    
    const [isLoggingOut, setIsLoggingOut] = useState(false);
    const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);
    const [inactivityTime] = useState(30); // minutos
    
    // Refs para controle
    const inactivityTimerRef = useRef<NodeJS.Timeout | null>(null);
    const logoutControllerRef = useRef<AbortController | null>(null);
    const isLoggingOutRef = useRef(false);
    const hasUnsavedChangesRef = useRef(false);

    // Atualizar refs quando estados mudam
    useEffect(() => {
        isLoggingOutRef.current = isLoggingOut;
    }, [isLoggingOut]);

    useEffect(() => {
        hasUnsavedChangesRef.current = hasUnsavedChanges;
    }, [hasUnsavedChanges]);

    // 1. Auditoria de eventos
    const logAuditEvent = useCallback(async (logData: AuditLog) => {
        try {
            await fetch('/api/audit/log', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(logData),
            });
        } catch (error) {
            console.warn('Audit logging failed:', error);
        }
    }, []);

    // 2. Limpeza completa de dados sensíveis
    const clearSensitiveData = useCallback(() => {
        // Limpar storage específico da aplicação
        const sensitiveKeys = [
            'ticket_drafts',
            'user_preferences', 
            'form_data',
            'cached_user_data'
        ];
        
        sensitiveKeys.forEach(key => {
            localStorage.removeItem(key);
            sessionStorage.removeItem(key);
        });

        // Limpar dados de autenticação residual
        const supabaseUrl = (supabase as any).supabaseUrl?.replace(/[^a-zA-Z0-9]/g, '') || 'supabase';
        localStorage.removeItem(`sb-${supabaseUrl}-auth-token`);
        sessionStorage.clear();
    }, [supabase]);

    // 3. Handler de logout principal com validação de segurança
    const handleLogout = useCallback(async (
        event?: React.MouseEvent, 
        reason?: 'manual' | 'inactivity' | 'session_expired' | 'multiple_tabs'
    ) => {
        if (event) {
            event.preventDefault();
        }

        if (isLoggingOutRef.current) return;
        
        if (hasUnsavedChangesRef.current && reason === 'manual') {
            const confirmMessage = 'Você tem alterações não salvas. Deseja realmente sair?';
            if (!window.confirm(confirmMessage)) {
                return;
            }
        }

        setIsLoggingOut(true);
        isLoggingOutRef.current = true;
        
        try {
            // Registrar evento de auditoria
            await logAuditEvent({
                action: 'logout_initiated',
                timestamp: new Date().toISOString(),
                user_agent: navigator.userAgent,
                reason: reason || 'manual'
            });

            // Executar logout no Supabase
            const { error } = await supabase.auth.signOut();

            if (error) {
                console.error('Supabase logout error:', error);
                throw error;
            }

            // Limpeza de dados sensíveis
            clearSensitiveData();

            // Registrar logout bem-sucedido
            await logAuditEvent({
                action: 'logout_completed',
                timestamp: new Date().toISOString(),
                user_agent: navigator.userAgent,
                reason: reason || 'manual'
            });

            // SEGURANÇA: Usar returnUrl validada
            const safeRedirectUrl = getSafeReturnUrl();
            console.log('Logout successful, redirecting to:', safeRedirectUrl);
            window.location.href = safeRedirectUrl;

        } catch (error: any) {
            console.error('Logout error:', error);
            
            // Limpeza mesmo em caso de erro
            clearSensitiveData();
            
            if (error?.name === 'AbortError' || !navigator.onLine) {
                await logAuditEvent({
                    action: 'logout_offline_fallback',
                    timestamp: new Date().toISOString(),
                    user_agent: navigator.userAgent,
                    reason: 'offline_or_timeout'
                });
                
                window.location.href = '/login?offline=true';
            } else {
                window.location.href = '/login?error=logout_failed';
            }
        } finally {
            setIsLoggingOut(false);
            isLoggingOutRef.current = false;
            logoutControllerRef.current = null;
        }
    }, [logAuditEvent, clearSensitiveData, supabase.auth]);

    // 4. Detecção de inatividade
    const handleLogoutRef = useRef(handleLogout);
    useEffect(() => {
        handleLogoutRef.current = handleLogout;
    }, [handleLogout]);

    const setupInactivityTimer = useCallback(() => {
        const resetInactivityTimer = () => {
            if (inactivityTimerRef.current) {
                clearTimeout(inactivityTimerRef.current);
            }
            
            inactivityTimerRef.current = setTimeout(() => {
                handleLogoutRef.current(undefined, 'inactivity');
            }, inactivityTime * 60 * 1000);
        };

        const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];
        
        events.forEach(event => {
            document.addEventListener(event, resetInactivityTimer, { passive: true });
        });

        resetInactivityTimer();

        return () => {
            if (inactivityTimerRef.current) {
                clearTimeout(inactivityTimerRef.current);
            }
            events.forEach(event => {
                document.removeEventListener(event, resetInactivityTimer);
            });
        };
    }, [inactivityTime]);

    // 5. Listener para mudanças de autenticação
    useEffect(() => {
        let mounted = true;

        const { data: { subscription } } = supabase.auth.onAuthStateChange(async (event, session) => {
            if (!mounted) return;
            
            console.log('Auth state changed:', event);
            
            switch (event) {
                case 'SIGNED_OUT':
                    if (!isLoggingOutRef.current) {
                        console.log('Auto logout detected - performing cleanup');
                        clearSensitiveData();
                        
                        await logAuditEvent({
                            action: 'logout_auto',
                            timestamp: new Date().toISOString(),
                            user_agent: navigator.userAgent,
                            reason: 'multiple_tabs'
                        });
                        
                        window.location.href = '/login?reason=multiple_tabs';
                    }
                    break;
                    
                case 'TOKEN_REFRESHED':
                    if (inactivityTimerRef.current) {
                        clearTimeout(inactivityTimerRef.current);
                        inactivityTimerRef.current = setTimeout(() => {
                            handleLogoutRef.current(undefined, 'inactivity');
                        }, inactivityTime * 60 * 1000);
                    }
                    break;
            }
        });

        return () => {
            mounted = false;
            subscription.unsubscribe();
        };
    }, [supabase, clearSensitiveData, inactivityTime, logAuditEvent]);

    // 6. Setup de inatividade
    useEffect(() => {
        const cleanupInactivity = setupInactivityTimer();
        return cleanupInactivity;
    }, [setupInactivityTimer]);

    // 7. Prevenção de navegação acidental com dados não salvos
    useEffect(() => {
        const handleBeforeUnload = (event: BeforeUnloadEvent) => {
            if (hasUnsavedChanges) {
                event.preventDefault();
                event.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
                return event.returnValue;
            }
        };

        window.addEventListener('beforeunload', handleBeforeUnload);
        
        return () => {
            window.removeEventListener('beforeunload', handleBeforeUnload);
        };
    }, [hasUnsavedChanges]);

    // 8. SEGURANÇA: Limpar query params maliciosos na montagem
    useEffect(() => {
        if (typeof window === 'undefined') return;
        
        const params = new URLSearchParams(window.location.search);
        const returnUrl = params.get('returnUrl');
        
        if (returnUrl && !isSafeRedirectUrl(returnUrl)) {
            // Remover parâmetro malicioso silenciosamente
            params.delete('returnUrl');
            const newUrl = `${window.location.pathname}${params.toString() ? '?' + params.toString() : ''}`;
            window.history.replaceState({}, '', newUrl);
            
            console.warn('Removed unsafe returnUrl parameter');
        }
    }, []);

    return (
        <header className={styles.header}>
            <nav className={styles.nav}>
                <ul className={styles.navList}>
                    <li>
                        <Link 
                            href="/tickets"
                            className={pathname === "/tickets" ? styles.linkActive : styles.link}
                        >
                            Ticket List
                        </Link>
                    </li>
                    <li>
                        <Link 
                            href="/tickets/new"
                            className={pathname === "/tickets/new" ? styles.linkActive : styles.link}
                            onClick={() => setHasUnsavedChanges(true)}
                        >
                            Create New Ticket
                        </Link>
                    </li>
                    <li>
                        <Link 
                            href="/tickets/users"
                            className={pathname === "/tickets/users" ? styles.linkActive : styles.link}
                        >
                            User List
                        </Link>
                    </li>
                </ul>
                
                <button
                    type="button"
                    onClick={(event) => handleLogout(event, 'manual')}
                    disabled={isLoggingOut}
                    className={styles.logoutButton}
                    aria-busy={isLoggingOut}
                >
                    {isLoggingOut ? (
                        <>
                            <span className={styles.spinner}></span>
                            Logging out...
                        </>
                    ) : (
                        'Log out'
                    )}
                </button>

                {inactivityTime > 0 && (
                    <div className={styles.inactivityWarning}>
                        Auto-logout in: {inactivityTime}min
                    </div>
                )}
            </nav>
            
            <div className={styles.divider}></div>
        </header>
    );
}