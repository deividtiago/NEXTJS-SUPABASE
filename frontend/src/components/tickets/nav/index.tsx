'use client'
import Link from "next/link";
import { usePathname } from "next/navigation";
import styles from "./Nav.module.css";
import { getSupabaseBrowserClient } from "@/supabase-utils/browserClient";
import { useEffect, useState, useCallback, useRef } from "react";

export default function Nav() {
    const pathname = usePathname();
    const supabase = getSupabaseBrowserClient();
    
    const [isLoggingOut, setIsLoggingOut] = useState(false);
    const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);
    
    const isLoggingOutRef = useRef(false);
    const hasUnsavedChangesRef = useRef(false);

    useEffect(() => {
        isLoggingOutRef.current = isLoggingOut;
    }, [isLoggingOut]);

    useEffect(() => {
        hasUnsavedChangesRef.current = hasUnsavedChanges;
    }, [hasUnsavedChanges]);

    // ========================================
    // 🔥 LOGOUT SIMPLIFICADO (USA ROTA EXISTENTE)
    // ========================================
    
    const handleLogout = useCallback(async (event?: React.MouseEvent) => {
        if (event) {
            event.preventDefault();
        }

        if (isLoggingOutRef.current) return;
        
        // Confirmar se houver mudanças não salvas
        if (hasUnsavedChangesRef.current) {
            const confirmMessage = 'Você tem alterações não salvas. Deseja realmente sair?';
            if (!window.confirm(confirmMessage)) {
                return;
            }
        }

        setIsLoggingOut(true);
        isLoggingOutRef.current = true;
        
        try {
            console.log('🚪 Iniciando logout...');

            // 🔥 Usar a rota de logout existente
            const { error } = await supabase.auth.signOut();

            if (error) {
                console.error('Erro no logout:', error);
                throw error;
            }

            console.log('✅ Logout bem-sucedido');

            // Limpar dados locais (apenas sessionStorage para UX)
            sessionStorage.clear();
            
            // Redirecionar para login
            window.location.href = '/login';

        } catch (error: any) {
            console.error('💥 Erro no logout:', error);
            
            // Mesmo com erro, limpar e redirecionar
            sessionStorage.clear();
            window.location.href = '/login?error=logout_failed';
            
        } finally {
            setIsLoggingOut(false);
            isLoggingOutRef.current = false;
        }
    }, [supabase.auth]);

    // ========================================
    // LISTENER DE MUDANÇAS DE AUTH
    // ========================================
    
    useEffect(() => {
        let mounted = true;

        const { data: { subscription } } = supabase.auth.onAuthStateChange(async (event, session) => {
            if (!mounted) return;
            
            console.log('🔄 Auth state changed:', event);
            
            // Se detectar logout em outra tab
            if (event === 'SIGNED_OUT' && !isLoggingOutRef.current) {
                console.log('🔀 Logout detectado em outra aba');
                sessionStorage.clear();
                window.location.href = '/login?reason=multiple_tabs';
            }
        });

        return () => {
            mounted = false;
            subscription.unsubscribe();
        };
    }, [supabase.auth]);

    // ========================================
    // PREVENÇÃO DE NAVEGAÇÃO COM DADOS NÃO SALVOS
    // ========================================
    
    useEffect(() => {
        const handleBeforeUnload = (event: BeforeUnloadEvent) => {
            if (hasUnsavedChanges) {
                event.preventDefault();
                event.returnValue = 'Você tem alterações não salvas. Deseja realmente sair?';
                return event.returnValue;
            }
        };

        window.addEventListener('beforeunload', handleBeforeUnload);
        
        return () => {
            window.removeEventListener('beforeunload', handleBeforeUnload);
        };
    }, [hasUnsavedChanges]);

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
                    onClick={handleLogout}
                    disabled={isLoggingOut}
                    className={styles.logoutButton}
                    aria-busy={isLoggingOut}
                >
                    {isLoggingOut ? (
                        <>
                            <span className={styles.spinner}></span>
                            Saindo...
                        </>
                    ) : (
                        'Sair'
                    )}
                </button>
            </nav>
            
            <div className={styles.divider}></div>
        </header>
    );
}