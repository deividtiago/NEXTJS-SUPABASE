'use client'
import Link from "next/link";
import { usePathname } from "next/navigation";
import styles from "./Nav.module.css";
import { useEffect, useState, useCallback, useRef } from "react";

export default function Nav() {
    const pathname = usePathname();
    
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
    // 🔥 LOGOUT - CHAMA ROTA DO SERVIDOR
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
            console.log('🚪 Chamando logout no servidor...');

            // 🔥 CHAMAR ROTA DE LOGOUT NO SERVIDOR
            const response = await fetch('/logout', {
                method: 'POST',
                credentials: 'include', // Incluir cookies
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(data.error || 'Erro ao realizar logout');
            }

            console.log('✅ Logout bem-sucedido');

            // Limpar dados locais (apenas UX, segurança é no servidor)
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
    }, []);

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