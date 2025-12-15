// app/tickets/change-password/page.tsx
"use client";

import { getSupabaseBrowserClient } from "@/supabase-utils/browserClient";
import { useRef, useState, FormEvent, useEffect } from "react"; 
import Link from 'next/link';
import { useRouter } from 'next/navigation';

export default function ChangePasswordPage() {
  const passwordRef = useRef<HTMLInputElement | null>(null);
  const supabase = getSupabaseBrowserClient();
  const router = useRouter();
  
  const [message, setMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isCheckingAuth, setIsCheckingAuth] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // 🔒 VERIFICAÇÃO DE AUTENTICAÇÃO NO CARREGAMENTO
  useEffect(() => {
    const checkAuth = async () => {
      console.log('🔐 Verificando autenticação na página de troca de senha...');
      
      try {
        const { data: { session }, error } = await supabase.auth.getSession();
        
        if (error) {
          console.error('❌ Erro ao verificar sessão:', error);
          setMessage('Erro ao verificar autenticação. Tente novamente.');
          setIsCheckingAuth(false);
          return;
        }

        if (!session) {
          console.log('❌ Nenhuma sessão encontrada. Redirecionando para login...');
          setMessage('Sessão expirada. Solicite um novo link de recuperação.');
          setTimeout(() => {
            router.push('/login?type=recovery');
          }, 2000);
          return;
        }

        console.log('✅ Sessão válida encontrada:', session.user.email);
        setIsAuthenticated(true);
      } catch (err) {
        console.error('💥 Erro inesperado:', err);
        setMessage('Erro inesperado. Tente novamente.');
      } finally {
        setIsCheckingAuth(false);
      }
    };

    checkAuth();
  }, [supabase, router]);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setMessage('');
    
    if (!passwordRef.current) {
      setMessage('Erro interno: O campo de senha não foi encontrado.');
      return;
    }

    const value = passwordRef.current.value.trim();

    if (value.length < 6) {
      setMessage('A nova senha deve ter pelo menos 6 caracteres.');
      return;
    }
    
    setIsLoading(true);

    try {
      const { error } = await supabase.auth.updateUser({ password: value });
      
      if (error) {
        setMessage(`Erro ao atualizar a senha: ${error.message}`);
      } else {
        setMessage("✅ Senha atualizada com sucesso! Redirecionando...");
        
        if (passwordRef.current) { 
          passwordRef.current.value = "";
        }

        // Redirecionar após 2 segundos
        setTimeout(() => {
          router.push('/tickets');
        }, 2000);
      }
    } catch (err: any) {
      setMessage(`Erro: ${err.message || 'Erro desconhecido'}`);
    } finally {
      setIsLoading(false);
    }
  };

  // 🔄 LOADING STATE
  if (isCheckingAuth) {
    return (
      <div style={{
        minHeight: '100vh',
        backgroundColor: '#0f1419',
        color: '#ffffff',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{
            width: '48px',
            height: '48px',
            border: '3px solid #2d3748',
            borderTop: '3px solid #3b9dd8',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            margin: '0 auto 1rem'
          }} />
          <p style={{ color: '#94a3b8' }}>Verificando autenticação...</p>
        </div>
      </div>
    );
  }

  // 🚫 NÃO AUTENTICADO
  if (!isAuthenticated) {
    return (
      <div style={{
        minHeight: '100vh',
        backgroundColor: '#0f1419',
        color: '#ffffff',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1rem'
      }}>
        <div style={{
          maxWidth: '28rem',
          width: '100%',
          padding: '2rem',
          textAlign: 'center'
        }}>
          <h2 style={{
            fontSize: '1.5rem',
            fontWeight: 'bold',
            color: '#ef4444',
            marginBottom: '1rem'
          }}>
            Acesso Negado
          </h2>
          <p style={{
            color: '#d1d5db',
            marginBottom: '1.5rem'
          }}>
            {message || 'Você precisa estar autenticado para redefinir sua senha.'}
          </p>
          <Link 
            href="/login?type=recovery"
            style={{
              display: 'inline-block',
              padding: '0.75rem 1.5rem',
              backgroundColor: '#3b9dd8',
              color: '#ffffff',
              borderRadius: '0.375rem',
              textDecoration: 'none',
              transition: 'background-color 0.2s'
            }}
            onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#2d8bc7'}
            onMouseLeave={(e) => e.currentTarget.style.backgroundColor = '#3b9dd8'}
          >
            Solicitar Novo Link
          </Link>
        </div>
      </div>
    );
  }

  // ✅ RENDERIZAÇÃO NORMAL - FORMATO LIMPO
  return (
    <div style={{
      minHeight: '100vh',
      backgroundColor: '#0f1419',
      color: '#ffffff',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '1rem'
    }}>
      <div style={{
        maxWidth: '28rem',
        width: '100%'
      }}>
        {/* Card Container */}
        <div style={{
          backgroundColor: '#1a1f2e',
          padding: '2rem',
          borderRadius: '0.5rem'
        }}>
          {/* Header */}
          <h1 style={{
            fontSize: '1.5rem',
            fontWeight: '400',
            marginBottom: '2rem',
            color: '#ffffff'
          }}>
            Redefinir Senha
          </h1>

          {/* Mensagem de Feedback */}
          {message && (
            <div style={{
              marginBottom: '1.5rem',
              padding: '0.75rem',
              borderRadius: '0.375rem',
              backgroundColor: message.includes('✅') ? '#065f46' : '#991b1b',
              color: message.includes('✅') ? '#d1fae5' : '#fecaca',
              fontSize: '0.875rem'
            }}>
              {message}
            </div>
          )}

          {/* Formulário */}
          <form onSubmit={handleSubmit}>
            <div style={{ marginBottom: '1.5rem' }}>
              <label 
                htmlFor="password"
                style={{
                  display: 'block',
                  color: '#ffffff',
                  marginBottom: '0.75rem',
                  fontWeight: '400'
                }}
              >
                New Password
              </label>
              <input
                ref={passwordRef}
                name="password"
                type="password"
                id="password"
                required
                minLength={6}
                disabled={isLoading}
                style={{
                  width: '100%',
                  padding: '0.75rem',
                  backgroundColor: '#0f1419',
                  border: '1px solid #2d3748',
                  borderRadius: '0.25rem',
                  color: '#ffffff',
                  fontSize: '1rem',
                  outline: 'none',
                  opacity: isLoading ? 0.5 : 1
                }}
              />
            </div>

            <button 
              type="submit" 
              disabled={isLoading}
              style={{
                width: '100%',
                padding: '0.875rem',
                backgroundColor: '#3b9dd8',
                color: '#ffffff',
                border: 'none',
                borderRadius: '0.25rem',
                fontSize: '1rem',
                cursor: isLoading ? 'not-allowed' : 'pointer',
                fontWeight: '500',
                transition: 'background-color 0.2s',
                opacity: isLoading ? 0.5 : 1
              }}
              onMouseEnter={(e) => !isLoading && (e.currentTarget.style.backgroundColor = '#2d8bc7')}
              onMouseLeave={(e) => !isLoading && (e.currentTarget.style.backgroundColor = '#3b9dd8')}
            >
              {isLoading ? 'Redefinindo...' : 'Reset Password'}
            </button>
          </form>

          {/* Link para voltar */}
          <div style={{
            marginTop: '1.5rem',
            textAlign: 'center'
          }}>
            <Link 
              href="/login"
              style={{
                color: '#3b9dd8',
                textDecoration: 'none',
                fontSize: '0.875rem'
              }}
            >
              ← Voltar para Login
            </Link>
          </div>
        </div>
      </div>

      {/* Animação de Spinner */}
      <style jsx>{`
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}