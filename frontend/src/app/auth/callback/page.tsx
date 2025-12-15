// app/auth/callback/page.tsx - VERSÃO OTIMIZADA
'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { createBrowserClient } from '@supabase/ssr';

export default function AuthCallbackPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [status, setStatus] = useState('Processando autenticação...');
  const [error, setError] = useState('');

  useEffect(() => {
    async function handleCallback() {
      try {
        const code = searchParams.get('code');
        const errorParam = searchParams.get('error');
        const errorDescription = searchParams.get('error_description');

        console.log('\n🎯 CALLBACK CLIENT-SIDE');
        console.log('   Code:', code ? `✅ ${code.substring(0, 10)}...` : '❌');

        if (errorParam) {
          throw new Error(errorDescription || errorParam);
        }

        if (!code) {
          throw new Error('Nenhum código de autenticação recebido');
        }

        const supabase = createBrowserClient(
          process.env.NEXT_PUBLIC_SUPABASE_URL!,
          process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
        );

        // Verifica se já tem sessão ativa
        const { data: sessionData } = await supabase.auth.getSession();
        if (sessionData?.session) {
          console.log('✅ Sessão já existe! Redirecionando...');
          // FORÇA um hard reload para garantir que o middleware pegue a sessão
          window.location.replace('/tickets');
          return;
        }

        console.log('🔄 Tentando exchange de code...');
        setStatus('Verificando código...');
        
        // Verifica PKCE verifier
        const pkceVerifier = localStorage.getItem('supabase-pkce-code-verifier');
        
        if (!pkceVerifier) {
          console.warn('⚠️ Sem PKCE verifier - usando API do servidor');
          
          const verifyResponse = await fetch('/api/auth/verify-code', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code }),
          });
          
          if (verifyResponse.ok) {
            const verifyData = await verifyResponse.json();
            if (verifyData.success) {
              console.log('✅ Código verificado pelo servidor!');
              setStatus('Autenticado! Redirecionando...');
              
              // Aguarda 500ms para garantir que cookies foram salvos
              await new Promise(resolve => setTimeout(resolve, 500));
              
              // FORÇA hard reload
              window.location.replace('/tickets');
              return;
            }
          }
          
          throw new Error('Código de verificação expirado ou inválido. Solicite um novo magic link.');
        }
        
        // Exchange com PKCE
        const { data, error: authError } = await supabase.auth.exchangeCodeForSession(code);

        if (authError) {
          console.error('❌ Erro auth:', authError.message);
          throw authError;
        }

        if (!data?.session) {
          throw new Error('Sessão não foi criada');
        }

        console.log('✅ Autenticado com sucesso!');
        console.log('   User:', data.user?.email);

        setStatus('Sucesso! Redirecionando...');
        
        // Aguarda 500ms para garantir que cookies foram salvos
        await new Promise(resolve => setTimeout(resolve, 500));

        // FORÇA hard reload
        window.location.replace('/tickets');

      } catch (err: any) {
        console.error('💥 Erro no callback:', err.message);
        setError(err.message || 'Erro ao processar autenticação');
        
        // Redireciona para login após 3 segundos
        setTimeout(() => {
          router.push(`/login?error=${encodeURIComponent(err.message)}&type=magiclink`);
        }, 3000);
      }
    }

    handleCallback();
  }, [searchParams, router]);

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="max-w-md w-full bg-white rounded-lg shadow-lg p-8">
          <div className="text-center">
            <div className="text-red-500 text-5xl mb-4">❌</div>
            <h2 className="text-2xl font-bold text-gray-900 mb-4">Erro na Autenticação</h2>
            <p className="text-gray-600 mb-6">{error}</p>
            <p className="text-sm text-gray-500">Redirecionando para o login...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="text-center">
        <div className="inline-block animate-spin rounded-full h-16 w-16 border-b-4 border-blue-600 mb-4"></div>
        <p className="text-xl text-gray-700">{status}</p>
        <p className="text-sm text-gray-500 mt-2">Por favor, aguarde...</p>
      </div>
    </div>
  );
}