// app/magic-thanks/page.tsx
// Nenhuma diretiva 'use client' aqui. Este é um Server Component.

import { Suspense } from 'react';
import Link from 'next/link';

// ----------------------------------------------------
// Componente MagicThanksContent (Server Component ou Cliente sem 'use client' aqui)
// Se este componente não usa hooks, ele não precisa ser 'use client'.
// Se precisar de 'use client', ele deve ser movido para um arquivo separado.
// ----------------------------------------------------
function MagicThanksContent({ type }: { type?: string }) {
  const isRecovery = type === "recovery";
  const isSignup = type === "signup";
  const title = isRecovery 
    ? "Link de recuperação enviado!" 
    : isSignup 
      ? "Confirmação de cadastro enviada!"
      : "Magic link enviado!";

  const message = isRecovery
    ? "Verifique seu email para redefinir sua senha."
    : isSignup
      ? "Verifique seu email para confirmar seu cadastro."
      : "Verifique seu email para fazer login. O link expira em 24 horas.";

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8 p-8 bg-white rounded-lg shadow">
        <div className="text-center">
          <h2 className="mt-6 text-3xl font-bold text-gray-900">{title}</h2>
          <p className="mt-2 text-sm text-gray-600">{message}</p>
        </div>
        
        <div className="mt-8 space-y-4">
          <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
            <p className="text-sm text-blue-800">
              <strong>📧 Verifique sua caixa de entrada</strong>
              <br />
              Se não encontrar o email, verifique a pasta de spam.
            </p>
          </div>
          
          <div className="text-center">
            <Link
              href="/login"
              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
            >
              Voltar para o login
            </Link>
          </div>
          
          <div className="text-center text-sm text-gray-500">
            <p>Problemas com o link? <Link href="/login" className="text-blue-600 hover:text-blue-500">Solicite um novo</Link></p>
          </div>
        </div>
      </div>
    </div>
  );
}

// ----------------------------------------------------
// Componente de Página (Server Component Assíncrono)
// ----------------------------------------------------
export default async function MagicLinkSuccessPage({ // <-- Tornar a função 'async'
  searchParams,
}: {
  searchParams: { type?: string };
}) {
  // A tipagem é { type?: string }, mas o erro de runtime forçou o tratamento como Promise.
  
  // Usamos o 'await' para resolver a Promise de searchParams antes de acessar 'type'.
  // Para que o TypeScript não reclame, fazemos um cast para Promise antes de aguardar.
  const params = await (searchParams as Promise<{ type?: string }>);
  
  // Agora acessamos a propriedade de forma segura
  const type = params.type;

  return (
    // O Suspense não é estritamente necessário se o problema for APENAS searchParams,
    // pois o Server Component Page/Layout resolve o `await`.
    // Mantendo-o, caso você tenha outras Suspense Boundaries na página que precisem dele.
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">Carregando...</div>
      </div>
    }>
      <MagicThanksContent type={type} />
    </Suspense>
  );
}

// O componente MagicThanksContentWrapper foi removido,
// pois o Server Component MagicLinkSuccessPage agora faz a resolução da Promise.