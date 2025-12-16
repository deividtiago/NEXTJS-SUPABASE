// app/page.tsx - CORRIGIDO PARA USAR /auth/verify
import { redirect } from "next/navigation";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Task Manager",
  description: "Sistema de gerenciamento de tarefas",
};

export default async function HomePage({
  searchParams,
}: {
  searchParams: Promise<{ code?: string; token_hash?: string; type?: string }>;
}) {
  const params = await searchParams;
  const code = params.code;
  const token_hash = params.token_hash;
  const type = params.type;

  console.log("🏠 [HOME PAGE] Parâmetros recebidos:", { 
    code: code ? `***${code.slice(-6)}` : 'ausente',
    token_hash: token_hash ? `***${token_hash.slice(-6)}` : 'ausente',
    type: type || 'ausente'
  });

  // Se tiver code ou token_hash, é um link de autenticação
  if (code || token_hash) {
    console.log("🔐 [HOME PAGE] Token de autenticação detectado");
    
    // Constrói a URL para /auth/verify (NÃO /auth/callback!)
    const verifyUrl = new URL('/auth/verify', process.env.NEXT_PUBLIC_SITE_URL || 'http://localhost:3000');
    
    // Usa token_hash se existir, senão usa code
    const tokenValue = token_hash || code || '';
    verifyUrl.searchParams.set('token_hash', tokenValue);
    
    // Define o type (magiclink por padrão)
    verifyUrl.searchParams.set('type', type || 'magiclink');
    
    console.log("📍 [HOME PAGE] Redirecionando para:", verifyUrl.toString());
    redirect(verifyUrl.toString());
  }

  // Se não tiver nenhum token, redireciona para login
  console.log("🔀 [HOME PAGE] Sem tokens, redirecionando para /login");
  redirect('/login');
}