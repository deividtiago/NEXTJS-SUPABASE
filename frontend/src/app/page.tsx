// app/page.tsx - VERSÃO CORRIGIDA
import { redirect } from "next/navigation";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Magic Link Handler",
  description: "Handler para redirecionamento de magic link",
};

export default async function HomePage({
  searchParams,
}: {
  searchParams: Promise<{ code?: string }>;
}) {
  const params = await searchParams;
  const code = params.code;

  // Se tiver código, é magic link - redireciona para callback
  if (code) {
    console.log("🎯 Código de magic link detectado na raiz:", code.substring(0, 10) + "...");
    
    // Constrói a URL de callback mantendo o código
    const callbackUrl = new URL('/auth/callback', process.env.NEXT_PUBLIC_SITE_URL || 'http://localhost:3000');
    callbackUrl.searchParams.set('code', code);
    callbackUrl.searchParams.set('redirect', '/tickets');
    
    console.log("📍 Redirecionando para:", callbackUrl.toString());
    redirect(callbackUrl.toString());
  }

  // Se não tiver código, redireciona para login normalmente
  console.log("🔀 Redirecionando para login (sem código)");
  redirect('/login');
}