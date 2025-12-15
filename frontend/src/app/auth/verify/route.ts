// app/auth/verify/route.ts
import { createServerClient } from '@supabase/ssr';
import { cookies } from 'next/headers';
import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  console.log('\n🔐 ========================================');
  console.log('VERIFICANDO LINK DE AUTENTICAÇÃO');
  console.log('========================================\n');

  const { searchParams } = new URL(request.url);
  const token_hash = searchParams.get('token_hash');
  const type = searchParams.get('type');
  
  console.log('📋 Parâmetros recebidos:');
  console.log('   token_hash:', token_hash ? `***${token_hash.slice(-6)}` : 'ausente');
  console.log('   type:', type);

  if (!token_hash || !type) {
    console.error('❌ Token ou type ausente');
    return NextResponse.redirect(new URL('/error?message=invalid-link', request.url));
  }

  try {
    const cookieStore = await cookies();
    const supabase = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
      {
        cookies: {
          get(name: string) {
            return cookieStore.get(name)?.value;
          },
          set(name: string, value: string, options: any) {
            try {
              cookieStore.set({ name, value, ...options });
            } catch (error) {
              console.error(`Erro ao salvar cookie:`, error);
            }
          },
          remove(name: string, options: any) {
            try {
              cookieStore.delete({ name, ...options });
            } catch (error) {
              console.error(`Erro ao remover cookie:`, error);
            }
          },
        },
      }
    );

    console.log('🔐 Verificando token...');

    const { error } = await supabase.auth.verifyOtp({
      token_hash,
      type: type as 'magiclink' | 'recovery' | 'email' | 'signup',
    });

    if (error) {
      console.error('❌ Erro:', error);
      return NextResponse.redirect(
        new URL(`/error?message=${encodeURIComponent(error.message)}`, request.url)
      );
    }

    console.log('✅ Verificação bem-sucedida!');

    const redirect_to = type === 'recovery' ? '/tickets/change-password' : '/tickets';
    
    console.log('📍 Redirecionando para:', redirect_to);

    return NextResponse.redirect(new URL(redirect_to, request.url));

  } catch (error: any) {
    console.error('💥 Erro:', error);
    return NextResponse.redirect(
      new URL('/error?message=verification-failed', request.url)
    );
  }
}