import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'
import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData()
    const email = formData.get('email') as string
    const password = formData.get('password') as string
    
    console.log('\n🔐 ========================================');
    console.log('PASSWORD LOGIN - SERVER-SIDE');
    console.log('========================================');
    console.log(`📧 Email: ${email}`);
    
    if (!email || !password) {
      console.log('❌ Campos obrigatórios faltando');
      // Retorna JSON 400
      return NextResponse.json({ 
        error: 'Campos obrigatórios faltando' 
      }, { status: 400 });
    }

    const cookieStore = await cookies()
    
    const supabase = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
      {
        cookies: {
          getAll() { return cookieStore.getAll() },
          setAll(cookiesToSet) {
            try {
              cookiesToSet.forEach(({ name, value, options }) =>
                cookieStore.set(name, value, options)
              )
            } catch (error) {
              console.error('⚠️ Erro ao salvar cookies:', error);
            }
          },
        },
      }
    )

    console.log('🔄 Tentando autenticar...');
    
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    })

    if (error) {
      console.error('❌ Erro no login:', error.message);
      // Retorna JSON 401
      return NextResponse.json({ 
        error: error.message || 'Erro de autenticação'
      }, { status: 401 });
    }

    if (!data?.user || !data?.session) {
      console.error('❌ Sessão não foi criada');
      // Retorna JSON 401
      return NextResponse.json({ 
        error: 'Erro inesperado: Sessão não foi criada'
      }, { status: 401 });
    }

    console.log('✅ Login bem-sucedido!');
    console.log(`   User: ${data.user.email}`);
    console.log(`   Session: ${data.session.access_token.substring(0, 20)}...`);
    console.log('🍪 Cookies salvos via Supabase SSR');
    
    // CORREÇÃO ESSENCIAL: Retorna JSON de sucesso (200)
    return NextResponse.json({ 
      success: true,
      message: 'Login realizado com sucesso. Redirecionando...'
    }, { status: 200 });

  } catch (error: any) {
    console.error('💥 Erro inesperado:', error);
    // Retorna JSON 500
    return NextResponse.json({ 
      error: 'Erro interno no servidor'
    }, { status: 500 });
  }
}

export async function GET() {
  // A rota de login com senha só deve aceitar POST
  return NextResponse.json({ 
    message: 'Rota de login. Use POST com email e password.',
    status: 'active'
  })
}