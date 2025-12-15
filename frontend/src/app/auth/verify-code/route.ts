// app/api/auth/verify-code/route.ts
import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'
import { NextRequest, NextResponse } from 'next/server'

// Função auxiliar para criar um atraso (sleep)
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
// Atraso aleatório entre 100ms e 600ms
const randomDelay = () => Math.floor(Math.random() * 500) + 100; 

export async function POST(request: NextRequest) {
  try {
    const contentType = request.headers.get('content-type');
    
    // 1. Validação de Content-Type (Segurança Básica de API)
    if (!contentType || !contentType.includes('application/json')) {
        await sleep(randomDelay()); // Atraso em caso de requisição malformada
        return NextResponse.json(
            { error: 'Content-Type inválido. Esperado application/json.' },
            { status: 415 } // Unsupported Media Type
        );
    }
    
    const { code } = await request.json()

    console.log('\n🔄 ========================================');
    console.log('SERVER-SIDE CODE VERIFICATION');
    console.log('========================================');
    console.log(`🔑 Código recebido: ${code ? code.substring(0, 10) + '...' : 'Nenhum'}`);
    
    // 2. Validação de Código (Input)
    if (!code || typeof code !== 'string') {
      console.error('❌ Código inválido ou ausente.');
      await sleep(randomDelay()); // Atraso em caso de código ausente
      return NextResponse.json(
        { error: 'Código inválido ou ausente' },
        { status: 400 }
      )
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
              console.error('⚠️ Erro ao salvar cookies de sessão:', error);
            }
          },
        },
      }
    )

    console.log('🔄 Tentando troca de código por sessão...');
    
    // 3. TROCA DO CÓDIGO (Operação Crítica)
    const { data, error } = await supabase.auth.exchangeCodeForSession(code)

    if (error) {
      console.error('❌ Erro na troca de código:', error.message);
      await sleep(randomDelay()); // Atraso em caso de falha na autenticação (Timing Attack Mitigation)
      return NextResponse.json(
        // Retornar erro genérico para não dar dicas a atacantes (Ex: 'Code not found' vs 'Code expired')
        { error: 'Código de autenticação expirado ou inválido. Tente novamente.' }, 
        { status: 401 }
      )
    }

    if (!data.session) {
      console.error('❌ Nenhuma sessão retornada.');
      await sleep(randomDelay()); // Atraso em caso de falha (Timing Attack Mitigation)
      return NextResponse.json(
        { error: 'Falha na autenticação. Nenhuma sessão foi estabelecida.' },
        { status: 401 }
      )
    }

    console.log('✅ Sessão obtida e cookies salvos com sucesso!');
    console.log(`   User: ${data.user.email}`);

    // Retorna sucesso 200 para o cliente (page.tsx)
    return NextResponse.json({ 
      success: true, 
      message: 'Sessão estabelecida com sucesso.' 
    })

  } catch (error: any) {
    console.error('💥 Erro interno no servidor:', error.message);
    await sleep(randomDelay()); // Atraso em caso de erro interno
    return NextResponse.json(
      { error: 'Erro interno no servidor' },
      { status: 500 }
    )
  }
}