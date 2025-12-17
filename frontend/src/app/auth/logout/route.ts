// app/logout/route.ts
import { getSupabaseCookiesUtilClient } from "@/supabase-utils/cookiesUtilClient";
import { NextRequest, NextResponse } from "next/server";

export async function POST(request: NextRequest) {
  console.log('\n🚪 ========================================');
  console.log('LOGOUT - SERVER-SIDE');
  console.log('========================================');

  try {
    const supabase = await getSupabaseCookiesUtilClient();

    // Obter usuário ANTES do logout (para logs)
    const { data: { user } } = await supabase.auth.getUser();
    
    if (user) {
      console.log(`👤 Realizando logout de: ${user.email}`);
    }

    // Executar logout no servidor
    const { error } = await supabase.auth.signOut();

    if (error) {
      console.error('❌ Erro no logout:', error);
      return NextResponse.json(
        { success: false, error: error.message },
        { status: 500 }
      );
    }

    console.log('✅ Logout bem-sucedido');
    
    return NextResponse.json({ 
      success: true,
      message: 'Logout realizado com sucesso'
    });

  } catch (error: any) {
    console.error('💥 Erro inesperado:', error);
    
    return NextResponse.json(
      { success: false, error: 'Erro interno no servidor' },
      { status: 500 }
    );
  }
}

// Manter GET para compatibilidade (caso algo ainda use)
export async function GET(request: NextRequest) {
  console.log('⚠️  GET /logout chamado - considere migrar para POST');
  
  try {
    const supabase = await getSupabaseCookiesUtilClient();
    await supabase.auth.signOut();
    
    return NextResponse.redirect(new URL("/login", request.url));
  } catch (error) {
    console.error('Erro no GET logout:', error);
    return NextResponse.redirect(new URL("/login?error=logout_failed", request.url));
  }
}