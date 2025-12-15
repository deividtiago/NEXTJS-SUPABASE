// src/middleware.ts - TUDO VAI PARA /auth/verify
import { NextRequest, NextResponse } from "next/server";
import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

const PROTECTED_ROUTES = [
  '/tickets',
  '/dashboard', 
  '/profile',
  '/settings',
  '/api/protected'
];

const PUBLIC_ROUTES = [
  '/', 
  '/login', 
  '/register', 
  '/forgot-password',
  '/magic-thanks',
  '/error',
  '/auth',
  '/tickets/change-password',
];

function addSecurityHeaders(response: NextResponse): NextResponse {
  Object.entries(SECURITY_HEADERS).forEach(([key, value]) => {
    response.headers.set(key, value);
  });
  return response;
}

function shouldSkipMiddleware(pathname: string): boolean {
  if (
    pathname.startsWith('/_next/') ||
    pathname.startsWith('/static/') ||
    pathname.includes('.') ||
    pathname === '/favicon.ico'
  ) {
    return true;
  }
  
  for (const publicRoute of PUBLIC_ROUTES) {
    if (pathname === publicRoute || pathname.startsWith(publicRoute + '/')) {
      return true;
    }
  }
  
  return false;
}

export async function middleware(request: NextRequest) {
  const url = new URL(request.url);
  const pathname = url.pathname;
  
  const code = url.searchParams.get('code');
  const token_hash = url.searchParams.get('token_hash');
  const type = url.searchParams.get('type');
  
  console.log(`\n🔍 [MIDDLEWARE] ${request.method} ${pathname}`);
  if (code) console.log(`   🔑 Code detectado: ***${code.slice(-6)}`);
  if (token_hash) console.log(`   🔐 Token_hash detectado: ***${token_hash.slice(-6)}`);
  if (type) console.log(`   📝 Type: ${type}`);
  
  // ========================================
  // FLUXO DE AUTENTICAÇÃO - TUDO PARA /auth/verify
  // ========================================
  
  // Se houver CODE ou TOKEN_HASH → redireciona para /auth/verify
  if ((code || token_hash) && pathname !== '/auth/verify') {
    console.log(`🔄 [AUTH] Redirecionando ${pathname} → /auth/verify`);
    
    const verifyUrl = new URL('/auth/verify', request.url);
    // Usa token_hash se existir, senão usa code
    const tokenValue = token_hash || code || '';
    verifyUrl.searchParams.set('token_hash', tokenValue);
    
    // 🔥 CORREÇÃO: Preservar o type que veio na URL original
    if (type) {
      verifyUrl.searchParams.set('type', type);
    } else {
      verifyUrl.searchParams.set('type', 'magiclink');
    }
    
    const response = NextResponse.redirect(verifyUrl);
    return addSecurityHeaders(response);
  }
  
  // /auth/verify SEMPRE passa direto
  if (pathname === '/auth/verify') {
    console.log(`✅ [AUTH] Permitindo acesso ao handler de autenticação`);
    const response = NextResponse.next();
    return addSecurityHeaders(response);
  }
  
  // ========================================
  // DEMAIS ROTAS
  // ========================================
  
  if (shouldSkipMiddleware(pathname)) {
    const response = NextResponse.next();
    return addSecurityHeaders(response);
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
            // No middleware não modificamos cookies
          },
          remove(name: string, options: any) {
            // No middleware não modificamos cookies
          },
        },
      }
    );
    
    const { data: { session } } = await supabase.auth.getSession();
    const user = session?.user;
    
    console.log(`   👤 Usuário: ${user ? user.email : 'NÃO AUTENTICADO'}`);
    
    const isProtectedRoute = PROTECTED_ROUTES.some(route => 
      pathname === route || pathname.startsWith(route + '/')
    );
    
    if (isProtectedRoute && !user) {
      console.log(`🚫 [AUTH] Redirecionando para /login`);
      
      if (pathname.startsWith('/api/')) {
        return addSecurityHeaders(NextResponse.json(
          { error: 'Não autorizado' },
          { status: 401 }
        ));
      }
      
      const loginUrl = new URL('/login', request.url);
      loginUrl.searchParams.set('redirect', pathname);
      return addSecurityHeaders(NextResponse.redirect(loginUrl));
    }
    
    if (user && (pathname === '/login' || pathname === '/register')) {
      console.log(`↪️ [AUTH] Usuário autenticado, redirecionando para /tickets`);
      return addSecurityHeaders(NextResponse.redirect(new URL('/tickets', request.url)));
    }
    
    const response = NextResponse.next();
    return addSecurityHeaders(response);
    
  } catch (error) {
    console.error('[MIDDLEWARE] Erro:', error);
    const response = NextResponse.next();
    return addSecurityHeaders(response);
  }
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|.*\\.).*)',
  ],
};

export default middleware;