// src/middleware.ts - CORRIGIDO
import { NextRequest, NextResponse } from "next/server";
import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
};

const PROTECTED_ROUTES = [
  '/tickets',
  '/dashboard', 
  '/profile',
  '/settings',
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

// 🔥 VALIDAÇÃO DE REDIRECT NO SERVIDOR
function isSafeRedirectUrl(url: string, baseUrl: string): boolean {
  try {
    const parsed = new URL(url, baseUrl);
    const base = new URL(baseUrl);
    
    // Validar origem
    if (parsed.origin !== base.origin) {
      console.warn('[SECURITY] Blocked external redirect:', url);
      return false;
    }
    
    // Validar protocolo
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      console.warn('[SECURITY] Blocked non-HTTP redirect:', url);
      return false;
    }
    
    // Validar path (prevenir ../)
    if (parsed.pathname.includes('..')) {
      console.warn('[SECURITY] Blocked path traversal:', url);
      return false;
    }
    
    return true;
  } catch {
    console.warn('[SECURITY] Invalid URL:', url);
    return false;
  }
}

function getSafeRedirectPath(request: NextRequest): string {
  const url = new URL(request.url);
  
  const returnUrl = url.searchParams.get('returnUrl') || 
                    url.searchParams.get('redirect') ||
                    url.searchParams.get('return_to');
  
  if (!returnUrl) {
    return '/tickets';
  }
  
  if (!isSafeRedirectUrl(returnUrl, request.url)) {
    console.warn('[SECURITY] Unsafe redirect blocked, using default');
    return '/tickets';
  }
  
  try {
    const parsed = new URL(returnUrl, request.url);
    return parsed.pathname + parsed.search;
  } catch {
    return '/tickets';
  }
}

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
  // FLUXO DE AUTENTICAÇÃO
  // ========================================
  
  if ((code || token_hash) && pathname !== '/auth/verify') {
    console.log(`🔄 [AUTH] Redirecionando ${pathname} → /auth/verify`);
    
    const verifyUrl = new URL('/auth/verify', request.url);
    const tokenValue = token_hash || code || '';
    verifyUrl.searchParams.set('token_hash', tokenValue);
    verifyUrl.searchParams.set('type', type || 'magiclink');
    
    const response = NextResponse.redirect(verifyUrl);
    return addSecurityHeaders(response);
  }
  
  if (pathname === '/auth/verify') {
    console.log(`✅ [AUTH] Permitindo acesso ao handler de autenticação`);
    const response = NextResponse.next();
    return addSecurityHeaders(response);
  }
  
  if (shouldSkipMiddleware(pathname)) {
    const response = NextResponse.next();
    return addSecurityHeaders(response);
  }
  
  // ========================================
  // VALIDAÇÃO DE SESSÃO
  // ========================================
  
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
          set() {},
          remove() {},
        },
      }
    );
    
    // 🔥 CORREÇÃO: Usar getUser() em vez de getSession()
    const { data: { user }, error } = await supabase.auth.getUser();
    
    if (error) {
      console.log(`   ⚠️ Erro ao validar usuário: ${error.message}`);
    }
    
    console.log(`   👤 Usuário: ${user ? user.email : 'NÃO AUTENTICADO'}`);
    
    const isProtectedRoute = PROTECTED_ROUTES.some(route => 
      pathname === route || pathname.startsWith(route + '/')
    );
    
    // ========================================
    // PROTEÇÃO DE ROTAS
    // ========================================
    
    if (isProtectedRoute && !user) {
      console.log(`🚫 [AUTH] Redirecionando para /login`);
      
      const loginUrl = new URL('/login', request.url);
      
      // Validar redirect antes de adicionar
      if (isSafeRedirectUrl(pathname, request.url)) {
        loginUrl.searchParams.set('redirect', pathname);
      }
      
      return addSecurityHeaders(NextResponse.redirect(loginUrl));
    }
    
    // ========================================
    // REDIRECIONAMENTO PÓS-LOGIN
    // ========================================
    
    if (user && (pathname === '/login' || pathname === '/register')) {
      console.log(`↪️ [AUTH] Usuário autenticado, redirecionando`);
      
      const safePath = getSafeRedirectPath(request);
      console.log(`   → Redirecionando para: ${safePath}`);
      
      return addSecurityHeaders(
        NextResponse.redirect(new URL(safePath, request.url))
      );
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