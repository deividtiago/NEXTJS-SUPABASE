
-- ✅ Migration para REMOVER a função check_email_exists problemática
-- Ela estava bloqueando ANTES do Supabase tentar enviar o email

-- 1. Dropar função antiga
DROP FUNCTION IF EXISTS public.check_email_exists(TEXT);

-- 2. Criar função SIMPLIFICADA (sem rate limiting)
-- O rate limiting agora é feito no client-side
CREATE OR REPLACE FUNCTION public.check_email_exists(user_email TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- ✅ APENAS verifica se email existe e está confirmado
    -- SEM rate limiting aqui
    RETURN EXISTS(
        SELECT 1 FROM auth.users 
        WHERE email = user_email
          AND confirmed_at IS NOT NULL
    );
END;
$$;

COMMENT ON FUNCTION public.check_email_exists IS 
'Função simplificada - apenas verifica existência do email. Rate limiting movido para client-side.';


-- ============================================
-- QUERY PARA LIMPAR RATE LIMIT (rodar no SQL Editor)
-- ============================================

-- Limpar todos os logs de password reset da última hora
DELETE FROM public.auth_audit_logs 
WHERE action IN ('password_reset_request', 'password_reset_rate_limited', 'password_reset_attempt_invalid_email')
AND created_at > NOW() - INTERVAL '1 hour';

-- Verificar quantos registros restam
SELECT 
    action,
    COUNT(*) as total,
    MAX(created_at) as ultima_tentativa
FROM public.auth_audit_logs 
WHERE action LIKE 'password_reset%'
GROUP BY action;


-- ============================================
-- QUERY PARA VERIFICAR STATUS DO EMAIL
-- ============================================

-- Verificar se o email está confirmado
SELECT 
    email,
    confirmed_at,
    created_at,
    last_sign_in_at,
    CASE 
        WHEN confirmed_at IS NULL THEN '❌ NÃO CONFIRMADO'
        ELSE '✅ CONFIRMADO'
    END as status
FROM auth.users 
WHERE email = 'SEU_EMAIL_AQUI@exemplo.com';
