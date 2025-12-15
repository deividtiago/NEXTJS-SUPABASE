-- Migration: Adicionar rate limiting simples para password reset
-- Objetivo: Prevenir abuso sem complicação excessiva

-- ✅ FUNÇÃO SIMPLES com rate limiting
CREATE OR REPLACE FUNCTION public.check_email_exists(user_email TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    recent_attempts INTEGER;
BEGIN
    -- 🛡️ RATE LIMITING BÁSICO: Máximo 3 tentativas por hora por IP
    SELECT COUNT(*) INTO recent_attempts
    FROM auth_audit_logs 
    WHERE ip_address = inet_client_addr()
      AND action = 'password_reset_request'
      AND created_at > (NOW() - INTERVAL '1 hour');
    
    IF recent_attempts >= 3 THEN
        RAISE LOG 'Rate limit exceeded: too many password reset attempts from IP %', inet_client_addr();
        RETURN FALSE;
    END IF;

    -- ✅ QUERY SEGURA E SIMPLES
    RETURN EXISTS(
        SELECT 1 FROM auth.users 
        WHERE email = user_email
          AND confirmed_at IS NOT NULL
    );
END;
$$;