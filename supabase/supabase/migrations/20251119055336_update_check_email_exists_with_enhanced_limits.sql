-- File: supabase/migrations/20251119000003_update_check_email_exists_with_enhanced_limits.sql
-- Migration: Atualizar função check_email_exists para usar novo sistema de rate limiting

CREATE OR REPLACE FUNCTION public.check_email_exists(user_email TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    user_exists BOOLEAN;
    rate_limit_result RECORD;
    client_ip TEXT;
BEGIN
    -- Obter IP do cliente
    client_ip := inet_client_addr()::TEXT;
    
    -- ✅ VERIFICAR RATE LIMIT SERVER-SIDE ROBUSTO
    SELECT * FROM public.check_password_reset_rate_limit(
        user_email, 
        client_ip
    ) INTO rate_limit_result;
    
    IF NOT rate_limit_result.allowed THEN
        RAISE LOG 'Rate limit exceeded for password reset: email=%, ip=%, reason=%', 
            user_email, client_ip, rate_limit_result.reason;
        RETURN FALSE;
    END IF;

    -- ✅ QUERY SEGURA - apenas usuários confirmados
    SELECT EXISTS(
        SELECT 1 FROM auth.users 
        WHERE email = user_email
          AND confirmed_at IS NOT NULL
    ) INTO user_exists;

    RETURN user_exists;
END;
$$;