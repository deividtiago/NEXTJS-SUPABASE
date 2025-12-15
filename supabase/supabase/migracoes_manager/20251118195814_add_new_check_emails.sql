-- Migration: Adicionar rate limiting simples para password reset
-- Objetivo: Prevenir abuso sem complicação excessiva

-- ✅ FUNÇÃO MELHORADA com rate limiting e registro
CREATE OR REPLACE FUNCTION public.check_email_exists(user_email TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    recent_attempts INTEGER;
    email_exists BOOLEAN;
BEGIN
    -- 🛡️ RATE LIMITING BÁSICO: Máximo 3 tentativas por hora por IP + Email
    SELECT COUNT(*) INTO recent_attempts
    FROM auth_audit_logs 
    WHERE ip_address = inet_client_addr()
      AND email = user_email
      AND action = 'password_reset_request'
      AND created_at > (NOW() - INTERVAL '1 hour');
    
    IF recent_attempts >= 3 THEN
        -- Registrar tentativa bloqueada por rate limit
        INSERT INTO public.auth_audit_logs (
            email, 
            action, 
            ip_address, 
            user_agent, 
            details
        ) VALUES (
            user_email,
            'password_reset_rate_limited',
            inet_client_addr(),
            current_setting('request.headers', true)::json->>'user-agent',
            json_build_object(
                'reason', 'rate_limit_exceeded',
                'recent_attempts', recent_attempts,
                'time_window', '1 hour'
            )
        );
        
        RAISE LOG 'Rate limit exceeded: too many password reset attempts for email % from IP %', user_email, inet_client_addr();
        RETURN FALSE;
    END IF;

    -- ✅ QUERY SEGURA E SIMPLES - verificar se email existe e está confirmado
    SELECT EXISTS(
        SELECT 1 FROM auth.users 
        WHERE email = user_email
          AND confirmed_at IS NOT NULL
    ) INTO email_exists;

    -- Registrar a tentativa (seja sucesso ou falha)
    INSERT INTO public.auth_audit_logs (
        email, 
        action, 
        ip_address, 
        user_agent, 
        details
    ) VALUES (
        user_email,
        CASE 
            WHEN email_exists THEN 'password_reset_request' 
            ELSE 'password_reset_attempt_invalid_email'
        END,
        inet_client_addr(),
        current_setting('request.headers', true)::json->>'user-agent',
        json_build_object(
            'email_exists', email_exists,
            'user_agent', current_setting('request.headers', true)::json->>'user-agent'
        )
    );

    RETURN email_exists;
END;
$$;