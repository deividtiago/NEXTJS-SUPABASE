CREATE OR REPLACE FUNCTION public.check_email_exists(user_email TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    recent_attempts INTEGER;
    email_exists BOOLEAN;
    user_id_exists UUID;
BEGIN
    -- 🛡️ RATE LIMITING: Máximo 3 tentativas por hora por IP + Email
    SELECT COUNT(*) INTO recent_attempts
    FROM auth_audit_logs 
    WHERE ip_address = inet_client_addr()
      AND email = user_email
      AND action IN ('password_reset_request', 'password_reset_attempt_invalid_email')
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
                'time_window', '1 hour',
                'max_attempts', 3
            )
        );
        
        RAISE LOG 'Rate limit exceeded: too many password reset attempts for email % from IP %', user_email, inet_client_addr();
        RETURN FALSE;
    END IF;

    -- ✅ VERIFICAR SE EMAIL EXISTE E ESTÁ CONFIRMADO
    SELECT id INTO user_id_exists
    FROM auth.users 
    WHERE email = user_email
      AND confirmed_at IS NOT NULL;

    email_exists := (user_id_exists IS NOT NULL);

    -- Registrar a tentativa
    INSERT INTO public.auth_audit_logs (
        user_id,
        email, 
        action, 
        ip_address, 
        user_agent, 
        details
    ) VALUES (
        user_id_exists,
        user_email,
        CASE 
            WHEN email_exists THEN 'password_reset_request' 
            ELSE 'password_reset_attempt_invalid_email'
        END,
        inet_client_addr(),
        current_setting('request.headers', true)::json->>'user-agent',
        json_build_object(
            'email_exists', email_exists,
            'user_agent', current_setting('request.headers', true)::json->>'user-agent',
            'rate_limit_info', json_build_object(
                'recent_attempts', recent_attempts + 1,
                'max_attempts', 3,
                'time_window', '1 hour'
            )
        )
    );

    RETURN email_exists;
END;
$$;