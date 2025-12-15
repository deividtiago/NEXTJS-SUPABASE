-- File: supabase/migrations/20251119000002_enhanced_server_side_rate_limiting.sql
-- Migration: Sistema robusto de rate limiting server-side

-- Tabela para controle de rate limiting
CREATE TABLE IF NOT EXISTS public.rate_limits (
    id BIGSERIAL PRIMARY KEY,
    identifier TEXT NOT NULL, -- IP, email, user_id, ou fingerprint
    action_type TEXT NOT NULL, -- 'login_attempt', 'password_reset', 'signup'
    attempt_count INTEGER DEFAULT 1,
    first_attempt TIMESTAMPTZ DEFAULT NOW(),
    last_attempt TIMESTAMPTZ DEFAULT NOW(),
    is_blocked BOOLEAN DEFAULT FALSE,
    block_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    -- Índices para performance
    CONSTRAINT unique_identifier_action UNIQUE(identifier, action_type)
);

-- Índices para performance
CREATE INDEX IF NOT EXISTS idx_rate_limits_identifier ON public.rate_limits(identifier);
CREATE INDEX IF NOT EXISTS idx_rate_limits_action_type ON public.rate_limits(action_type);
CREATE INDEX IF NOT EXISTS idx_rate_limits_block_until ON public.rate_limits(block_until);
CREATE INDEX IF NOT EXISTS idx_rate_limits_created_at ON public.rate_limits(created_at);

-- Habilitar RLS
ALTER TABLE public.rate_limits ENABLE ROW LEVEL SECURITY;

-- Apenas o sistema pode acessar a tabela de rate limits
CREATE POLICY "System only access to rate_limits" ON public.rate_limits
    FOR ALL USING (false); -- Ninguém pode acessar diretamente

-- Função principal de rate limiting
CREATE OR REPLACE FUNCTION public.check_rate_limit(
    p_identifier TEXT,
    p_action_type TEXT,
    p_max_attempts INTEGER DEFAULT 5,
    p_time_window_minutes INTEGER DEFAULT 15,
    p_block_duration_minutes INTEGER DEFAULT 30
)
RETURNS TABLE(
    allowed BOOLEAN,
    remaining_attempts INTEGER,
    reset_time TIMESTAMPTZ,
    block_until TIMESTAMPTZ,
    reason TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_record public.rate_limits;
    v_now TIMESTAMPTZ := NOW();
    v_reset_time TIMESTAMPTZ;
    v_remaining_attempts INTEGER;
BEGIN
    -- Buscar ou criar registro
    INSERT INTO public.rate_limits (identifier, action_type)
    VALUES (p_identifier, p_action_type)
    ON CONFLICT (identifier, action_type) 
    DO UPDATE SET 
        attempt_count = CASE 
            WHEN rate_limits.first_attempt < (v_now - (p_time_window_minutes || ' minutes')::INTERVAL)
            THEN 1
            ELSE rate_limits.attempt_count + 1
        END,
        first_attempt = CASE 
            WHEN rate_limits.first_attempt < (v_now - (p_time_window_minutes || ' minutes')::INTERVAL)
            THEN v_now
            ELSE rate_limits.first_attempt
        END,
        last_attempt = v_now,
        is_blocked = CASE 
            WHEN rate_limits.block_until IS NOT NULL AND rate_limits.block_until > v_now
            THEN true
            WHEN (rate_limits.attempt_count + 1) >= p_max_attempts
            THEN true
            ELSE false
        END,
        block_until = CASE 
            WHEN rate_limits.block_until IS NOT NULL AND rate_limits.block_until > v_now
            THEN rate_limits.block_until
            WHEN (rate_limits.attempt_count + 1) >= p_max_attempts
            THEN v_now + (p_block_duration_minutes || ' minutes')::INTERVAL
            ELSE NULL
        END
    RETURNING * INTO v_record;

    -- Calcular valores de retorno
    v_reset_time := v_record.first_attempt + (p_time_window_minutes || ' minutes')::INTERVAL;
    v_remaining_attempts := GREATEST(0, p_max_attempts - v_record.attempt_count);

    -- Verificar se está bloqueado
    IF v_record.is_blocked AND v_record.block_until > v_now THEN
        RETURN QUERY SELECT 
            false, 
            0, 
            v_reset_time,
            v_record.block_until,
            'blocked'::TEXT;
        RETURN;
    END IF;

    -- Verificar se excedeu o limite
    IF v_record.attempt_count >= p_max_attempts THEN
        RETURN QUERY SELECT 
            false, 
            0, 
            v_reset_time,
            v_record.block_until,
            'rate_limit_exceeded'::TEXT;
        RETURN;
    END IF;

    -- Permitir a ação
    RETURN QUERY SELECT 
        true, 
        v_remaining_attempts, 
        v_reset_time,
        NULL::TIMESTAMPTZ,
        'allowed'::TEXT;

END;
$$;

-- Função específica para login attempts
CREATE OR REPLACE FUNCTION public.check_login_rate_limit(
    p_email TEXT,
    p_ip_address TEXT
)
RETURNS TABLE(
    allowed BOOLEAN,
    remaining_attempts INTEGER,
    reset_time TIMESTAMPTZ,
    block_until TIMESTAMPTZ,
    reason TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Aplicar rate limit por IP (mais restritivo)
    RETURN QUERY 
    SELECT * FROM public.check_rate_limit(
        p_identifier := 'ip_' || p_ip_address,
        p_action_type := 'login_attempt',
        p_max_attempts := 5,        -- 5 tentativas
        p_time_window_minutes := 15, -- em 15 minutos
        p_block_duration_minutes := 30 -- bloquear por 30 minutos
    );
END;
$$;

-- Função específica para password reset
CREATE OR REPLACE FUNCTION public.check_password_reset_rate_limit(
    p_email TEXT,
    p_ip_address TEXT
)
RETURNS TABLE(
    allowed BOOLEAN,
    remaining_attempts INTEGER,
    reset_time TIMESTAMPTZ,
    block_until TIMESTAMPTZ,
    reason TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Aplicar rate limit por email (evitar spam para mesmo email)
    RETURN QUERY 
    SELECT * FROM public.check_rate_limit(
        p_identifier := 'email_' || p_email,
        p_action_type := 'password_reset',
        p_max_attempts := 3,        -- 3 tentativas
        p_time_window_minutes := 60, -- em 60 minutos
        p_block_duration_minutes := 120 -- bloquear por 2 horas
    );
END;
$$;

-- Função específica para signup
CREATE OR REPLACE FUNCTION public.check_signup_rate_limit(
    p_ip_address TEXT
)
RETURNS TABLE(
    allowed BOOLEAN,
    remaining_attempts INTEGER,
    reset_time TIMESTAMPTZ,
    block_until TIMESTAMPTZ,
    reason TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Aplicar rate limit por IP para signups
    RETURN QUERY 
    SELECT * FROM public.check_rate_limit(
        p_identifier := 'ip_' || p_ip_address,
        p_action_type := 'signup',
        p_max_attempts := 3,        -- 3 cadastros
        p_time_window_minutes := 60, -- em 60 minutos
        p_block_duration_minutes := 120 -- bloquear por 2 horas
    );
END;
$$;

-- Função para limpar rate limits antigos (manutenção)
CREATE OR REPLACE FUNCTION public.cleanup_old_rate_limits()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM public.rate_limits 
    WHERE created_at < (NOW() - INTERVAL '7 days'); -- Manter apenas 7 dias
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$;

-- Comentários para documentação
COMMENT ON TABLE public.rate_limits IS 
'Sistema centralizado de rate limiting server-side.
Controla tentativas de login, password reset e signup por IP/email.';

COMMENT ON FUNCTION public.check_rate_limit IS 
'Função principal de rate limiting com bloqueio automático.
Retorna status, tentativas restantes e tempo de reset.';

COMMENT ON FUNCTION public.cleanup_old_rate_limits IS 
'Limpa registros de rate limits antigos (mais de 7 dias) para manutenção.';