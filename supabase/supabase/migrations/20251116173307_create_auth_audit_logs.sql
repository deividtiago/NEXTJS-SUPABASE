-- Migration: Criar tabela de logs de auditoria para segurança
-- File: supabase/migrations/20241116000002_create_auth_audit_logs.sql

-- Criar tabela de logs de auditoria
CREATE TABLE IF NOT EXISTS public.auth_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    email TEXT, -- Armazenar email mesmo sem user_id para tentativas falhas
    action TEXT NOT NULL,
    ip_address INET,
    user_agent TEXT,
    details JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Índices para performance
CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_user_id ON public.auth_audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_action ON public.auth_audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_created_at ON public.auth_audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_ip_address ON public.auth_audit_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_email ON public.auth_audit_logs(email);

-- Habilitar RLS (Row Level Security)
ALTER TABLE public.auth_audit_logs ENABLE ROW LEVEL SECURITY;

-- Políticas RLS
-- Usuários podem ver apenas seus próprios logs
CREATE POLICY "Users can view own audit logs" ON public.auth_audit_logs
    FOR SELECT USING (auth.uid() = user_id);

-- Serviço pode inserir logs (qualquer operação de auth)
CREATE POLICY "Service can insert audit logs" ON public.auth_audit_logs
    FOR INSERT WITH CHECK (true);

-- Apenas administradores podem ver todos os logs (opcional)
-- CREATE POLICY "Admins can view all audit logs" ON public.auth_audit_logs
--     FOR SELECT USING (auth.jwt() ->> 'email' = 'admin@email.com');

-- Conceder permissões
GRANT USAGE ON SCHEMA public TO authenticated;
GRANT ALL ON public.auth_audit_logs TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE public.auth_audit_logs_id_seq TO authenticated;

-- Comentários para documentação
COMMENT ON TABLE public.auth_audit_logs IS 'Logs de auditoria para eventos de autenticação e segurança';
COMMENT ON COLUMN public.auth_audit_logs.user_id IS 'ID do usuário (NULL para tentativas falhas)';
COMMENT ON COLUMN public.auth_audit_logs.email IS 'Email envolvido na operação';
COMMENT ON COLUMN public.auth_audit_logs.action IS 'Tipo de ação: login_attempt, login_success, login_failed, etc';
COMMENT ON COLUMN public.auth_audit_logs.ip_address IS 'Endereço IP do cliente';
COMMENT ON COLUMN public.auth_audit_logs.user_agent IS 'User agent do navegador';
COMMENT ON COLUMN public.auth_audit_logs.details IS 'Detalhes adicionais do evento em JSON';
COMMENT ON COLUMN public.auth_audit_logs.created_at IS 'Timestamp de quando o evento ocorreu';