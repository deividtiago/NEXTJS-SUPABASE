-- Script 1: Correção completa das políticas e sincronização
-- File: fix_manager_policies_and_sync.sql

-- 1. Remover políticas existentes para recriar corretamente
DROP POLICY IF EXISTS "Users can view their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can insert their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can update their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can delete their own tasks" ON public.manager;

-- 2. Criar função para garantir user_id sempre preenchido
CREATE OR REPLACE FUNCTION public.ensure_manager_user_id()
RETURNS TRIGGER AS $$
BEGIN
    -- SEMPRE definir user_id com o usuário autenticado
    NEW.user_id = auth.uid();
    
    -- Sincronizar user_email com base no user_id
    IF NEW.user_id IS NOT NULL THEN
        NEW.user_email = (
            SELECT email 
            FROM auth.users 
            WHERE id = NEW.user_id
        );
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3. Criar função para sincronizar user_email em updates
CREATE OR REPLACE FUNCTION public.sync_manager_user_email()
RETURNS TRIGGER AS $$
BEGIN
    -- Se user_id mudar, atualizar user_email automaticamente
    IF NEW.user_id IS NOT NULL AND (OLD.user_id IS NULL OR NEW.user_id != OLD.user_id) THEN
        NEW.user_email = (
            SELECT email 
            FROM auth.users 
            WHERE id = NEW.user_id
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 4. Aplicar triggers
DROP TRIGGER IF EXISTS ensure_user_id_on_insert ON public.manager;
CREATE TRIGGER ensure_user_id_on_insert
    BEFORE INSERT ON public.manager
    FOR EACH ROW
    EXECUTE FUNCTION public.ensure_manager_user_id();

DROP TRIGGER IF EXISTS sync_user_email_on_update ON public.manager;
CREATE TRIGGER sync_user_email_on_update
    BEFORE UPDATE ON public.manager
    FOR EACH ROW
    EXECUTE FUNCTION public.sync_manager_user_email();

-- 5. Recriar políticas RLS corretamente
CREATE POLICY "Users can view their own tasks"
    ON public.manager
    FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own tasks"
    ON public.manager
    FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own tasks"
    ON public.manager
    FOR UPDATE
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can delete their own tasks"
    ON public.manager
    FOR DELETE
    USING (auth.uid() = user_id);

-- 6. Garantir que o RLS está ativado
ALTER TABLE public.manager ENABLE ROW LEVEL SECURITY;

-- 7. Recriar índices para performance
DROP INDEX IF EXISTS idx_manager_user_id;
CREATE INDEX idx_manager_user_id ON public.manager(user_id);

DROP INDEX IF EXISTS idx_manager_user_email;
CREATE INDEX idx_manager_user_email ON public.manager(user_email);

-- 8. Atualizar comentários
COMMENT ON TABLE public.manager IS 'Tabela de gerenciamento de tarefas com sincronização user_id/user_email';
COMMENT ON COLUMN public.manager.user_id IS 'ID do usuário (UUID) - usado para RLS';
COMMENT ON COLUMN public.manager.user_email IS 'Email do usuário - sincronizado automaticamente';