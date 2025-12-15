-- Migration: Corrigir manager table restaurando user_id e mantendo user_email
-- File: supabase/migrations/20251114092637_fix_manager_user_id.sql

-- Passo 1: Remover políticas RLS atuais
DROP POLICY IF EXISTS "Users can view their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can insert their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can update their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can delete their own tasks" ON public.manager;

-- Passo 2: Adicionar coluna user_id de volta (se não existir)
ALTER TABLE public.manager 
ADD COLUMN IF NOT EXISTS user_id UUID;

-- Passo 3: Preencher user_id com base no email dos usuários
UPDATE public.manager 
SET user_id = (
    SELECT id 
    FROM auth.users 
    WHERE auth.users.email = manager.user_email
)
WHERE user_id IS NULL;

-- Passo 4: Adicionar constraint de foreign key
ALTER TABLE public.manager 
ADD CONSTRAINT manager_user_id_fkey 
FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;

-- Passo 5: Tornar user_id obrigatório
ALTER TABLE public.manager 
ALTER COLUMN user_id SET NOT NULL;

-- Passo 6: Recriar índices para ambas as colunas
CREATE INDEX IF NOT EXISTS idx_manager_user_id ON public.manager(user_id);
CREATE INDEX IF NOT EXISTS idx_manager_user_email ON public.manager(user_email);

-- Passo 7: Recriar políticas RLS que funcionam com ambas as colunas
-- Política usando user_id (mais eficiente)
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

-- Passo 8: Atualizar comentários
COMMENT ON COLUMN public.manager.user_id IS 'Foreign key to auth.users - ensures task belongs to specific user';
COMMENT ON COLUMN public.manager.user_email IS 'User email - alternative identifier for tasks';
COMMENT ON COLUMN public.manager.id IS 'Primary key - task identifier';

-- Passo 9: Criar função para sincronizar user_id e user_email automaticamente
CREATE OR REPLACE FUNCTION public.sync_manager_user_email()
RETURNS TRIGGER AS $$
BEGIN
    -- Se user_id foi alterado, atualiza user_email
    IF NEW.user_id IS NOT NULL AND (OLD.user_id IS NULL OR NEW.user_id != OLD.user_id) THEN
        NEW.user_email := (SELECT email FROM auth.users WHERE id = NEW.user_id);
    -- Se user_email foi alterado, atualiza user_id
    ELSIF NEW.user_email IS NOT NULL AND (OLD.user_email IS NULL OR NEW.user_email != OLD.user_email) THEN
        NEW.user_id := (SELECT id FROM auth.users WHERE email = NEW.user_email);
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Passo 10: Criar trigger para sincronização automática
DROP TRIG IF EXISTS sync_manager_emails ON public.manager;
CREATE TRIGGER sync_manager_emails
    BEFORE INSERT OR UPDATE ON public.manager
    FOR EACH ROW
    EXECUTE FUNCTION public.sync_manager_user_email();