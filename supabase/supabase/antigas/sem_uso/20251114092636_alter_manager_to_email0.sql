-- Migration: Alterar manager table de user_id para user_email
-- File: supabase/migrations/20251114092636_alter_manager_to_email1.sql

-- Passo 1: Remover políticas RLS antigas PRIMEIRO
DROP POLICY IF EXISTS "Users can view their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can insert their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can update their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can delete their own tasks" ON public.manager;

-- Passo 2: Adicionar coluna user_email (se não existir)
ALTER TABLE public.manager 
ADD COLUMN IF NOT EXISTS user_email TEXT;

-- Passo 3: Verificar se a coluna user_id existe antes de tentar usá-la
DO $$ 
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'manager' AND column_name = 'user_id') THEN
        -- Preencher user_email com base no user_id existente
        UPDATE public.manager 
        SET user_email = (
            SELECT email 
            FROM auth.users 
            WHERE auth.users.id = manager.user_id
        )
        WHERE user_email IS NULL;
    END IF;
END $$;

-- Passo 4: Tornar user_email obrigatório
ALTER TABLE public.manager 
ALTER COLUMN user_email SET NOT NULL;

-- Passo 5: Criar índice na nova coluna
CREATE INDEX IF NOT EXISTS idx_manager_user_email ON public.manager(user_email);

-- Passo 6: Recriar políticas usando email
CREATE POLICY "Users can view their own tasks"
    ON public.manager
    FOR SELECT
    USING (auth.jwt() ->> 'email' = user_email);

CREATE POLICY "Users can insert their own tasks"
    ON public.manager
    FOR INSERT
    WITH CHECK (auth.jwt() ->> 'email' = user_email);

CREATE POLICY "Users can update their own tasks"
    ON public.manager
    FOR UPDATE
    USING (auth.jwt() ->> 'email' = user_email)
    WITH CHECK (auth.jwt() ->> 'email' = user_email);

CREATE POLICY "Users can delete their own tasks"
    ON public.manager
    FOR DELETE
    USING (auth.jwt() ->> 'email' = user_email);

-- Passo 7: Remover índice antigo (se existir)
DROP INDEX IF EXISTS idx_manager_user_id;

-- Passo 8: Remover a constraint de foreign key se existir
ALTER TABLE public.manager 
DROP CONSTRAINT IF EXISTS manager_user_id_fkey;

-- Passo 9: Remover a coluna user_id (se existir)
ALTER TABLE public.manager 
DROP COLUMN IF EXISTS user_id;

-- Passo 10: Atualizar comentários
COMMENT ON COLUMN public.manager.user_email IS 'User email - ensures task belongs to specific user';
COMMENT ON COLUMN public.manager.id IS 'Primary key - task identifier';