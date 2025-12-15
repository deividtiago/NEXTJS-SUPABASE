-- Migration: Corrigir manager table - adicionar user_id de volta
-- File: supabase/migrations/20251114094710_alter_manager_to_email2.sql

-- Passo 1: REMOVER TODAS AS POLICIES PRIMEIRO (CRÍTICO!)
DROP POLICY IF EXISTS "Users can view their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can insert their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can update their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can delete their own tasks" ON public.manager;

-- Passo 2: Verificar e adicionar user_email se não existir
ALTER TABLE public.manager 
ADD COLUMN IF NOT EXISTS user_email TEXT;

-- Passo 3: Adicionar coluna user_id de volta (se não existir)
ALTER TABLE public.manager 
ADD COLUMN IF NOT EXISTS user_id UUID;

-- Passo 4: Preencher user_id com base no user_email (se user_email existir e tiver dados)
DO $$ 
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'manager' AND column_name = 'user_email'
        AND EXISTS (SELECT 1 FROM public.manager WHERE user_email IS NOT NULL)
    ) THEN
        UPDATE public.manager 
        SET user_id = (
            SELECT id 
            FROM auth.users 
            WHERE auth.users.email = manager.user_email
        )
        WHERE user_id IS NULL AND user_email IS NOT NULL;
    END IF;
END $$;

-- Passo 5: Se não houver dados, não tornar obrigatório ainda
-- (isso permite que você adicione dados manualmente se necessário)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.manager WHERE user_id IS NOT NULL) THEN
        ALTER TABLE public.manager ALTER COLUMN user_id SET NOT NULL;
    END IF;
END $$;

-- Passo 6: Preencher user_email se estiver vazio mas user_id existir
UPDATE public.manager 
SET user_email = (
    SELECT email 
    FROM auth.users 
    WHERE id = manager.user_id
)
WHERE user_email IS NULL AND user_id IS NOT NULL;

-- Passo 7: Adicionar constraint de foreign key
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint 
        WHERE conname = 'manager_user_id_fkey'
    ) THEN
        ALTER TABLE public.manager 
        ADD CONSTRAINT manager_user_id_fkey 
        FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;
    END IF;
END $$;

-- Passo 8: Recriar índice
CREATE INDEX IF NOT EXISTS idx_manager_user_id ON public.manager(user_id);

-- Passo 9: Recriar políticas usando user_id (mais eficiente)
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

-- Passo 10: Criar trigger para manter user_email sincronizado
CREATE OR REPLACE FUNCTION public.sync_manager_user_email()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.user_id IS NOT NULL THEN
        NEW.user_email = (
            SELECT email 
            FROM auth.users 
            WHERE id = NEW.user_id
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS sync_user_email ON public.manager;
CREATE TRIGGER sync_user_email
    BEFORE INSERT OR UPDATE OF user_id ON public.manager
    FOR EACH ROW
    EXECUTE FUNCTION public.sync_manager_user_email();

-- Passo 11: Atualizar comentários
COMMENT ON COLUMN public.manager.user_id IS 'Foreign key to auth.users - ensures task belongs to specific user';
COMMENT ON COLUMN public.manager.user_email IS 'User email - kept in sync with user_id for convenience';

-- Passo 12: Tornar user_id obrigatório se ainda não for
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.manager WHERE user_id IS NULL) THEN
        ALTER TABLE public.manager ALTER COLUMN user_id SET NOT NULL;
    END IF;
END $$;