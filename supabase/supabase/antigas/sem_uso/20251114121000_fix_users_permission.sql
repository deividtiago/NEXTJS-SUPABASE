-- Migration: Corrigir erro de permissão "permission denied for table users"
-- File: supabase/migrations/20251114121000_fix_users_permission.sql

-- PROBLEMA: O trigger sync_manager_user_email() está tentando acessar auth.users
-- mas não tem permissão. SOLUÇÃO: Remover completamente user_email ou usar função segura.

-- OPÇÃO 1: Remover completamente user_email (RECOMENDADO)
-- Esta é a solução mais simples e segura

-- 1. Remover trigger e função problemáticos
DROP TRIGGER IF EXISTS sync_user_email ON public.manager;
DROP FUNCTION IF EXISTS public.sync_manager_user_email();

-- 2. Remover a coluna user_email (não é necessária)
ALTER TABLE public.manager 
DROP COLUMN IF EXISTS user_email;

-- 3. Garantir que user_id seja obrigatório
ALTER TABLE public.manager 
ALTER COLUMN user_id SET NOT NULL;

-- 4. Recriar constraint de foreign key
ALTER TABLE public.manager 
DROP CONSTRAINT IF EXISTS manager_user_id_fkey;

ALTER TABLE public.manager 
ADD CONSTRAINT manager_user_id_fkey 
FOREIGN KEY (user_id) 
REFERENCES auth.users(id) 
ON DELETE CASCADE;

-- 5. Remover e recriar policies
DROP POLICY IF EXISTS "Users can view their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can insert their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can update their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can delete their own tasks" ON public.manager;

-- 6. Criar policies corretas
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
    USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own tasks"
    ON public.manager
    FOR DELETE
    USING (auth.uid() = user_id);

-- 7. Garantir que RLS está habilitado
ALTER TABLE public.manager ENABLE ROW LEVEL SECURITY;

-- 8. Garantir permissões corretas
GRANT USAGE ON SCHEMA public TO authenticated;
GRANT ALL ON public.manager TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE public.manager_id_seq TO authenticated;

-- 9. Recriar índices
CREATE INDEX IF NOT EXISTS idx_manager_user_id ON public.manager(user_id);
CREATE INDEX IF NOT EXISTS idx_manager_created_at ON public.manager(created_at DESC);

-- 10. Garantir que o trigger updated_at existe e funciona
CREATE OR REPLACE FUNCTION public.handle_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS set_updated_at ON public.manager;
CREATE TRIGGER set_updated_at
    BEFORE UPDATE ON public.manager
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_updated_at();

-- 11. Verificar estrutura final
COMMENT ON TABLE public.manager IS 'Task management table with user isolation via RLS';
COMMENT ON COLUMN public.manager.user_id IS 'Required: User ID from auth.users';
COMMENT ON COLUMN public.manager.titulo IS 'Required: Task title';
COMMENT ON COLUMN public.manager.descricao IS 'Optional: Task description';
COMMENT ON COLUMN public.manager.concluida IS 'Task completion status (default: false)';

-- 12. Mensagem de sucesso
DO $$
BEGIN
    RAISE NOTICE '✅ Migration concluída com sucesso!';
    RAISE NOTICE '✅ Coluna user_email removida (não era necessária)';
    RAISE NOTICE '✅ Trigger problemático removido';
    RAISE NOTICE '✅ Permissões corrigidas';
    RAISE NOTICE '✅ Agora você pode inserir tarefas normalmente!';
END $$;