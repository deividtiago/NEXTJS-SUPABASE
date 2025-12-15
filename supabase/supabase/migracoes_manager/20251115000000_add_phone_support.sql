-- Migration: Adicionar suporte a telefone
-- File: supabase/migrations/20251115000000_add_phone_support.sql

-- 1. Adicionar coluna de telefone na tabela manager (se necessário)
ALTER TABLE public.manager 
ADD COLUMN IF NOT EXISTS user_phone TEXT;

-- 2. Criar índice para performance
CREATE INDEX IF NOT EXISTS idx_manager_user_phone 
ON public.manager(user_phone);

-- 3. Criar função para sincronizar telefone do usuário
CREATE OR REPLACE FUNCTION public.sync_user_phone()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.user_id IS NOT NULL THEN
        NEW.user_phone = (
            SELECT phone 
            FROM auth.users 
            WHERE id = NEW.user_id
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 4. Criar trigger para sincronizar telefone
DROP TRIGGER IF EXISTS sync_phone_on_insert ON public.manager;
CREATE TRIGGER sync_phone_on_insert
    BEFORE INSERT ON public.manager
    FOR EACH ROW
    EXECUTE FUNCTION public.sync_user_phone();

DROP TRIGGER IF EXISTS sync_phone_on_update ON public.manager;
CREATE TRIGGER sync_phone_on_update
    BEFORE UPDATE OF user_id ON public.manager
    FOR EACH ROW
    EXECUTE FUNCTION public.sync_user_phone();

-- 5. Atualizar telefones existentes (se houver dados)
UPDATE public.manager m
SET user_phone = (
    SELECT phone 
    FROM auth.users u 
    WHERE u.id = m.user_id
)
WHERE user_id IS NOT NULL;

-- 6. Comentários
COMMENT ON COLUMN public.manager.user_phone IS 'Telefone do usuário sincronizado de auth.users';