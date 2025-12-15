
-- ========================================
-- MIGRATION ÚNICA: Correção da tabela auth_verifiers
-- ========================================

-- 1. Remove a constraint única se existir (causa problemas com emails duplicados)
DO $$ 
BEGIN
    -- Tenta remover a constraint única pelo nome conhecido
    BEGIN
        ALTER TABLE public.auth_verifiers 
        DROP CONSTRAINT IF EXISTS auth_verifiers_email_idx;
        RAISE NOTICE 'Constraint única auth_verifiers_email_idx removida';
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'Constraint auth_verifiers_email_idx não encontrada ou já removida: %', SQLERRM;
    END;

    -- Tenta remover por qualquer constraint única na coluna email
    BEGIN
        EXECUTE (
            SELECT 'ALTER TABLE public.auth_verifiers DROP CONSTRAINT IF EXISTS ' || conname || ' CASCADE'
            FROM pg_constraint 
            WHERE conrelid = 'public.auth_verifiers'::regclass
            AND conkey = ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid = 'public.auth_verifiers'::regclass AND attname = 'email')]
            AND contype = 'u'
            LIMIT 1
        );
        RAISE NOTICE 'Qualquer constraint única na coluna email removida';
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'Nenhuma constraint única na coluna email encontrada: %', SQLERRM;
    END;
END $$;

-- 2. Remove índices antigos se existirem
DROP INDEX IF EXISTS public.auth_verifiers_email_idx;
DROP INDEX IF EXISTS public.idx_auth_verifiers_email;

-- 3. Cria índices otimizados
CREATE INDEX IF NOT EXISTS idx_auth_verifiers_email 
ON public.auth_verifiers(email);

CREATE INDEX IF NOT EXISTS idx_auth_verifiers_expires_at 
ON public.auth_verifiers(expires_at);

CREATE INDEX IF NOT EXISTS idx_auth_verifiers_created_at 
ON public.auth_verifiers(created_at);

-- 4. Adiciona coluna para melhor controle (opcional)
ALTER TABLE public.auth_verifiers 
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

-- 5. Cria função para atualizar updated_at automaticamente
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 6. Cria trigger para atualizar updated_at
DROP TRIGGER IF EXISTS update_auth_verifiers_updated_at ON public.auth_verifiers;
CREATE TRIGGER update_auth_verifiers_updated_at
    BEFORE UPDATE ON public.auth_verifiers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- 7. Limpa registros expirados (manutenção)
DELETE FROM public.auth_verifiers 
WHERE expires_at < NOW() - INTERVAL '1 hour';

-- 8. Atualiza RLS para melhor segurança
DROP POLICY IF EXISTS "Users can view their own verifiers" ON public.auth_verifiers;
DROP POLICY IF EXISTS "Anyone can insert verifiers" ON public.auth_verifiers;
DROP POLICY IF EXISTS "Anyone can delete expired verifiers" ON public.auth_verifiers;

-- Políticas RLS otimizadas
CREATE POLICY "Allow all operations for auth flow" 
ON public.auth_verifiers 
FOR ALL 
USING (true) 
WITH CHECK (true);

-- 9. Adiciona comentários para documentação
COMMENT ON TABLE public.auth_verifiers IS 'Armazena code_verifiers PKCE para autenticação com magic link';
COMMENT ON COLUMN public.auth_verifiers.email IS 'Email do usuário solicitando autenticação';
COMMENT ON COLUMN public.auth_verifiers.code_verifier IS 'Code verifier PKCE (secreto)';
COMMENT ON COLUMN public.auth_verifiers.expires_at IS 'Data de expiração do verifier (10 minutos)';
COMMENT ON COLUMN public.auth_verifiers.created_at IS 'Data de criação do registro';
COMMENT ON COLUMN public.auth_verifiers.updated_at IS 'Data da última atualização';

-- 10. Verificação final da estrutura da tabela
DO $$
DECLARE
    constraint_count integer;
    index_count integer;
BEGIN
    -- Verifica constraints únicas
    SELECT COUNT(*) INTO constraint_count
    FROM pg_constraint 
    WHERE conrelid = 'public.auth_verifiers'::regclass
    AND contype = 'u';
    
    IF constraint_count > 0 THEN
        RAISE WARNING 'Ainda existem % constraints únicas na tabela auth_verifiers', constraint_count;
    ELSE
        RAISE NOTICE '✅ Tabela auth_verifiers não tem constraints únicas (CORRETO)';
    END IF;
    
    -- Verifica índices
    SELECT COUNT(*) INTO index_count
    FROM pg_indexes 
    WHERE tablename = 'auth_verifiers' 
    AND schemaname = 'public';
    
    RAISE NOTICE '✅ Tabela auth_verifiers tem % índices', index_count;
    
    -- Conta registros
    RAISE NOTICE '📊 Total de registros na tabela: %', (SELECT COUNT(*) FROM public.auth_verifiers);
    RAISE NOTICE '🗑️  Registros expirados: %', (SELECT COUNT(*) FROM public.auth_verifiers WHERE expires_at < NOW());
END $$;

-- ========================================
-- FIM DA MIGRATION
-- ========================================
