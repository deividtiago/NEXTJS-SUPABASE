-- Cria a tabela para armazenar os code_verifiers
CREATE TABLE IF NOT EXISTS public.auth_verifiers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() + INTERVAL '10 minutes',
    
    -- Índices para performance
    CONSTRAINT auth_verifiers_email_idx UNIQUE (email)
);

-- Habilita RLS (Row Level Security)
ALTER TABLE public.auth_verifiers ENABLE ROW LEVEL SECURITY;

-- Política: apenas o próprio usuário pode ver seus verifiers (opcional)
CREATE POLICY "Users can view their own verifiers" 
    ON public.auth_verifiers 
    FOR SELECT 
    USING (true); -- Ou usando auth.uid() se quiser mais segurança

-- Política para inserção
CREATE POLICY "Anyone can insert verifiers" 
    ON public.auth_verifiers 
    FOR INSERT 
    WITH CHECK (true);

-- Política para deleção
CREATE POLICY "Anyone can delete expired verifiers" 
    ON public.auth_verifiers 
    FOR DELETE 
    USING (true);