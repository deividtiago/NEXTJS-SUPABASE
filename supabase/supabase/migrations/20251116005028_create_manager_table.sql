--Migration: criar tabela "manager" com políticas RLS
-- File: supabase/migrations/YYYYMMDDHHMSS_create_manager_table.sql

-- Criar a tabela manager
CREATE TABLE IF NOT EXISTS public.manager (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    titulo TEXT NOT NULL,
    descricao TEXT,
    concluida BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Criar index para uma melhor performance de query
CREATE INDEX IF NOT EXISTS idx_manager_user_id ON public.manager(user_id);
CREATE INDEX IF NOT EXISTS idx_manager_created_at ON public.manager(created_at DESC);

-- Habilitar ROW LEVEL SECURITY
ALTER TABLE public.manager ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if they exist
DROP POLICY IF EXISTS "Users can view their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can insert their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can update their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can delete their own tasks" ON public.manager;

-- Create RLS Policies
-- Policy: usuarios só podem visualizar suas próprias tarefas
CREATE POLICY "Users can view their own tasks"
    ON public.manager
    FOR SELECT
    USING (auth.uid() = user_id);

-- Policy: Users can only insert tasks for themselves
CREATE POLICY "Users can insert their own tasks"
    ON public.manager
    FOR INSERT
    WITH CHECK (auth.uid() = user_id);

-- Policy: Users can only update their own tasks
CREATE POLICY "Users can update their own tasks"
    ON public.manager   
    FOR UPDATE
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

-- Policy: Users can only delete their own tasks
CREATE POLICY "Users can delete their own tasks"
    ON public.manager
    FOR DELETE
    USING (auth.uid() = user_id);

-- Criar função para fazer update automaticamente updated_at timestamp
CREATE OR REPLACE FUNCTION public.handle_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for updated_at
DROP TRIGGER IF EXISTS set_updated_at ON public.manager;
CREATE TRIGGER set_updated_at
    BEFORE UPDATE ON public.manager
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_updated_at();

-- Create function to check if email exists (for password recovery)
CREATE OR REPLACE FUNCTION public.check_email_exists(user_email TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM auth.users
        WHERE email = user_email
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant necessary permissions
GRANT USAGE ON SCHEMA public TO authenticated;
GRANT ALL ON public.manager TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE public.manager_id_seq TO authenticated;

-- Add comments for documentation
COMMENT ON TABLE public.manager IS 'Task management table with user isolation';
COMMENT ON COLUMN public.manager.user_id IS 'Foreign key to auth.users - ensures task belongs to specific user';
COMMENT ON COLUMN public.manager.titulo IS 'Task title';
COMMENT ON COLUMN public.manager.descricao IS 'Task description';
COMMENT ON COLUMN public.manager.concluida IS 'Task completion status';
COMMENT ON COLUMN public.manager.updated_at IS 'Timestamp of last update'; 