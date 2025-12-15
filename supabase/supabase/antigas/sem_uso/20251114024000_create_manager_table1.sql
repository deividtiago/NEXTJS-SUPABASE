-- Migration: Create manager table with RLS policies using email
-- File: supabase/migrations/YYYYMMDDHHMMSS_create_manager_table.sql

-- Create the manager table
CREATE TABLE IF NOT EXISTS public.manager (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    user_email TEXT NOT NULL,
    titulo TEXT NOT NULL,
    descricao TEXT,
    concluida BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create index for better query performance
CREATE INDEX IF NOT EXISTS idx_manager_user_email ON public.manager(user_email);
CREATE INDEX IF NOT EXISTS idx_manager_created_at ON public.manager(created_at DESC);

-- Enable Row Level Security
ALTER TABLE public.manager ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if they exist
DROP POLICY IF EXISTS "Users can view their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can insert their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can update their own tasks" ON public.manager;
DROP POLICY IF EXISTS "Users can delete their own tasks" ON public.manager;

-- Create RLS Policies using email
-- Policy: Users can only view their own tasks
CREATE POLICY "Users can view their own tasks"
    ON public.manager
    FOR SELECT
    USING (auth.jwt() ->> 'email' = user_email);

-- Policy: Users can only insert tasks for themselves
CREATE POLICY "Users can insert their own tasks"
    ON public.manager
    FOR INSERT
    WITH CHECK (auth.jwt() ->> 'email' = user_email);

-- Policy: Users can only update their own tasks
CREATE POLICY "Users can update their own tasks"
    ON public.manager
    FOR UPDATE
    USING (auth.jwt() ->> 'email' = user_email)
    WITH CHECK (auth.jwt() ->> 'email' = user_email);

-- Policy: Users can only delete their own tasks
CREATE POLICY "Users can delete their own tasks"
    ON public.manager
    FOR DELETE
    USING (auth.jwt() ->> 'email' = user_email);

-- Create function to automatically update updated_at timestamp
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
COMMENT ON TABLE public.manager IS 'Task management table with user isolation by email';
COMMENT ON COLUMN public.manager.user_email IS 'User email - ensures task belongs to specific user';
COMMENT ON COLUMN public.manager.titulo IS 'Task title';
COMMENT ON COLUMN public.manager.descricao IS 'Task description';
COMMENT ON COLUMN public.manager.concluida IS 'Task completion status';
COMMENT ON COLUMN public.manager.updated_at IS 'Timestamp of last update';