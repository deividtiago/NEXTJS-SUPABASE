-- Função para verificar se um email existe no sistema
CREATE OR REPLACE FUNCTION public.check_email_exists(user_email TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 
    FROM auth.users 
    WHERE email = user_email
  );
END;
$$;