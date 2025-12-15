-- Função que checa se o email existe no banco de dados
CREATE OR REPLACE FUNCTION public.check_email_exists(user_email TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    RETURN EXISTS(
        SELECT 1
        FROM auth.users
        WHERE email = user_email
    );
END;
$$;