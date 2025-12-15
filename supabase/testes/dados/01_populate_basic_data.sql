
-- População Básica de Dados
-- Arquivo: testes/dados/01_populate_basic_data.sql

BEGIN;

-- Criar função de população básica
CREATE OR REPLACE FUNCTION testes.populate_basic_data()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    result JSONB;
    user_count INTEGER;
    task_count INTEGER := 0;
BEGIN
    -- Verificar se existem usuários
    SELECT COUNT(*) INTO user_count FROM auth.users;
    
    IF user_count = 0 THEN
        RETURN jsonb_build_object(
            'status', 'error',
            'message', 'Nenhum usuário encontrado. Execute create_test_users.sql primeiro.',
            'tasks_created', 0
        );
    END IF;

    -- Inserir tarefas básicas para cada usuário
    WITH inserted_tasks AS (
        INSERT INTO public.manager (user_id, user_email, titulo, descricao, concluida, created_at)
        SELECT 
            u.id,
            u.email,
            tasks.titulo,
            tasks.descricao,
            (random() < 0.3) as concluida,
            NOW() - (seq.num * INTERVAL '2 hours')
        FROM auth.users u
        CROSS JOIN LATERAL (
            SELECT * FROM (VALUES
                ('Reunião de planejamento', 'Discutir metas do próximo trimestre'),
                ('Desenvolver feature XYZ', 'Implementar nova funcionalidade'),
                ('Revisar código', 'Code review do PR #45'),
                ('Atualizar documentação', 'Documentar novas APIs'),
                ('Testar sistema', 'Testes de integração'),
                ('Corrigir bugs', 'Resolver issues reportados'),
                ('Deploy em staging', 'Preparar ambiente de teste'),
                ('Treinamento equipe', 'Treinar novos colaboradores')
            ) AS t(titulo, descricao)
        ) tasks
        CROSS JOIN generate_series(1, 6) AS seq(num)
        WHERE u.email IS NOT NULL
        RETURNING 1
    )
    SELECT COUNT(*) INTO task_count FROM inserted_tasks;

    COMMIT;
    
    RETURN jsonb_build_object(
        'status', 'success',
        'message', 'Dados básicos inseridos com sucesso',
        'tasks_created', task_count,
        'executed_at', NOW()
    );
END;
$$;

-- Executar população
SELECT testes.populate_basic_data();

-- Limpar função
DROP FUNCTION testes.populate_basic_data();

COMMIT;