-- População Avançada de Dados
-- Arquivo: testes/dados/02_populate_advanced_data.sql

BEGIN;

CREATE OR REPLACE FUNCTION testes.populate_advanced_data()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    task_categories JSONB := '[
        {"category": "Dev", "titles": ["Implementar", "Refatorar", "Otimizar", "Debug"], "descriptions": ["Desenvolvimento", "Melhoria", "Performance", "Correção"]},
        {"category": "Reunião", "titles": ["Daily", "Planning", "Review", "Retro"], "descriptions": ["Sincronização", "Planejamento", "Revisão", "Reflexão"]},
        {"category": "Ops", "titles": ["Deploy", "Monitor", "Backup", "Scale"], "descriptions": ["Produção", "Observabilidade", "Segurança", "Performance"]}
    ]'::JSONB;
    
    task_count INTEGER := 0;
BEGIN
    WITH category_tasks AS (
        SELECT 
            u.id as user_id,
            u.email as user_email,
            cat->>'category' as category,
            (cat->'titles'->>(floor(random() * jsonb_array_length(cat->'titles'))::int))::text as titulo,
            (cat->'descriptions'->>(floor(random() * jsonb_array_length(cat->'descriptions'))::int))::text as descricao,
            (random() < 0.4) as concluida,
            NOW() - (random() * 30 * INTERVAL '1 day') as created_at
        FROM auth.users u
        CROSS JOIN jsonb_array_elements(task_categories) cat
        CROSS JOIN generate_series(1, 4) as num
        WHERE u.email IS NOT NULL
    ),
    inserted AS (
        INSERT INTO public.manager (user_id, user_email, titulo, descricao, concluida, created_at, updated_at)
        SELECT 
            user_id,
            user_email,
            titulo || ' ' || category || ' ' || num,
            descricao || ' - ' || category,
            concluida,
            created_at,
            CASE WHEN concluida THEN created_at + (random() * INTERVAL '2 days') ELSE created_at END
        FROM category_tasks
        RETURNING 1
    )
    SELECT COUNT(*) INTO task_count FROM inserted;

    RETURN jsonb_build_object(
        'status', 'success', 
        'tasks_created', task_count,
        'type', 'advanced_data'
    );
END;
$$;

SELECT testes.populate_advanced_data();
DROP FUNCTION testes.populate_advanced_data();

COMMIT;