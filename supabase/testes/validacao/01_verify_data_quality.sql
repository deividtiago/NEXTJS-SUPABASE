-- Validação da Qualidade dos Dados
-- Arquivo: testes/validacao/01_verify_data_quality.sql

DO $$
DECLARE
    total_tasks BIGINT;
    total_users BIGINT;
    completion_rate DECIMAL;
    data_quality JSONB;
BEGIN
    -- Estatísticas básicas
    SELECT COUNT(*), COUNT(DISTINCT user_id) INTO total_tasks, total_users FROM public.manager;
    
    SELECT 
        ROUND(100.0 * SUM(CASE WHEN concluida THEN 1 ELSE 0 END) / COUNT(*), 2) 
    INTO completion_rate 
    FROM public.manager;

    -- Verificar problemas comuns
    WITH issues AS (
        SELECT
            COUNT(CASE WHEN titulo IS NULL OR trim(titulo) = '' THEN 1 END) as empty_titles,
            COUNT(CASE WHEN user_id IS NULL THEN 1 END) as null_user_ids,
            COUNT(CASE WHEN user_email IS NULL THEN 1 END) as null_emails,
            COUNT(CASE WHEN created_at > NOW() THEN 1 END) as future_dates
        FROM public.manager
    )
    SELECT jsonb_build_object(
        'empty_titles', empty_titles,
        'null_user_ids', null_user_ids,
        'null_emails', null_emails,
        'future_dates', future_dates
    ) INTO data_quality FROM issues;

    -- Report final
    RAISE NOTICE '📊 RELATÓRIO DE QUALIDADE DE DADOS';
    RAISE NOTICE '================================';
    RAISE NOTICE 'Total de tarefas: %', total_tasks;
    RAISE NOTICE 'Usuários com tarefas: %', total_users;
    RAISE NOTICE 'Taxa de conclusão: %%%', completion_rate;
    RAISE NOTICE 'Problemas encontrados: %', data_quality;
    
    -- Alertas críticos
    IF total_tasks = 0 THEN
        RAISE WARNING '❌ Nenhuma tarefa encontrada!';
    END IF;
    
    IF (data_quality->>'null_user_ids')::INT > 0 THEN
        RAISE WARNING '⚠️  Tarefas sem user_id encontradas: %', data_quality->>'null_user_ids';
    END IF;
END $$;