-- Script: Populate Manager Table with Sample Data
-- File: populate_manager_sample_data.sql

-- 1. Primeiro, vamos criar alguns usuários de teste se não existirem
-- NOTA: Em ambiente real, esses usuários seriam criados via autenticação
DO $$
DECLARE
    user1_id UUID := '11111111-1111-1111-1111-111111111111'::UUID;
    user2_id UUID := '22222222-2222-2222-2222-222222222222'::UUID;
    user3_id UUID := '33333333-3333-3333-3333-333333333333'::UUID;
BEGIN
    -- Inserir usuários de teste na tabela auth.users (se não existirem)
    -- NOTA: Em produção, isso seria feito pelo sistema de autenticação
    INSERT INTO auth.users (
        id,
        instance_id,
        email,
        encrypted_password,
        email_confirmed_at,
        created_at,
        updated_at,
        raw_app_meta_data,
        raw_user_meta_data,
        is_super_admin,
        role
    )
    SELECT 
        user1_id,
        '00000000-0000-0000-0000-000000000000',
        'joao.silva@email.com',
        '$2a$10$dXJ3SW6G7P.XBLBvanJXu.EHL3.6QbhAe6eS5YwR6Zk/4cS5oqjDO', -- password: 'password123'
        NOW(),
        NOW(),
        NOW(),
        '{"provider": "email", "providers": ["email"]}',
        '{"name": "João Silva"}',
        false,
        'authenticated'
    WHERE NOT EXISTS (SELECT 1 FROM auth.users WHERE id = user1_id);

    INSERT INTO auth.users (
        id,
        instance_id,
        email,
        encrypted_password,
        email_confirmed_at,
        created_at,
        updated_at,
        raw_app_meta_data,
        raw_user_meta_data,
        is_super_admin,
        role
    )
    SELECT 
        user2_id,
        '00000000-0000-0000-0000-000000000000',
        'maria.santos@email.com',
        '$2a$10$dXJ3SW6G7P.XBLBvanJXu.EHL3.6QbhAe6eS5YwR6Zk/4cS5oqjDO',
        NOW(),
        NOW(),
        NOW(),
        '{"provider": "email", "providers": ["email"]}',
        '{"name": "Maria Santos"}',
        false,
        'authenticated'
    WHERE NOT EXISTS (SELECT 1 FROM auth.users WHERE id = user2_id);

    INSERT INTO auth.users (
        id,
        instance_id,
        email,
        encrypted_password,
        email_confirmed_at,
        created_at,
        updated_at,
        raw_app_meta_data,
        raw_user_meta_data,
        is_super_admin,
        role
    )
    SELECT 
        user3_id,
        '00000000-0000-0000-0000-000000000000',
        'pedro.oliveira@email.com',
        '$2a$10$dXJ3SW6G7P.XBLBvanJXu.EHL3.6QbhAe6eS5YwR6Zk/4cS5oqjDO',
        NOW(),
        NOW(),
        NOW(),
        '{"provider": "email", "providers": ["email"]}',
        '{"name": "Pedro Oliveira"}',
        false,
        'authenticated'
    WHERE NOT EXISTS (SELECT 1 FROM auth.users WHERE id = user3_id);
END $$;

-- 2. Limpar dados existentes (opcional - descomente se necessário)
-- DELETE FROM public.manager;

-- 3. Inserir dados de exemplo para cada usuário
-- Tarefas para João Silva (user1_id)
INSERT INTO public.manager (user_id, titulo, descricao, concluida, created_at) VALUES
(
    '11111111-1111-1111-1111-111111111111',
    'Reunião de Planejamento',
    'Preparar apresentação para reunião trimestral com a equipe',
    true,
    NOW() - INTERVAL '5 days'
),
(
    '11111111-1111-1111-1111-111111111111',
    'Atualizar Documentação',
    'Revisar e atualizar documentação do projeto no Confluence',
    false,
    NOW() - INTERVAL '2 days'
),
(
    '11111111-1111-1111-1111-111111111111',
    'Testar Nova Funcionalidade',
    'Realizar testes de integração da feature de relatórios',
    false,
    NOW() - INTERVAL '1 day'
),
(
    '11111111-1111-1111-1111-111111111111',
    'Revisar Pull Requests',
    'Revisar PRs pendentes no repositório do projeto',
    true,
    NOW() - INTERVAL '3 hours'
);

-- Tarefas para Maria Santos (user2_id)
INSERT INTO public.manager (user_id, titulo, descricao, concluida, created_at) VALUES
(
    '22222222-2222-2222-2222-222222222222',
    'Compras do Mês',
    'Fazer lista de compras e ir ao supermercado',
    false,
    NOW() - INTERVAL '7 days'
),
(
    '22222222-2222-2222-2222-222222222222',
    'Pagamento de Contas',
    'Pagar contas de luz, água e internet',
    true,
    NOW() - INTERVAL '1 day'
),
(
    '22222222-2222-2222-2222-222222222222',
    'Estudar Inglês',
    'Praticar listening e speaking por 30 minutos',
    false,
    NOW() - INTERVAL '12 hours'
),
(
    '22222222-2222-2222-2222-222222222222',
    'Organizar Armário',
    'Separar roupas para doação e organizar o armário',
    false,
    NOW() - INTERVAL '2 days'
),
(
    '22222222-2222-2222-2222-222222222222',
    'Marcar Consulta Médica',
    'Ligar para marcar consulta com cardiologista',
    true,
    NOW() - INTERVAL '4 days'
);

-- Tarefas para Pedro Oliveira (user3_id)
INSERT INTO public.manager (user_id, titulo, descricao, concluida, created_at) VALUES
(
    '33333333-3333-3333-3333-333333333333',
    'Desenvolver API REST',
    'Implementar endpoints para módulo de usuários',
    true,
    NOW() - INTERVAL '10 days'
),
(
    '33333333-3333-3333-3333-333333333333',
    'Configurar CI/CD',
    'Configurar pipeline de deploy automático no GitLab',
    false,
    NOW() - INTERVAL '6 days'
),
(
    '33333333-3333-3333-3333-333333333333',
    'Otimizar Performance',
    'Identificar e corrigir gargalos de performance no sistema',
    false,
    NOW() - INTERVAL '3 days'
),
(
    '33333333-3333-3333-3333-333333333333',
    'Escrever Testes Unitários',
    'Criar testes para módulo de autenticação',
    true,
    NOW() - INTERVAL '1 day'
),
(
    '33333333-3333-3333-3333-333333333333',
    'Estudar Docker',
    'Aprender sobre containerização e orquestração',
    false,
    NOW() - INTERVAL '8 hours'
),
(
    '33333333-3333-3333-3333-333333333333',
    'Participar de Workshop',
    'Workshop sobre arquitetura de microserviços',
    true,
    NOW() - INTERVAL '15 days'
);

-- 4. Atualizar algumas tarefas para simular o trigger de updated_at
UPDATE public.manager 
SET descricao = descricao || ' (ATUALIZADO)', concluida = true 
WHERE id IN (2, 5, 8, 12);

-- 5. Verificar os dados inseridos
SELECT 
    m.id,
    m.titulo,
    m.descricao,
    m.concluida,
    m.created_at,
    m.updated_at,
    u.email as user_email
FROM public.manager m
LEFT JOIN auth.users u ON m.user_id = u.id
ORDER BY m.user_id, m.created_at DESC;

-- 6. Estatísticas dos dados inseridos
SELECT 
    u.email,
    COUNT(m.id) as total_tasks,
    SUM(CASE WHEN m.concluida THEN 1 ELSE 0 END) as completed_tasks,
    SUM(CASE WHEN NOT m.concluida THEN 1 ELSE 0 END) as pending_tasks,
    ROUND(AVG(CASE WHEN m.concluida THEN 1.0 ELSE 0.0 END) * 100, 2) as completion_rate
FROM public.manager m
JOIN auth.users u ON m.user_id = u.id
GROUP BY u.email
ORDER BY total_tasks DESC;

-- 7. Testar a função check_email_exists
SELECT 
    'joao.silva@email.com' as email,
    public.check_email_exists('joao.silva@email.com') as exists;

SELECT 
    'email.inexistente@teste.com' as email,
    public.check_email_exists('email.inexistente@teste.com') as exists;

-- 8. Verificar se as políticas RLS estão funcionando
-- (Este teste deve ser executado em sessões autenticadas com cada usuário)
COMMENT ON TABLE public.manager IS 'Tabela populada com dados de exemplo para desenvolvimento e teste';