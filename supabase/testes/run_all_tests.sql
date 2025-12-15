-- Executor de Todos os Testes
-- Arquivo: testes/run_all_tests.sql

\echo '🧪 INICIANDO SUITE DE TESTES DO MANAGER'
\echo '======================================'

\echo ''
\echo '1. Populando dados básicos...'
\i testes/dados/01_populate_basic_data.sql

\echo ''
\echo '2. Populando dados avançados...'
\i testes/dados/02_populate_advanced_data.sql

\echo ''
\echo '3. Adicionando casos de teste específicos...'
\i testes/dados/03_populate_test_cases.sql

\echo ''
\echo '4. Validando qualidade dos dados...'
\i testes/validacao/01_verify_data_quality.sql

\echo ''
\echo '5. Verificando políticas RLS...'
\i testes/validacao/02_check_rls_policies.sql

\echo ''
\echo '✅ SUITE DE TESTES CONCLUÍDA'
\echo 'Verifique os logs acima para resultados detalhados.'