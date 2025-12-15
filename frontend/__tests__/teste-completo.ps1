Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "🔐 TESTE DE SEGURANÇA - SQL INJECTION" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Criar pasta para resultados
$dataHora = Get-Date -Format "dd-MM-yyyy_HH-mm"
$pastaResultados = ".\Resultados_$dataHora"
New-Item -ItemType Directory -Force -Path $pastaResultados | Out-Null
Write-Host "📁 Resultados em: $pastaResultados" -ForegroundColor Yellow

Write-Host "`n🎯 TESTANDO PÁGINA DE LOGIN DO NEXT.JS" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green

# Teste 1: Página de login básica
Write-Host "`n[1/4] 📄 Página de login (GET)" -ForegroundColor Magenta
sqlmap -u "http://localhost:3000/login" `
    --batch `
    --answers="Y,C,Y" `
    --output-dir="$pastaResultados\1_login_basico" `
    --flush-session

# Teste 2: Com parâmetro magicLink
Write-Host "`n[2/4] 🔗 Página com parâmetro magicLink" -ForegroundColor Magenta
sqlmap -u "http://localhost:3000/login?magicLink=yes" `
    --batch `
    --answers="Y,C,Y" `
    --output-dir="$pastaResultados\2_magiclink_param" `
    --flush-session

Write-Host "`n🎯 TESTANDO ENDPOINTS DO SUPABASE" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green

# Teste 3: Endpoint de login do Supabase
Write-Host "`n[3/4] 🗝️ Endpoint de autenticação" -ForegroundColor Magenta
$dadosLogin = "email=teste@exemplo.com&password=senha123&grant_type=password"
sqlmap -u "http://localhost:54321/auth/v1/token" `
    --data="$dadosLogin" `
    --headers="apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0" `
    --batch `
    --answers="Y,C,Y" `
    --output-dir="$pastaResultados\3_supabase_login" `
    --flush-session

# Teste 4: Endpoint de cadastro
Write-Host "`n[4/4] 📝 Endpoint de cadastro" -ForegroundColor Magenta
$dadosCadastro = "email=novo@exemplo.com&password=senha456"
sqlmap -u "http://localhost:54321/auth/v1/signup" `
    --data="$dadosCadastro" `
    --headers="apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0" `
    --batch `
    --answers="Y,C,Y" `
    --output-dir="$pastaResultados\4_supabase_signup" `
    --flush-session

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "✅ TESTES CONCLUÍDOS COM SUCESSO!" -ForegroundColor Green
Write-Host "📊 Verifique os resultados na pasta acima" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Cyan

# Abrir pasta
Invoke-Item $pastaResultados
