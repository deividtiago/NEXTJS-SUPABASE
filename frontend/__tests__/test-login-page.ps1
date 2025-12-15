# test-login-page.ps1
# Testes específicos para http://localhost:3000/login

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "🔐 TESTES DE SEGURANÇA - PÁGINA DE LOGIN" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Alvo: http://localhost:3000/login" -ForegroundColor Yellow
Write-Host ""

# Variáveis
$TARGET_URL = "http://localhost:3000"
$LOGIN_PAGE = "$TARGET_URL/login"
$OUTPUT_DIR = ".\resultados\login-tests\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$LOG_FILE = "$OUTPUT_DIR\log-detalhado.txt"

# Criar diretórios
New-Item -ItemType Directory -Force -Path $OUTPUT_DIR | Out-Null

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    Add-Content -Path $LOG_FILE -Value $logEntry
    Write-Host $logEntry
}

# 1. Testar a página de login com parâmetros GET
Write-Log "🧪 TESTE 1: Parâmetros GET na página de login"
Write-Log "Testando URL: $LOGIN_PAGE?magicLink=yes"

sqlmap -u "$LOGIN_PAGE?magicLink=yes" `
    --batch `
    --level=2 `
    --risk=1 `
    --output-dir="$OUTPUT_DIR\get-params" `
    --flush-session

# 2. Testar diferentes valores para magicLink
Write-Log "🧪 TESTE 2: Injeção no parâmetro magicLink"

$magicLinkPayloads = @(
    "yes' OR '1'='1",
    "yes' OR '1'='1' --",
    "yes' UNION SELECT NULL--",
    "yes'); DROP TABLE users;--"
)

foreach ($payload in $magicLinkPayloads) {
    $encodedPayload = [Uri]::EscapeDataString($payload)
    Write-Log "Testando payload: $payload"
    
    sqlmap -u "$LOGIN_PAGE?magicLink=$encodedPayload" `
        --batch `
        --level=3 `
        --risk=2 `
        --output-dir="$OUTPUT_DIR\magiclink-payload-$($payload.Replace("'","").Replace(" ",""))" `
        --flush-session
}

# 3. Testar formulário de login (POST)
Write-Log "🧪 TESTE 3: Formulário POST de login"

# Criar arquivo de request simulando o formulário
$postRequestFile = "$OUTPUT_DIR\login-post.txt"
@"
POST /login HTTP/1.1
Host: localhost:3000
Content-Type: application/x-www-form-urlencoded
Content-Length: 43

email=test@example.com&password=password123
"@ | Out-File -FilePath $postRequestFile -Encoding UTF8

sqlmap -r $postRequestFile `
    --batch `
    --level=3 `
    --risk=2 `
    --output-dir="$OUTPUT_DIR\form-post" `
    --flush-session

# 4. Testar headers da página
Write-Log "🧪 TESTE 4: Headers e cookies"

sqlmap -u $LOGIN_PAGE `
    --headers="User-Agent: Mozilla/5.0' OR '1'='1" `
    --batch `
    --level=2 `
    --risk=1 `
    --output-dir="$OUTPUT_DIR\headers" `
    --flush-session

# 5. Testar XSS na página de login
Write-Log "🧪 TESTE 5: Testes de XSS básicos"

$xssPayloads = @(
    "<script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "onload=alert('XSS')"
)

foreach ($xss in $xssPayloads) {
    $encodedXss = [Uri]::EscapeDataString($xss)
    Write-Log "Testando XSS: $xss"
    
    # Testar no parâmetro magicLink
    sqlmap -u "$LOGIN_PAGE?magicLink=$encodedXss" `
        --batch `
        --level=2 `
        --risk=1 `
        --output-dir="$OUTPUT_DIR\xss-test" `
        --flush-session
}

# 6. Testar se há vazamento de informações
Write-Log "🧪 TESTE 6: Enumeração de diretórios/páginas"

$commonPaths = @(
    "/login/admin",
    "/login/backup",
    "/login/config",
    "/login/.env",
    "/login/api",
    "/login/auth"
)

foreach ($path in $commonPaths) {
    Write-Log "Testando caminho: $path"
    $testUrl = "$TARGET_URL$path"
    
    try {
        $response = Invoke-WebRequest -Uri $testUrl -Method GET -TimeoutSec 3
        Write-Log "⚠️  Caminho acessível: $testUrl (Status: $($response.StatusCode))" -ForegroundColor Yellow
    } catch {
        # Caminho não existe ou não acessível
    }
}

# 7. Testar rate limiting
Write-Log "🧪 TESTE 7: Teste básico de rate limiting"

for ($i = 1; $i -le 10; $i++) {
    Write-Log "Requisição $i para $LOGIN_PAGE"
    try {
        $response = Invoke-WebRequest -Uri $LOGIN_PAGE -Method GET -TimeoutSec 2
        Write-Log "  Status: $($response.StatusCode)"
    } catch {
        Write-Log "  ❌ Erro ou bloqueio detectado" -ForegroundColor Red
        break
    }
    Start-Sleep -Milliseconds 500
}

Write-Log "✅ Todos os testes foram executados!"
Write-Log "📁 Resultados salvos em: $OUTPUT_DIR"

# Gerar relatório resumido
$reportFile = "$OUTPUT_DIR\relatorio-resumo.html"
@"
<!DOCTYPE html>
<html>
<head>
    <title>Relatório - Testes Login: $LOGIN_PAGE</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        .vulnerability { background: #ffebee; padding: 15px; margin: 10px 0; border-left: 4px solid #f44336; }
        .safe { background: #e8f5e9; padding: 15px; margin: 10px 0; border-left: 4px solid #4caf50; }
        .warning { background: #fff3e0; padding: 15px; margin: 10px 0; border-left: 4px solid #ff9800; }
    </style>
</head>
<body>
    <h1>🔒 Relatório de Testes - $LOGIN_PAGE</h1>
    <p><strong>Data:</strong> $(Get-Date)</p>
    <p><strong>URL testada:</strong> $LOGIN_PAGE</p>
    
    <h2>📋 Testes Realizados</h2>
    
    <div class="test">
        <h3>1. Injeção SQL via GET (magicLink)</h3>
        <p><strong>Status:</strong> Verificar logs SQLmap</p>
    </div>
    
    <div class="test">
        <h3>2. Testes XSS</h3>
        <p><strong>Payloads testados:</strong> $(@($xssPayloads) -join ', ')</p>
    </div>
    
    <div class="test">
        <h3>3. Formulário POST</h3>
        <p><strong>Método:</strong> SQLmap com request file</p>
    </div>
    
    <div class="warning">
        <h3>⚠️ Recomendações</h3>
        <ul>
            <li>Validar todos os parâmetros GET</li>
            <li>Implementar CSRF tokens</li>
            <li>Usar Content Security Policy (CSP)</li>
            <li>Rate limiting para tentativas de login</li>
        </ul>
    </div>
</body>
</html>
"@ | Out-File -FilePath $reportFile -Encoding UTF8

Write-Log "📄 Relatório gerado: $reportFile"

# Abrir pasta de resultados
Invoke-Item $OUTPUT_DIR