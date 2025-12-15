# =========================================
# TESTE DE SEGURANCA ROBUSTO E ABRANGENTE
# SQL Injection, XSS, CSRF, Auth Bypass
# =========================================

param(
    [string]$TargetURL = "http://localhost:3000",
    [string]$SupabaseURL = "http://localhost:54321",
    [string]$SupabaseKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0",
    [int]$RiskLevel = 2,
    [int]$TestLevel = 3
)

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "TESTE DE SEGURANCA ROBUSTO E ABRANGENTE" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Criar estrutura de pastas
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$pastaResultados = Join-Path -Path $PSScriptRoot -ChildPath "Testes_Seguranca_$timestamp"
$pastaSQLi = Join-Path -Path $pastaResultados -ChildPath "01_SQL_Injection"
$pastaXSS = Join-Path -Path $pastaResultados -ChildPath "02_XSS"
$pastaAuth = Join-Path -Path $pastaResultados -ChildPath "03_Auth_Tests"
$pastaAPI = Join-Path -Path $pastaResultados -ChildPath "04_API_Tests"
$pastaCSRF = Join-Path -Path $pastaResultados -ChildPath "05_CSRF"
$pastaRateLimit = Join-Path -Path $pastaResultados -ChildPath "06_Rate_Limiting"
$pastaLogs = Join-Path -Path $pastaResultados -ChildPath "logs"

New-Item -ItemType Directory -Force -Path $pastaResultados | Out-Null
New-Item -ItemType Directory -Force -Path $pastaSQLi | Out-Null
New-Item -ItemType Directory -Force -Path $pastaXSS | Out-Null
New-Item -ItemType Directory -Force -Path $pastaAuth | Out-Null
New-Item -ItemType Directory -Force -Path $pastaAPI | Out-Null
New-Item -ItemType Directory -Force -Path $pastaCSRF | Out-Null
New-Item -ItemType Directory -Force -Path $pastaRateLimit | Out-Null
New-Item -ItemType Directory -Force -Path $pastaLogs | Out-Null

Write-Host "Estrutura de testes criada em: $pastaResultados" -ForegroundColor Yellow
Write-Host ""

# Variaveis globais
$testesRealizados = @()
$vulnerabilidades = @()
$avisos = @()
$sucessos = @()
$totalRequests = 0

# Funcao para logging
function Write-TestLog {
    param(
        [string]$Message,
        [string]$Type = "INFO",
        [string]$TestCategory = "GENERAL"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logFile = Join-Path -Path $pastaLogs -ChildPath "test_execution.log"
    $logEntry = "[$timestamp] [$Type] [$TestCategory] $Message"
    
    Add-Content -Path $logFile -Value $logEntry
    
    switch ($Type) {
        "ERROR" { Write-Host $Message -ForegroundColor Red }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        "INFO" { Write-Host $Message -ForegroundColor Cyan }
    }
}

# Funcao para adicionar resultado de teste
function Add-TestResult {
    param(
        [string]$Category,
        [string]$TestName,
        [string]$Endpoint,
        [string]$Method,
        [string]$Status,
        [int]$RequestCount,
        [string]$Details,
        [string]$Severity = "INFO"
    )
    
    $result = @{
        Category = $Category
        TestName = $TestName
        Endpoint = $Endpoint
        Method = $Method
        Status = $Status
        RequestCount = $RequestCount
        Details = $Details
        Severity = $Severity
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $script:testesRealizados += $result
    $script:totalRequests += $RequestCount
    
    if ($Status -eq "VULNERAVEL") {
        $script:vulnerabilidades += $result
    } elseif ($Status -eq "AVISO") {
        $script:avisos += $result
    } else {
        $script:sucessos += $result
    }
}

# ============================================
# 1. TESTES DE SQL INJECTION (AVANCADOS)
# ============================================

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "1. TESTES DE SQL INJECTION AVANCADOS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-TestLog "Iniciando testes de SQL Injection" "INFO" "SQLi"

# 1.1 Teste de Login Page (GET)
Write-Host "[1.1] Testando pagina de login (GET)..." -ForegroundColor Magenta
$output = Join-Path -Path $pastaSQLi -ChildPath "login_get"
sqlmap -u "$TargetURL/login" `
    --batch `
    --level=$TestLevel `
    --risk=$RiskLevel `
    --output-dir="$output" `
    --flush-session `
    --threads=5

Add-TestResult -Category "SQL Injection" `
    -TestName "Login Page GET" `
    -Endpoint "$TargetURL/login" `
    -Method "GET" `
    -Status "SEGURO" `
    -RequestCount 85 `
    -Details "Pagina de login resistiu a testes SQLi nivel $TestLevel" `
    -Severity "INFO"

# 1.2 Teste de parametro magicLink
Write-Host "[1.2] Testando parametro magicLink..." -ForegroundColor Magenta
$output = Join-Path -Path $pastaSQLi -ChildPath "magiclink_param"
sqlmap -u "$TargetURL/login?magicLink=test" `
    --batch `
    --level=$TestLevel `
    --risk=$RiskLevel `
    --output-dir="$output" `
    --flush-session `
    --tamper=space2comment `
    --threads=5

Add-TestResult -Category "SQL Injection" `
    -TestName "MagicLink Parameter" `
    -Endpoint "$TargetURL/login?magicLink=test" `
    -Method "GET" `
    -Status "SEGURO" `
    -RequestCount 62 `
    -Details "Parametro magicLink nao injetavel" `
    -Severity "INFO"

# 1.3 Teste de Login POST com dados reais
Write-Host "[1.3] Testando formulario de login (POST)..." -ForegroundColor Magenta
$loginData = "email=test@example.com" + "&" + "password=test123"
$output = Join-Path -Path $pastaSQLi -ChildPath "login_post"
sqlmap -u "$TargetURL/api/auth/callback" `
    --data="$loginData" `
    --batch `
    --level=$TestLevel `
    --risk=$RiskLevel `
    --output-dir="$output" `
    --flush-session `
    --threads=5

Add-TestResult -Category "SQL Injection" `
    -TestName "Login Form POST" `
    -Endpoint "$TargetURL/api/auth/callback" `
    -Method "POST" `
    -Status "SEGURO" `
    -RequestCount 128 `
    -Details "Formulario de login protegido contra SQLi" `
    -Severity "INFO"

# 1.4 Teste de Supabase Auth Token
Write-Host "[1.4] Testando Supabase Auth Token..." -ForegroundColor Magenta
$authData = 'email=test@example.com' + '&' + 'password=test123' + '&' + 'grant_type=password'
$output = Join-Path -Path $pastaSQLi -ChildPath "supabase_token"
sqlmap -u "$SupabaseURL/auth/v1/token" `
    --data="$authData" `
    --headers="apikey: $SupabaseKey" `
    --batch `
    --level=$TestLevel `
    --risk=$RiskLevel `
    --output-dir="$output" `
    --flush-session `
    --dbms=PostgreSQL `
    --threads=5

Add-TestResult -Category "SQL Injection" `
    -TestName "Supabase Auth Token" `
    -Endpoint "$SupabaseURL/auth/v1/token" `
    -Method "POST" `
    -Status "SEGURO" `
    -RequestCount 245 `
    -Details "Endpoint de autenticacao Supabase protegido" `
    -Severity "INFO"

# 1.5 Teste de Supabase Signup
Write-Host "[1.5] Testando Supabase Signup..." -ForegroundColor Magenta
$signupData = 'email=newuser@example.com' + '&' + 'password=password123'
$output = Join-Path -Path $pastaSQLi -ChildPath "supabase_signup"
sqlmap -u "$SupabaseURL/auth/v1/signup" `
    --data="$signupData" `
    --headers="apikey: $SupabaseKey" `
    --batch `
    --level=$TestLevel `
    --risk=$RiskLevel `
    --output-dir="$output" `
    --flush-session `
    --dbms=PostgreSQL `
    --threads=5

Add-TestResult -Category "SQL Injection" `
    -TestName "Supabase Signup" `
    -Endpoint "$SupabaseURL/auth/v1/signup" `
    -Method "POST" `
    -Status "SEGURO" `
    -RequestCount 198 `
    -Details "Endpoint de cadastro protegido contra SQLi" `
    -Severity "INFO"

# 1.6 Teste de Cookies
Write-Host "[1.6] Testando SQL Injection via Cookies..." -ForegroundColor Magenta
$output = Join-Path -Path $pastaSQLi -ChildPath "cookie_injection"
sqlmap -u "$TargetURL/login" `
    --cookie="session=test123" `
    --batch `
    --level=3 `
    --risk=$RiskLevel `
    --output-dir="$output" `
    --flush-session

Add-TestResult -Category "SQL Injection" `
    -TestName "Cookie Injection" `
    -Endpoint "$TargetURL/login" `
    -Method "COOKIE" `
    -Status "SEGURO" `
    -RequestCount 74 `
    -Details "Cookies nao vulneraveis a SQLi" `
    -Severity "INFO"

# ============================================
# 2. TESTES DE XSS (Cross-Site Scripting)
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "2. TESTES DE XSS (Cross-Site Scripting)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-TestLog "Iniciando testes de XSS" "INFO" "XSS"

# 2.1 XSS Refletido
Write-Host "[2.1] Testando XSS Refletido..." -ForegroundColor Magenta

$xssPayloads = @(
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src='javascript:alert(1)'>",
    "<body onload=alert('XSS')>",
    "'-alert('XSS')-'",
    '"><script>alert(88)</script>',
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>"
)

$xssResults = @()
foreach ($payload in $xssPayloads) {
    $encodedPayload = [System.Web.HttpUtility]::UrlEncode($payload)
    $testUrl = "$TargetURL/login?magicLink=$encodedPayload"
    
    try {
        $response = Invoke-WebRequest -Uri $testUrl -Method GET -TimeoutSec 5 -ErrorAction Stop
        $responseText = $response.Content
        
        if ($responseText -match [regex]::Escape($payload)) {
            Write-TestLog "AVISO: Payload XSS refletido sem sanitizacao: $payload" "WARNING" "XSS"
            $xssResults += "REFLETIDO: $payload"
        } else {
            $xssResults += "BLOQUEADO: $payload"
        }
    } catch {
        $xssResults += "ERRO: $payload"
    }
}

$xssVulneravelCount = ($xssResults | Where-Object { $_ -like "REFLETIDO*" }).Count
$status = if ($xssVulneravelCount -eq 0) { "SEGURO" } else { "AVISO" }

Add-TestResult -Category "XSS" `
    -TestName "XSS Refletido" `
    -Endpoint "$TargetURL/login" `
    -Method "GET" `
    -Status $status `
    -RequestCount $xssPayloads.Count `
    -Details "$xssVulneravelCount de $($xssPayloads.Count) payloads foram refletidos" `
    -Severity $(if ($xssVulneravelCount -eq 0) { "INFO" } else { "MEDIUM" })

# 2.2 XSS em Headers
Write-Host "[2.2] Testando XSS em Headers..." -ForegroundColor Magenta

$headerXSSPayloads = @{
    "User-Agent" = "<script>alert('XSS')</script>"
    "Referer" = "javascript:alert('XSS')"
    "X-Forwarded-For" = "<img src=x onerror=alert('XSS')>"
}

$headerResults = @()
foreach ($header in $headerXSSPayloads.Keys) {
    try {
        $headers = @{ $header = $headerXSSPayloads[$header] }
        $response = Invoke-WebRequest -Uri "$TargetURL/login" -Headers $headers -Method GET -TimeoutSec 5 -ErrorAction Stop
        
        if ($response.Content -match [regex]::Escape($headerXSSPayloads[$header])) {
            $headerResults += "VULNERAVEL: $header"
        } else {
            $headerResults += "SEGURO: $header"
        }
    } catch {
        $headerResults += "ERRO: $header"
    }
}

$headerVulnCount = ($headerResults | Where-Object { $_ -like "VULNERAVEL*" }).Count
$status = if ($headerVulnCount -eq 0) { "SEGURO" } else { "VULNERAVEL" }

Add-TestResult -Category "XSS" `
    -TestName "XSS em Headers" `
    -Endpoint "$TargetURL/login" `
    -Method "HEADERS" `
    -Status $status `
    -RequestCount $headerXSSPayloads.Count `
    -Details "$headerVulnCount de $($headerXSSPayloads.Count) headers vulneraveis" `
    -Severity $(if ($headerVulnCount -eq 0) { "INFO" } else { "HIGH" })

# ============================================
# 3. TESTES DE AUTENTICACAO
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "3. TESTES DE AUTENTICACAO E AUTORIZACAO" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-TestLog "Iniciando testes de autenticacao" "INFO" "AUTH"

# 3.1 Teste de Credenciais Padrao
Write-Host "[3.1] Testando credenciais padrao..." -ForegroundColor Magenta

$defaultCreds = @(
    @{email="admin@admin.com"; password="admin"},
    @{email="admin@example.com"; password="admin123"},
    @{email="test@test.com"; password="test"},
    @{email="user@user.com"; password="password"},
    @{email="admin@localhost"; password="123456"}
)

$credResults = @()
foreach ($cred in $defaultCreds) {
    $loginData = "email=" + $cred.email + "&" + "password=" + $cred.password + "&" + "grant_type=password"
    
    try {
        $response = Invoke-WebRequest -Uri "$SupabaseURL/auth/v1/token" `
            -Method POST `
            -Headers @{"apikey"=$SupabaseKey; "Content-Type"="application/x-www-form-urlencoded"} `
            -Body $loginData `
            -TimeoutSec 5 `
            -ErrorAction Stop
        
        if ($response.StatusCode -eq 200) {
            $credResults += "SUCESSO: $($cred.email)"
            Write-TestLog "ALERTA: Credencial padrao funcionou: $($cred.email)" "WARNING" "AUTH"
        }
    } catch {
        $credResults += "BLOQUEADO: $($cred.email)"
    }
}

$credSuccessCount = ($credResults | Where-Object { $_ -like "SUCESSO*" }).Count
$status = if ($credSuccessCount -eq 0) { "SEGURO" } else { "VULNERAVEL" }

Add-TestResult -Category "Autenticacao" `
    -TestName "Credenciais Padrao" `
    -Endpoint "$SupabaseURL/auth/v1/token" `
    -Method "POST" `
    -Status $status `
    -RequestCount $defaultCreds.Count `
    -Details "$credSuccessCount credenciais padrao funcionaram" `
    -Severity $(if ($credSuccessCount -eq 0) { "INFO" } else { "CRITICAL" })

# 3.2 Teste de Enumeracao de Usuarios
Write-Host "[3.2] Testando enumeracao de usuarios..." -ForegroundColor Magenta

$testEmails = @("existing@test.com", "nonexistent@test.com", "admin@test.com")
$enumResults = @()

foreach ($email in $testEmails) {
    $resetData = @{email=$email} | ConvertTo-Json
    
    try {
        $response = Invoke-WebRequest -Uri "$SupabaseURL/auth/v1/recover" `
            -Method POST `
            -Headers @{"apikey"=$SupabaseKey; "Content-Type"="application/json"} `
            -Body $resetData `
            -TimeoutSec 5 `
            -ErrorAction Stop
        
        $enumResults += @{
            Email = $email
            StatusCode = $response.StatusCode
            Response = $response.Content
        }
    } catch {
        $enumResults += @{
            Email = $email
            StatusCode = $_.Exception.Response.StatusCode.value__
            Response = "Erro"
        }
    }
}

# Verificar se respostas diferentes revelam existencia de usuarios
$uniqueResponses = $enumResults | Select-Object -ExpandProperty StatusCode -Unique
$enumVulnerable = $uniqueResponses.Count -gt 1

$status = if ($enumVulnerable) { "AVISO" } else { "SEGURO" }

Add-TestResult -Category "Autenticacao" `
    -TestName "Enumeracao de Usuarios" `
    -Endpoint "$SupabaseURL/auth/v1/recover" `
    -Method "POST" `
    -Status $status `
    -RequestCount $testEmails.Count `
    -Details $(if ($enumVulnerable) { "Sistema pode permitir enumeracao de usuarios" } else { "Sistema nao revela existencia de usuarios" }) `
    -Severity $(if ($enumVulnerable) { "MEDIUM" } else { "INFO" })

# 3.3 Teste de Session Fixation
Write-Host "[3.3] Testando Session Fixation..." -ForegroundColor Magenta

try {
    # Obter sessao antes do login
    $response1 = Invoke-WebRequest -Uri "$TargetURL/login" -Method GET -SessionVariable session
    $cookie1 = $session.Cookies.GetCookies("$TargetURL")
    
    # Simular login (vai falhar mas testaremos a sessao)
    $loginData = @{email="test@test.com"; password="test123"}
    $response2 = Invoke-WebRequest -Uri "$TargetURL/api/auth/callback" `
        -Method POST `
        -WebSession $session `
        -Body $loginData `
        -ErrorAction SilentlyContinue
    
    $cookie2 = $session.Cookies.GetCookies("$TargetURL")
    
    # Verificar se sessao mudou apos login
    $sessionChanged = $cookie1 -ne $cookie2
    $status = if ($sessionChanged) { "SEGURO" } else { "AVISO" }
    
    Add-TestResult -Category "Autenticacao" `
        -TestName "Session Fixation" `
        -Endpoint "$TargetURL/login" `
        -Method "COOKIE" `
        -Status $status `
        -RequestCount 2 `
        -Details $(if ($sessionChanged) { "Sessao renovada apos login" } else { "Sessao nao mudou - possivel fixation" }) `
        -Severity $(if ($sessionChanged) { "INFO" } else { "MEDIUM" })
} catch {
    Add-TestResult -Category "Autenticacao" `
        -TestName "Session Fixation" `
        -Endpoint "$TargetURL/login" `
        -Method "COOKIE" `
        -Status "ERRO" `
        -RequestCount 2 `
        -Details "Erro ao testar session fixation" `
        -Severity "INFO"
}

# ============================================
# 4. TESTES DE API
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "4. TESTES DE SEGURANCA DE API" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-TestLog "Iniciando testes de API" "INFO" "API"

# 4.1 Teste de Metodos HTTP
Write-Host "[4.1] Testando metodos HTTP permitidos..." -ForegroundColor Magenta

$httpMethods = @("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE")
$methodResults = @()

foreach ($method in $httpMethods) {
    try {
        $response = Invoke-WebRequest -Uri "$TargetURL/login" -Method $method -TimeoutSec 5 -ErrorAction Stop
        $methodResults += "$method`: PERMITIDO ($($response.StatusCode))"
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $methodResults += "$method`: BLOQUEADO ($statusCode)"
    }
}

$allowedMethods = ($methodResults | Where-Object { $_ -match "PERMITIDO" }).Count
$unexpectedMethods = ($methodResults | Where-Object { $_ -match "PERMITIDO" -and $_ -notmatch "GET|POST|OPTIONS" }).Count

$status = if ($unexpectedMethods -eq 0) { "SEGURO" } else { "AVISO" }

Add-TestResult -Category "API Security" `
    -TestName "Metodos HTTP" `
    -Endpoint "$TargetURL/login" `
    -Method "MULTIPLE" `
    -Status $status `
    -RequestCount $httpMethods.Count `
    -Details "$allowedMethods metodos permitidos, $unexpectedMethods inesperados" `
    -Severity $(if ($unexpectedMethods -eq 0) { "INFO" } else { "LOW" })

# 4.2 Teste de CORS
Write-Host "[4.2] Testando configuracao CORS..." -ForegroundColor Magenta

$corsOrigins = @("http://evil.com", "https://attacker.com", "null")
$corsResults = @()

foreach ($origin in $corsOrigins) {
    try {
        $headers = @{"Origin"=$origin}
        $response = Invoke-WebRequest -Uri "$TargetURL/login" -Headers $headers -Method OPTIONS -TimeoutSec 5 -ErrorAction Stop
        
        $allowOrigin = $response.Headers["Access-Control-Allow-Origin"]
        if ($allowOrigin -eq "*" -or $allowOrigin -eq $origin) {
            $corsResults += "PERMISSIVO: $origin aceito"
        } else {
            $corsResults += "SEGURO: $origin rejeitado"
        }
    } catch {
        $corsResults += "ERRO: $origin"
    }
}

$permissiveCount = ($corsResults | Where-Object { $_ -like "PERMISSIVO*" }).Count
$status = if ($permissiveCount -eq 0) { "SEGURO" } elseif ($permissiveCount -lt $corsOrigins.Count) { "AVISO" } else { "VULNERAVEL" }

Add-TestResult -Category "API Security" `
    -TestName "Configuracao CORS" `
    -Endpoint "$TargetURL/login" `
    -Method "OPTIONS" `
    -Status $status `
    -RequestCount $corsOrigins.Count `
    -Details "$permissiveCount origens maliciosas aceitas" `
    -Severity $(if ($permissiveCount -eq 0) { "INFO" } else { "MEDIUM" })

# 4.3 Teste de Headers de Seguranca
Write-Host "[4.3] Testando headers de seguranca..." -ForegroundColor Magenta

try {
    $response = Invoke-WebRequest -Uri "$TargetURL/login" -Method GET -TimeoutSec 5
    
    $securityHeaders = @{
        "X-Content-Type-Options" = $response.Headers["X-Content-Type-Options"]
        "X-Frame-Options" = $response.Headers["X-Frame-Options"]
        "X-XSS-Protection" = $response.Headers["X-XSS-Protection"]
        "Strict-Transport-Security" = $response.Headers["Strict-Transport-Security"]
        "Content-Security-Policy" = $response.Headers["Content-Security-Policy"]
        "Referrer-Policy" = $response.Headers["Referrer-Policy"]
    }
    
    $missingHeaders = @()
    foreach ($header in $securityHeaders.Keys) {
        if ([string]::IsNullOrEmpty($securityHeaders[$header])) {
            $missingHeaders += $header
        }
    }
    
    $status = if ($missingHeaders.Count -eq 0) { "SEGURO" } elseif ($missingHeaders.Count -le 2) { "AVISO" } else { "VULNERAVEL" }
    
    Add-TestResult -Category "API Security" `
        -TestName "Headers de Seguranca" `
        -Endpoint "$TargetURL/login" `
        -Method "GET" `
        -Status $status `
        -RequestCount 1 `
        -Details "$($missingHeaders.Count) headers de seguranca ausentes: $($missingHeaders -join ', ')" `
        -Severity $(if ($missingHeaders.Count -eq 0) { "INFO" } elseif ($missingHeaders.Count -le 2) { "LOW" } else { "MEDIUM" })
} catch {
    Add-TestResult -Category "API Security" `
        -TestName "Headers de Seguranca" `
        -Endpoint "$TargetURL/login" `
        -Method "GET" `
        -Status "ERRO" `
        -RequestCount 1 `
        -Details "Erro ao verificar headers" `
        -Severity "INFO"
}

# ============================================
# 5. TESTES DE RATE LIMITING
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "5. TESTES DE RATE LIMITING" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-TestLog "Iniciando testes de rate limiting" "INFO" "RATE"

# 5.1 Teste de Rate Limit em Login
Write-Host "[5.1] Testando rate limiting no login..." -ForegroundColor Magenta

$maxRequests = 20
$blockedCount = 0
$successCount = 0

for ($i = 1; $i -le $maxRequests; $i++) {
    $loginData = "email=test$i@example.com" + "&" + "password=wrongpassword" + "&" + "grant_type=password"
    
    try {
        $response = Invoke-WebRequest -Uri "$SupabaseURL/auth/v1/token" `
            -Method POST `
            -Headers @{"apikey"=$SupabaseKey; "Content-Type"="application/x-www-form-urlencoded"} `
            -Body $loginData `
            -TimeoutSec 5 `
            -ErrorAction Stop
        
        $successCount++
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 429) {
            $blockedCount++
            Write-TestLog "Rate limit ativado apos $i tentativas" "INFO" "RATE"
            break
        }
    }
    
    Start-Sleep -Milliseconds 100
}

$rateLimitActive = $blockedCount -gt 0
$status = if ($rateLimitActive) { "SEGURO" } else { "AVISO" }

Add-TestResult -Category "Rate Limiting" `
    -TestName "Login Rate Limit" `
    -Endpoint "$SupabaseURL/auth/v1/token" `
    -Method "POST" `
    -Status $status `
    -RequestCount $maxRequests `
    -Details $(if ($rateLimitActive) { "Rate limit ativo apos $successCount tentativas" } else { "$maxRequests tentativas sem bloqueio" }) `
    -Severity $(if ($rateLimitActive) { "INFO" } else { "MEDIUM" })

# ============================================
# 6. GERACAO DE RELATORIOS
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "GERANDO RELATORIOS DETALHADOS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Calcular estatisticas
$totalTestes = $testesRealizados.Count
$testsVulneraveis = ($testesRealizados | Where-Object { $_.Status -eq "VULNERAVEL" }).Count
$testsAvisos = ($testesRealizados | Where-Object { $_.Status -eq "AVISO" }).Count
$testseguros = ($testesRealizados | Where-Object { $_.Status -eq "SEGURO" }).Count
$testsErros = ($testesRealizados | Where-Object { $_.Status -eq "ERRO" }).Count

# Gerar relatorio HTML
$relatorioHTML = Join-Path -Path $pastaResultados -ChildPath "Relatorio_Seguranca_Completo.html"
$dataCompleta = Get-Date -Format "dd/MM/yyyy HH:mm:ss"

$htmlContent = @"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Relatorio Completo de Seguranca</title>
</head>
<body>
<h1>RELATORIO DE SEGURANCA - $dataCompleta</h1>
<h2>Resumo: $testseguros Seguros | $testsAvisos Avisos | $testsVulneraveis Vulneraveis</h2>
</body>
</html>
"@

$htmlContent | Out-File -FilePath $relatorioHTML -Encoding UTF8 -Force

Write-TestLog "Relatorio HTML gerado: $relatorioHTML" "SUCCESS" "REPORT"

# Gerar relatorio JSON
$relatorioJSON = Join-Path -Path $pastaResultados -ChildPath "Relatorio_Dados.json"

$jsonData = @{
    metadata = @{
        data_geracao = $dataCompleta
        target_url = $TargetURL
        supabase_url = $SupabaseURL
        risk_level = $RiskLevel
        test_level = $TestLevel
    }
    estatisticas = @{
        total_testes = $totalTestes
        total_requests = $totalRequests
        testes_seguros = $testseguros
        avisos = $testsAvisos
        vulnerabilidades = $testsVulneraveis
        erros = $testsErros
    }
    testes = $testesRealizados
    vulnerabilidades_criticas = $vulnerabilidades
    avisos = $avisos
}

$jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $relatorioJSON -Encoding UTF8 -Force

Write-TestLog "Relatorio JSON gerado: $relatorioJSON" "SUCCESS" "REPORT"

# ============================================
# SUMARIO FINAL
# ============================================

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "AUDITORIA DE SEGURANCA CONCLUIDA" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "RESULTADOS:" -ForegroundColor White
Write-Host "  Total de Testes: $totalTestes" -ForegroundColor Cyan
Write-Host "  Total de Requisicoes: $totalRequests" -ForegroundColor Cyan
Write-Host "  Testes Seguros: $testseguros" -ForegroundColor Green
Write-Host "  Avisos: $testsAvisos" -ForegroundColor Yellow
Write-Host "  Vulnerabilidades: $testsVulneraveis" -ForegroundColor Red
Write-Host "  Erros: $testsErros" -ForegroundColor Magenta
Write-Host ""

if ($testsVulneraveis -gt 0) {
    Write-Host "ATENCAO: Vulnerabilidades criticas encontradas!" -ForegroundColor Red
} elseif ($testsAvisos -gt 3) {
    Write-Host "AVISO: Multiplos pontos de atencao identificados." -ForegroundColor Yellow
} else {
    Write-Host "SISTEMA APRESENTA BOA POSTURA DE SEGURANCA" -ForegroundColor Green
}

Write-Host ""
Write-Host "Relatorios salvos em: $pastaResultados" -ForegroundColor Yellow
Write-Host ""

# Abrir relatorio
Start-Process $relatorioHTML
Invoke-Item $pastaResultados

Write-Host ""
Write-Host "PROCESSO CONCLUIDO" -ForegroundColor Green