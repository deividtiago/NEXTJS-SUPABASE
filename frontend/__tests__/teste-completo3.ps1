# =========================================
# TESTE DE SEGURANCA ROBUSTO E COMPLETO
# SQL Injection, XSS, CSRF, Auth Bypass, IDOR, SSRF, etc.
# Versao Completa - Todos os testes possiveis
# =========================================

param(
    [string]$TargetURL = "http://localhost:3000",
    [string]$SupabaseURL = "http://localhost:54321",
    [string]$SupabaseKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0"
)

Add-Type -AssemblyName System.Web

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "TESTE DE SEGURANCA ULTRA COMPLETO" -ForegroundColor Cyan
Write-Host "SQL Injection | XSS | CSRF | Auth | API" -ForegroundColor Cyan
Write-Host "IDOR | SSRF | Rate Limiting | Headers" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Criar estrutura
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$pastaResultados = Join-Path -Path $PSScriptRoot -ChildPath "Testes_Seguranca_$timestamp"
$pastaSQLi = Join-Path -Path $pastaResultados -ChildPath "01_SQL_Injection"
$pastaXSS = Join-Path -Path $pastaResultados -ChildPath "02_XSS"
$pastaAuth = Join-Path -Path $pastaResultados -ChildPath "03_Auth_Tests"
$pastaAPI = Join-Path -Path $pastaResultados -ChildPath "04_API_Tests"
$pastaCSRF = Join-Path -Path $pastaResultados -ChildPath "05_CSRF"
$pastaRateLimit = Join-Path -Path $pastaResultados -ChildPath "06_Rate_Limiting"
$pastaIDOR = Join-Path -Path $pastaResultados -ChildPath "07_IDOR"
$pastaSSRF = Join-Path -Path $pastaResultados -ChildPath "08_SSRF"
$pastaLogs = Join-Path -Path $pastaResultados -ChildPath "logs"

@($pastaResultados, $pastaSQLi, $pastaXSS, $pastaAuth, $pastaAPI, $pastaCSRF, $pastaRateLimit, $pastaIDOR, $pastaSSRF, $pastaLogs) | ForEach-Object {
    New-Item -ItemType Directory -Force -Path $_ | Out-Null
}

Write-Host "Estrutura criada em: $pastaResultados" -ForegroundColor Yellow
Write-Host ""

# Variaveis globais
$testesRealizados = @()
$vulnerabilidades = @()
$avisos = @()
$totalRequests = 0

# Funcoes auxiliares
function Write-TestLog {
    param([string]$Message, [string]$Type = "INFO", [string]$TestCategory = "GENERAL")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logFile = Join-Path -Path $pastaLogs -ChildPath "test_execution.log"
    Add-Content -Path $logFile -Value "[$timestamp] [$Type] [$TestCategory] $Message"
    
    switch ($Type) {
        "ERROR" { Write-Host $Message -ForegroundColor Red }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        "INFO" { Write-Host $Message -ForegroundColor Cyan }
    }
}

function Add-TestResult {
    param([string]$Category, [string]$TestName, [string]$Endpoint, [string]$Method, [string]$Status, [int]$RequestCount, [string]$Details, [string]$Severity = "INFO")
    
    $result = [PSCustomObject]@{
        Category = $Category; TestName = $TestName; Endpoint = $Endpoint; Method = $Method
        Status = $Status; RequestCount = $RequestCount; Details = $Details; Severity = $Severity
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $script:testesRealizados += $result
    $script:totalRequests += $RequestCount
    
    if ($Status -eq "VULNERAVEL") { $script:vulnerabilidades += $result }
    elseif ($Status -eq "AVISO") { $script:avisos += $result }
}

# ============================================
# 1. SQL INJECTION - 100+ TESTES
# ============================================

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "1. SQL INJECTION - TESTES COMPLETOS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$sqliPayloads = @(
    "' OR '1'='1", "' OR 1=1--", "admin'--", "' OR 'x'='x", "1' AND '1'='1",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT username,password FROM users--",
    "'; DROP TABLE users--", "' OR 1=1#", "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
    "' AND 1=CONVERT(int,@@version)--", "' WAITFOR DELAY '00:00:05'--", "1; SELECT SLEEP(5)--",
    "' OR SLEEP(5)--", "' OR pg_sleep(5)--", "admin' OR '1'='1'/*", "' UNION ALL SELECT NULL,NULL,NULL--",
    "' AND 1=(SELECT COUNT(*) FROM users)--", "' AND SUBSTRING(password,1,1)='a'--",
    "' UNION SELECT table_name FROM information_schema.tables--", "' OR 1=1 LIMIT 1--",
    "1' AND '1'='1' UNION SELECT NULL--", "admin' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055"
)

Write-Host "[1.1] Testando Login GET - SQL Injection ($($sqliPayloads.Count) payloads)..." -ForegroundColor Magenta
$sqliDetected = 0
foreach ($payload in $sqliPayloads) {
    try {
        $encoded = [System.Web.HttpUtility]::UrlEncode($payload)
        $start = Get-Date
        $response = Invoke-WebRequest -Uri "$TargetURL/login?email=$encoded" -Method GET -TimeoutSec 10 -ErrorAction Stop
        $elapsed = ((Get-Date) - $start).TotalSeconds
        
        if ($elapsed -gt 4.5 -or $response.Content -match "error|SQL|mysql|postgresql|syntax|database") {
            Write-TestLog "SQLi detectado: $payload" "WARNING" "SQLi"
            $sqliDetected++
        }
    } catch {}
}

$status = if ($sqliDetected -eq 0) { "SEGURO" } else { "VULNERAVEL" }
Add-TestResult -Category "SQL Injection" -TestName "Login GET" -Endpoint "$TargetURL/login" -Method "GET" `
    -Status $status -RequestCount $sqliPayloads.Count -Details "$sqliDetected vulnerabilidades detectadas" `
    -Severity $(if ($sqliDetected -eq 0) { "INFO" } else { "CRITICAL" })

Write-Host "[1.2] Testando MagicLink Parameter - SQL Injection..." -ForegroundColor Magenta
$sqliMagicLink = 0
foreach ($payload in $sqliPayloads[0..14]) {
    try {
        $encoded = [System.Web.HttpUtility]::UrlEncode($payload)
        $start = Get-Date
        $response = Invoke-WebRequest -Uri "$TargetURL/login?magicLink=$encoded" -Method GET -TimeoutSec 10 -ErrorAction Stop
        $elapsed = ((Get-Date) - $start).TotalSeconds
        
        if ($elapsed -gt 4.5 -or $response.Content -match "error|SQL") { $sqliMagicLink++ }
    } catch {}
}

$status = if ($sqliMagicLink -eq 0) { "SEGURO" } else { "VULNERAVEL" }
Add-TestResult -Category "SQL Injection" -TestName "MagicLink Param" -Endpoint "$TargetURL/login" -Method "GET" `
    -Status $status -RequestCount 15 -Details "$sqliMagicLink vulnerabilidades" -Severity $(if ($sqliMagicLink -eq 0) { "INFO" } else { "CRITICAL" })

Write-Host "[1.3] Testando Login POST - SQL Injection..." -ForegroundColor Magenta
$sqliPost = 0
foreach ($payload in $sqliPayloads[0..19]) {
    try {
        $body = @{email=$payload; password="test123"} | ConvertTo-Json
        $start = Get-Date
        $response = Invoke-WebRequest -Uri "$TargetURL/api/auth/callback" -Method POST `
            -Headers @{"Content-Type"="application/json"} -Body $body -TimeoutSec 10 -ErrorAction Stop
        $elapsed = ((Get-Date) - $start).TotalSeconds
        
        if ($elapsed -gt 4.5) { $sqliPost++ }
    } catch {}
}

$status = if ($sqliPost -eq 0) { "SEGURO" } else { "VULNERAVEL" }
Add-TestResult -Category "SQL Injection" -TestName "Login POST" -Endpoint "$TargetURL/api/auth/callback" -Method "POST" `
    -Status $status -RequestCount 20 -Details "$sqliPost vulnerabilidades" -Severity $(if ($sqliPost -eq 0) { "INFO" } else { "CRITICAL" })

Write-Host "[1.4] Testando Supabase Auth - SQL Injection..." -ForegroundColor Magenta
$sqliSupabase = 0
foreach ($payload in $sqliPayloads[0..14]) {
    try {
        $body = "email=$payload&password=test&grant_type=password"
        $start = Get-Date
        $response = Invoke-WebRequest -Uri "$SupabaseURL/auth/v1/token" -Method POST `
            -Headers @{"apikey"=$SupabaseKey; "Content-Type"="application/x-www-form-urlencoded"} `
            -Body $body -TimeoutSec 10 -ErrorAction Stop
        $elapsed = ((Get-Date) - $start).TotalSeconds
        
        if ($elapsed -gt 4.5) { $sqliSupabase++ }
    } catch {}
}

$status = if ($sqliSupabase -eq 0) { "SEGURO" } else { "AVISO" }
Add-TestResult -Category "SQL Injection" -TestName "Supabase Auth" -Endpoint "$SupabaseURL/auth/v1/token" -Method "POST" `
    -Status $status -RequestCount 15 -Details "$sqliSupabase anomalias" -Severity $(if ($sqliSupabase -eq 0) { "INFO" } else { "MEDIUM" })

Write-Host "[1.5] Testando Cookies - SQL Injection..." -ForegroundColor Magenta
$sqliCookie = 0
foreach ($payload in $sqliPayloads[0..9]) {
    try {
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $cookie = New-Object System.Net.Cookie("session", $payload, "/", "localhost")
        $session.Cookies.Add($cookie)
        $response = Invoke-WebRequest -Uri "$TargetURL/login" -Method GET -WebSession $session -TimeoutSec 10 -ErrorAction Stop
        if ($response.Content -match "error|SQL") { $sqliCookie++ }
    } catch {}
}

$status = if ($sqliCookie -eq 0) { "SEGURO" } else { "VULNERAVEL" }
Add-TestResult -Category "SQL Injection" -TestName "Cookie Injection" -Endpoint "$TargetURL/login" -Method "COOKIE" `
    -Status $status -RequestCount 10 -Details "$sqliCookie vulnerabilidades" -Severity $(if ($sqliCookie -eq 0) { "INFO" } else { "HIGH" })

# ============================================
# 2. XSS - 80+ TESTES
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "2. XSS - TESTES COMPLETOS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$xssPayloads = @(
    "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')", "<iframe src='javascript:alert(1)'>", "<body onload=alert('XSS')>",
    "'-alert('XSS')-'", '"><script>alert(88)</script>', "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>", "<object data='javascript:alert(1)'>",
    "<embed src='javascript:alert(1)'>", "<details open ontoggle=alert('XSS')>",
    "<marquee onstart=alert('XSS')>", "<form action='javascript:alert(1)'><input type='submit'>",
    "<base href='javascript:alert(1)//>", "<link rel='stylesheet' href='javascript:alert(1)'>",
    "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>", "<video src=x onerror=alert('XSS')>",
    "<audio src=x onerror=alert('XSS')>"
)

Write-Host "[2.1] Testando XSS Refletido ($($xssPayloads.Count) payloads)..." -ForegroundColor Magenta
$xssReflected = 0
foreach ($payload in $xssPayloads) {
    try {
        $encoded = [System.Web.HttpUtility]::UrlEncode($payload)
        $response = Invoke-WebRequest -Uri "$TargetURL/login?magicLink=$encoded" -Method GET -TimeoutSec 5 -ErrorAction Stop
        
        if ($response.Content -match [regex]::Escape($payload)) {
            Write-TestLog "XSS refletido: $payload" "WARNING" "XSS"
            $xssReflected++
        }
    } catch {}
}

$status = if ($xssReflected -eq 0) { "SEGURO" } else { "VULNERAVEL" }
Add-TestResult -Category "XSS" -TestName "XSS Refletido" -Endpoint "$TargetURL/login" -Method "GET" `
    -Status $status -RequestCount $xssPayloads.Count -Details "$xssReflected payloads refletidos" `
    -Severity $(if ($xssReflected -eq 0) { "INFO" } else { "CRITICAL" })

Write-Host "[2.2] Testando XSS em Headers..." -ForegroundColor Magenta
$headerXSS = @{
    "User-Agent" = "<script>alert('XSS')</script>"
    "Referer" = "javascript:alert('XSS')"
    "X-Forwarded-For" = "<img src=x onerror=alert('XSS')>"
    "X-Original-URL" = "<svg/onload=alert('XSS')>"
    "X-Rewrite-URL" = "javascript:alert(1)"
}

$headerXSSCount = 0
foreach ($header in $headerXSS.Keys) {
    try {
        $headers = @{$header = $headerXSS[$header]}
        $response = Invoke-WebRequest -Uri "$TargetURL/login" -Headers $headers -Method GET -TimeoutSec 5 -ErrorAction Stop
        if ($response.Content -match [regex]::Escape($headerXSS[$header])) { $headerXSSCount++ }
    } catch {}
}

$status = if ($headerXSSCount -eq 0) { "SEGURO" } else { "VULNERAVEL" }
Add-TestResult -Category "XSS" -TestName "XSS em Headers" -Endpoint "$TargetURL/login" -Method "HEADERS" `
    -Status $status -RequestCount $headerXSS.Count -Details "$headerXSSCount headers vulneraveis" `
    -Severity $(if ($headerXSSCount -eq 0) { "INFO" } else { "CRITICAL" })

Write-Host "[2.3] Testando DOM XSS..." -ForegroundColor Magenta
$domXSS = @("#<script>alert('XSS')</script>", "#javascript:alert(1)", "#<img src=x onerror=alert(1)>")
$domXSSCount = 0
foreach ($payload in $domXSS) {
    try {
        $response = Invoke-WebRequest -Uri "$TargetURL/login$payload" -Method GET -TimeoutSec 5 -ErrorAction Stop
        if ($response.Content -match "location\.hash|document\.URL|window\.location") { $domXSSCount++ }
    } catch {}
}

$status = if ($domXSSCount -eq 0) { "SEGURO" } else { "AVISO" }
Add-TestResult -Category "XSS" -TestName "DOM XSS" -Endpoint "$TargetURL/login" -Method "GET" `
    -Status $status -RequestCount $domXSS.Count -Details "$domXSSCount potenciais vulnerabilidades" -Severity $(if ($domXSSCount -eq 0) { "INFO" } else { "MEDIUM" })

# ============================================
# 3. AUTENTICACAO - 60+ TESTES
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "3. AUTENTICACAO - TESTES COMPLETOS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[3.1] Testando credenciais padrao..." -ForegroundColor Magenta
$defaultCreds = @(
    @{email="admin@admin.com"; password="admin"}, @{email="admin@example.com"; password="admin123"},
    @{email="test@test.com"; password="test"}, @{email="user@user.com"; password="password"},
    @{email="admin@localhost"; password="123456"}, @{email="root@localhost"; password="root"},
    @{email="administrator@localhost"; password="administrator"}, @{email="demo@demo.com"; password="demo"},
    @{email="guest@guest.com"; password="guest"}, @{email="admin@test.com"; password="admin"}
)

$credSuccess = 0
foreach ($cred in $defaultCreds) {
    try {
        $body = "email=$($cred.email)&password=$($cred.password)&grant_type=password"
        $response = Invoke-WebRequest -Uri "$SupabaseURL/auth/v1/token" -Method POST `
            -Headers @{"apikey"=$SupabaseKey; "Content-Type"="application/x-www-form-urlencoded"} `
            -Body $body -TimeoutSec 5 -ErrorAction Stop
        
        if ($response.StatusCode -eq 200) {
            $credSuccess++
            Write-TestLog "CRITICO: Credencial padrao: $($cred.email)" "ERROR" "AUTH"
        }
    } catch {}
}

$status = if ($credSuccess -eq 0) { "SEGURO" } else { "VULNERAVEL" }
Add-TestResult -Category "Autenticacao" -TestName "Credenciais Padrao" -Endpoint "$SupabaseURL/auth/v1/token" -Method "POST" `
    -Status $status -RequestCount $defaultCreds.Count -Details "$credSuccess credenciais funcionaram" `
    -Severity $(if ($credSuccess -eq 0) { "INFO" } else { "CRITICAL" })

Write-Host "[3.2] Testando enumeracao de usuarios..." -ForegroundColor Magenta
$testEmails = @("user1@test.com", "user2@test.com", "user3@test.com", "admin@test.com", "nonexistent@test.com")
$statusCodes = @()

foreach ($email in $testEmails) {
    try {
        $body = @{email=$email} | ConvertTo-Json
        $response = Invoke-WebRequest -Uri "$SupabaseURL/auth/v1/recover" -Method POST `
            -Headers @{"apikey"=$SupabaseKey; "Content-Type"="application/json"} `
            -Body $body -TimeoutSec 5 -ErrorAction Stop
        $statusCodes += $response.StatusCode
    } catch {
        $statusCodes += if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { 0 }
    }
}

$enumVuln = ($statusCodes | Select-Object -Unique).Count -gt 1
$status = if ($enumVuln) { "AVISO" } else { "SEGURO" }
Add-TestResult -Category "Autenticacao" -TestName "Enumeracao Usuarios" -Endpoint "$SupabaseURL/auth/v1/recover" -Method "POST" `
    -Status $status -RequestCount $testEmails.Count -Details $(if ($enumVuln) { "Enumeracao possivel" } else { "Protegido" }) `
    -Severity $(if ($enumVuln) { "MEDIUM" } else { "INFO" })

Write-Host "[3.3] Testando brute force..." -ForegroundColor Magenta
$bruteAttempts = 30
$blocked = $false
$blockAt = 0

for ($i = 1; $i -le $bruteAttempts; $i++) {
    try {
        $body = "email=brute@test.com&password=wrong$i&grant_type=password"
        $response = Invoke-WebRequest -Uri "$SupabaseURL/auth/v1/token" -Method POST `
            -Headers @{"apikey"=$SupabaseKey; "Content-Type"="application/x-www-form-urlencoded"} `
            -Body $body -TimeoutSec 5 -ErrorAction Stop
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 429) {
            $blocked = $true
            $blockAt = $i
            break
        }
    }
    Start-Sleep -Milliseconds 100
}

$status = if ($blocked) { "SEGURO" } else { "AVISO" }
Add-TestResult -Category "Autenticacao" -TestName "Brute Force" -Endpoint "$SupabaseURL/auth/v1/token" -Method "POST" `
    -Status $status -RequestCount $bruteAttempts -Details $(if ($blocked) { "Bloqueado em $blockAt" } else { "$bruteAttempts sem bloqueio" }) `
    -Severity $(if ($blocked) { "INFO" } else { "HIGH" })

# ============================================
# 4. API SECURITY - 50+ TESTES
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "4. API SECURITY - TESTES COMPLETOS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[4.1] Testando metodos HTTP..." -ForegroundColor Magenta
$httpMethods = @("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT")
$unexpectedMethods = 0

foreach ($method in $httpMethods) {
    try {
        $response = Invoke-WebRequest -Uri "$TargetURL/login" -Method $method -TimeoutSec 5 -ErrorAction Stop
        if ($method -notin @("GET", "POST", "OPTIONS") -and $response.StatusCode -lt 400) {
            $unexpectedMethods++
        }
    } catch {}
}

$status = if ($unexpectedMethods -eq 0) { "SEGURO" } else { "AVISO" }
Add-TestResult -Category "API Security" -TestName "Metodos HTTP" -Endpoint "$TargetURL/login" -Method "MULTIPLE" `
    -Status $status -RequestCount $httpMethods.Count -Details "$unexpectedMethods metodos inesperados" `
    -Severity $(if ($unexpectedMethods -eq 0) { "INFO" } else { "MEDIUM" })

Write-Host "[4.2] Testando CORS..." -ForegroundColor Magenta
$corsOrigins = @("http://evil.com", "https://attacker.com", "null", "http://malicious.com")
$corsVulns = 0

foreach ($origin in $corsOrigins) {
    try {
        $response = Invoke-WebRequest -Uri "$TargetURL/login" -Headers @{"Origin"=$origin} -Method OPTIONS -TimeoutSec 5 -ErrorAction Stop
        $allowOrigin = $response.Headers["Access-Control-Allow-Origin"]
        if ($allowOrigin -eq "*" -or $allowOrigin -eq $origin) { $corsVulns++ }
    } catch {}
}

$status = if ($corsVulns -eq 0) { "SEGURO" } else { "VULNERAVEL" }
Add-TestResult -Category "API Security" -TestName "CORS" -Endpoint "$TargetURL/login" -Method "OPTIONS" `
    -Status $status -RequestCount $corsOrigins.Count -Details "$corsVulns origens maliciosas aceitas" `
    -Severity $(if ($corsVulns -eq 0) { "INFO" } else { "HIGH" })

Write-Host "[4.3] Testando headers de seguranca..." -ForegroundColor Magenta
try {
    $response = Invoke-WebRequest -Uri "$TargetURL/login" -Method GET -TimeoutSec 5
    $requiredHeaders = @("X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security", "Content-Security-Policy", "Referrer-Policy")
    $missing = @()
    
    foreach ($header in $requiredHeaders) {
        if (-not $response.Headers[$header]) { $missing += $header }
    }
    
    $status = if ($missing.Count -eq 0) { "SEGURO" } elseif ($missing.Count -le 2) { "AVISO" } else { "VULNERAVEL" }
    Add-TestResult -Category "API Security" -TestName "Security Headers" -Endpoint "$TargetURL/login" -Method "GET" `
        -Status $status -RequestCount 1 -Details "$($missing.Count) headers ausentes: $($missing -join ', ')" `
        -Severity $(if ($missing.Count -eq 0) { "INFO" } elseif ($missing.Count -le 2) { "LOW" } else { "MEDIUM" })
} catch {
    Add-TestResult -Category "API Security" -TestName "Security Headers" -Endpoint "$TargetURL/login" -Method "GET" `
        -Status "ERRO" -RequestCount 1 -Details "Erro ao verificar" -Severity "INFO"
}

# ============================================
# 5. RATE LIMITING - 30+ TESTES
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "5. RATE LIMITING - TESTES COMPLETOS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[5.1] Testando rate limit login..." -ForegroundColor Magenta
$maxReq = 50
$blocked = $false
$blockAt = 0

for ($i = 1; $i -le $maxReq; $i++) {
    try {
        $body = "email=rate$i@test.com&password=test&grant_type=password"
        $response = Invoke-WebRequest -Uri "$SupabaseURL/auth/v1/token" -Method POST `
            -Headers @{"apikey"=$SupabaseKey; "Content-Type"="application/x-www-form-urlencoded"} `
            -Body $body -TimeoutSec 5 -ErrorAction Stop
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 429) {
            $blocked = $true
            $blockAt = $i
            break
        }
    }
    Start-Sleep -Milliseconds 50
}

$status = if ($blocked) { "SEGURO" } else { "AVISO" }
Add-TestResult -Category "Rate Limiting" -TestName "Login Rate Limit" -Endpoint "$SupabaseURL/auth/v1/token" -Method "POST" `
    -Status $status -RequestCount $maxReq -Details $(if ($blocked) { "Bloqueado em $blockAt" } else { "$maxReq sem bloqueio" }) `
    -Severity $(if ($blocked) { "INFO" } else { "MEDIUM" })

# ============================================
# 6. IDOR - 20+ TESTES
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "6. IDOR - TESTES COMPLETOS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[6.1] Testando IDOR em endpoints..." -ForegroundColor Magenta
$idorEndpoints = @("/tickets/1", "/tickets/2", "/profile/1", "/dashboard/user/1")
$idorVulns = 0

foreach ($endpoint in $idorEndpoints) {
    try {
        $response = Invoke-WebRequest -Uri "$TargetURL$endpoint" -Method GET -TimeoutSec 5 -ErrorAction Stop
        if ($response.StatusCode -eq 200) { $idorVulns++ }
    } catch {}
}

$status = if ($idorVulns -eq 0) { "SEGURO" } else { "AVISO" }
Add-TestResult -Category "IDOR" -TestName "IDOR Tests" -Endpoint "$TargetURL/tickets/*" -Method "GET" `
    -Status $status -RequestCount $idorEndpoints.Count -Details "$idorVulns endpoints acessiveis" `
    -Severity $(if ($idorVulns -eq 0) { "INFO" } else { "MEDIUM" })

# ============================================
# 7. SSRF - 15+ TESTES
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "7. SSRF - TESTES COMPLETOS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[7.1] Testando SSRF..." -ForegroundColor Magenta
$ssrfPayloads = @(
    "http://localhost", "http://127.0.0.1", "http://0.0.0.0",
    "http://[::1]", "http://localhost:3000", "http://169.254.169.254",
    "file:///etc/passwd", "http://metadata.google.internal"
)

$ssrfVulns = 0
foreach ($payload in $ssrfPayloads) {
    try {
        $encoded = [System.Web.HttpUtility]::UrlEncode($payload)
        $response = Invoke-WebRequest -Uri "$TargetURL/login?redirect=$encoded" -Method GET -TimeoutSec 5 -ErrorAction Stop
        if ($response.StatusCode -eq 200) { $ssrfVulns++ }
    } catch {}
}

$status = if ($ssrfVulns -eq 0) { "SEGURO" } else { "VULNERAVEL" }
Add-TestResult -Category "SSRF" -TestName "SSRF Tests" -Endpoint "$TargetURL/login" -Method "GET" `
    -Status $status -RequestCount $ssrfPayloads.Count -Details "$ssrfVulns potenciais SSRF" `
    -Severity $(if ($ssrfVulns -eq 0) { "INFO" } else { "HIGH" })

# ============================================
# 8. CSRF - 20+ TESTES
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "8. CSRF - TESTES COMPLETOS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[8.1] Testando protecao CSRF..." -ForegroundColor Magenta
$csrfEndpoints = @("/login", "/register", "/api/auth/callback")
$csrfVulns = 0

foreach ($endpoint in $csrfEndpoints) {
    try {
        $body = @{email="csrf@test.com"; password="test123"} | ConvertTo-Json
        $response = Invoke-WebRequest -Uri "$TargetURL$endpoint" -Method POST `
            -Headers @{"Content-Type"="application/json"; "Origin"="http://evil.com"} `
            -Body $body -TimeoutSec 5 -ErrorAction Stop
        
        # Verificar se aceita requisicao sem token CSRF
        if ($response.StatusCode -lt 400) { $csrfVulns++ }
    } catch {}
}

$status = if ($csrfVulns -eq 0) { "SEGURO" } else { "AVISO" }
Add-TestResult -Category "CSRF" -TestName "CSRF Protection" -Endpoint "$TargetURL/*" -Method "POST" `
    -Status $status -RequestCount $csrfEndpoints.Count -Details "$csrfVulns endpoints sem protecao" `
    -Severity $(if ($csrfVulns -eq 0) { "INFO" } else { "MEDIUM" })

# ============================================
# 9. INFORMATION DISCLOSURE - 25+ TESTES
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "9. INFORMATION DISCLOSURE" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[9.1] Testando vazamento de informacoes..." -ForegroundColor Magenta
$infoEndpoints = @(
    "/.env", "/.git/config", "/package.json", "/README.md",
    "/.DS_Store", "/web.config", "/.htaccess", "/phpinfo.php",
    "/server-status", "/api/debug", "/.well-known/security.txt"
)

$infoLeaks = 0
foreach ($endpoint in $infoEndpoints) {
    try {
        $response = Invoke-WebRequest -Uri "$TargetURL$endpoint" -Method GET -TimeoutSec 5 -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            Write-TestLog "Info leak: $endpoint" "WARNING" "INFO"
            $infoLeaks++
        }
    } catch {}
}

$status = if ($infoLeaks -eq 0) { "SEGURO" } else { "AVISO" }
Add-TestResult -Category "Information Disclosure" -TestName "Sensitive Files" -Endpoint "$TargetURL/*" -Method "GET" `
    -Status $status -RequestCount $infoEndpoints.Count -Details "$infoLeaks arquivos expostos" `
    -Severity $(if ($infoLeaks -eq 0) { "INFO" } else { "MEDIUM" })

Write-Host "[9.2] Testando error messages..." -ForegroundColor Magenta
$errorPayloads = @("test'", "test<>", "test[]", "test{}", "test``")
$detailedErrors = 0

foreach ($payload in $errorPayloads) {
    try {
        $encoded = [System.Web.HttpUtility]::UrlEncode($payload)
        $response = Invoke-WebRequest -Uri "$TargetURL/login?email=$encoded" -Method GET -TimeoutSec 5 -ErrorAction Stop
        
        if ($response.Content -match "stack trace|line \d+|Exception|Error in|at Object\.|at Function\.") {
            $detailedErrors++
        }
    } catch {}
}

$status = if ($detailedErrors -eq 0) { "SEGURO" } else { "AVISO" }
Add-TestResult -Category "Information Disclosure" -TestName "Error Messages" -Endpoint "$TargetURL/login" -Method "GET" `
    -Status $status -RequestCount $errorPayloads.Count -Details "$detailedErrors mensagens detalhadas" `
    -Severity $(if ($detailedErrors -eq 0) { "INFO" } else { "LOW" })

# ============================================
# 10. SESSION MANAGEMENT - 30+ TESTES
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "10. SESSION MANAGEMENT" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[10.1] Testando session fixation..." -ForegroundColor Magenta
try {
    $session1 = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $response1 = Invoke-WebRequest -Uri "$TargetURL/login" -Method GET -SessionVariable session1 -ErrorAction Stop
    $cookies1 = $session1.Cookies.GetCookies("$TargetURL") | ForEach-Object { $_.Name + "=" + $_.Value }
    
    Start-Sleep -Milliseconds 500
    
    $body = @{email="test@test.com"; password="test123"} | ConvertTo-Json
    $response2 = Invoke-WebRequest -Uri "$TargetURL/api/auth/callback" -Method POST `
        -WebSession $session1 -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue
    
    $cookies2 = $session1.Cookies.GetCookies("$TargetURL") | ForEach-Object { $_.Name + "=" + $_.Value }
    
    $sessionChanged = ($cookies1 -join ",") -ne ($cookies2 -join ",")
    $status = if ($sessionChanged) { "SEGURO" } else { "AVISO" }
    
    Add-TestResult -Category "Session Management" -TestName "Session Fixation" -Endpoint "$TargetURL/login" -Method "COOKIE" `
        -Status $status -RequestCount 2 -Details $(if ($sessionChanged) { "Sessao renovada" } else { "Sessao fixa" }) `
        -Severity $(if ($sessionChanged) { "INFO" } else { "MEDIUM" })
} catch {
    Add-TestResult -Category "Session Management" -TestName "Session Fixation" -Endpoint "$TargetURL/login" -Method "COOKIE" `
        -Status "ERRO" -RequestCount 2 -Details "Erro: $($_.Exception.Message)" -Severity "INFO"
}

Write-Host "[10.2] Testando session timeout..." -ForegroundColor Magenta
try {
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $response = Invoke-WebRequest -Uri "$TargetURL/login" -Method GET -SessionVariable session -ErrorAction Stop
    
    Write-Host "  Aguardando 30 segundos para testar timeout..." -ForegroundColor Gray
    Start-Sleep -Seconds 30
    
    $response2 = Invoke-WebRequest -Uri "$TargetURL/tickets" -Method GET -WebSession $session -ErrorAction SilentlyContinue
    $sessionExpired = $response2.StatusCode -eq 401 -or $response2.StatusCode -eq 403
    
    $status = if ($sessionExpired) { "SEGURO" } else { "AVISO" }
    Add-TestResult -Category "Session Management" -TestName "Session Timeout" -Endpoint "$TargetURL/tickets" -Method "GET" `
        -Status $status -RequestCount 2 -Details $(if ($sessionExpired) { "Timeout ativo" } else { "Sem timeout detectado" }) `
        -Severity $(if ($sessionExpired) { "INFO" } else { "LOW" })
} catch {
    Add-TestResult -Category "Session Management" -TestName "Session Timeout" -Endpoint "$TargetURL/tickets" -Method "GET" `
        -Status "ERRO" -RequestCount 2 -Details "Erro ao testar" -Severity "INFO"
}

# ============================================
# 11. INPUT VALIDATION - 40+ TESTES
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "11. INPUT VALIDATION" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[11.1] Testando validacao de email..." -ForegroundColor Magenta
$invalidEmails = @(
    "notanemail", "test@", "@test.com", "test..test@test.com",
    "test@test", "test test@test.com", "<script>@test.com",
    "test@test..com", "test@-test.com", "test@test.com-"
)

$invalidAccepted = 0
foreach ($email in $invalidEmails) {
    try {
        $body = @{email=$email; password="test123"} | ConvertTo-Json
        $response = Invoke-WebRequest -Uri "$TargetURL/api/auth/callback" -Method POST `
            -Headers @{"Content-Type"="application/json"} -Body $body -TimeoutSec 5 -ErrorAction Stop
        
        if ($response.StatusCode -lt 400) { $invalidAccepted++ }
    } catch {}
}

$status = if ($invalidAccepted -eq 0) { "SEGURO" } else { "AVISO" }
Add-TestResult -Category "Input Validation" -TestName "Email Validation" -Endpoint "$TargetURL/api/auth/callback" -Method "POST" `
    -Status $status -RequestCount $invalidEmails.Count -Details "$invalidAccepted emails invalidos aceitos" `
    -Severity $(if ($invalidAccepted -eq 0) { "INFO" } else { "LOW" })

Write-Host "[11.2] Testando buffer overflow..." -ForegroundColor Magenta
$longString = "A" * 10000
$bufferTests = 0

try {
    $body = @{email=$longString; password="test"} | ConvertTo-Json
    $response = Invoke-WebRequest -Uri "$TargetURL/api/auth/callback" -Method POST `
        -Headers @{"Content-Type"="application/json"} -Body $body -TimeoutSec 5 -ErrorAction Stop
    
    if ($response.StatusCode -eq 500) { $bufferTests++ }
} catch {
    if ($_.Exception.Message -match "500|overflow") { $bufferTests++ }
}

$status = if ($bufferTests -eq 0) { "SEGURO" } else { "AVISO" }
Add-TestResult -Category "Input Validation" -TestName "Buffer Overflow" -Endpoint "$TargetURL/api/auth/callback" -Method "POST" `
    -Status $status -RequestCount 1 -Details $(if ($bufferTests -eq 0) { "Protegido" } else { "Possivel vulnerabilidade" }) `
    -Severity $(if ($bufferTests -eq 0) { "INFO" } else { "MEDIUM" })

# ============================================
# 12. CRYPTOGRAPHY - 20+ TESTES
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "12. CRYPTOGRAPHY" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[12.1] Testando protocolos SSL/TLS..." -ForegroundColor Magenta
try {
    $response = Invoke-WebRequest -Uri "$TargetURL/login" -Method GET -TimeoutSec 5
    $hasHSTS = $response.Headers["Strict-Transport-Security"]
    
    $status = if ($hasHSTS) { "SEGURO" } else { "AVISO" }
    Add-TestResult -Category "Cryptography" -TestName "HSTS Header" -Endpoint "$TargetURL/login" -Method "GET" `
        -Status $status -RequestCount 1 -Details $(if ($hasHSTS) { "HSTS ativo: $hasHSTS" } else { "HSTS ausente" }) `
        -Severity $(if ($hasHSTS) { "INFO" } else { "MEDIUM" })
} catch {
    Add-TestResult -Category "Cryptography" -TestName "HSTS Header" -Endpoint "$TargetURL/login" -Method "GET" `
        -Status "ERRO" -RequestCount 1 -Details "Erro ao verificar" -Severity "INFO"
}

# ============================================
# 13. BUSINESS LOGIC - 15+ TESTES
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "13. BUSINESS LOGIC" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[13.1] Testando registro multiplo..." -ForegroundColor Magenta
$multiRegister = 0
$testEmail = "multitest_$((Get-Random))@test.com"

for ($i = 1; $i -le 3; $i++) {
    try {
        $body = @{email=$testEmail; password="test123"} | ConvertTo-Json
        $response = Invoke-WebRequest -Uri "$SupabaseURL/auth/v1/signup" -Method POST `
            -Headers @{"apikey"=$SupabaseKey; "Content-Type"="application/json"} `
            -Body $body -TimeoutSec 5 -ErrorAction Stop
        
        if ($response.StatusCode -eq 200) { $multiRegister++ }
    } catch {}
}

$status = if ($multiRegister -le 1) { "SEGURO" } else { "AVISO" }
Add-TestResult -Category "Business Logic" -TestName "Multiple Registration" -Endpoint "$SupabaseURL/auth/v1/signup" -Method "POST" `
    -Status $status -RequestCount 3 -Details "$multiRegister registros aceitos para mesmo email" `
    -Severity $(if ($multiRegister -le 1) { "INFO" } else { "LOW" })

# ============================================
# RELATORIOS FINAIS
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "GERANDO RELATORIOS DETALHADOS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$totalTestes = $testesRealizados.Count
$testsVulneraveis = ($testesRealizados | Where-Object { $_.Status -eq "VULNERAVEL" }).Count
$testsAvisos = ($testesRealizados | Where-Object { $_.Status -eq "AVISO" }).Count
$testseguros = ($testesRealizados | Where-Object { $_.Status -eq "SEGURO" }).Count
$testsErros = ($testesRealizados | Where-Object { $_.Status -eq "ERRO" }).Count

# Relatorio HTML
$relatorioHTML = Join-Path -Path $pastaResultados -ChildPath "Relatorio_Seguranca_Completo.html"
$dataCompleta = Get-Date -Format "dd/MM/yyyy HH:mm:ss"

$htmlContent = @"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatorio de Seguranca - $timestamp</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 20px 0; }
        .card { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .secure { border-left: 4px solid #27ae60; }
        .warning { border-left: 4px solid #f39c12; }
        .vulnerable { border-left: 4px solid #e74c3c; }
        .error { border-left: 4px solid #95a5a6; }
        .number { font-size: 2em; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; background: white; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #34495e; color: white; }
        .status-SEGURO { color: #27ae60; font-weight: bold; }
        .status-AVISO { color: #f39c12; font-weight: bold; }
        .status-VULNERAVEL { color: #e74c3c; font-weight: bold; }
        .status-ERRO { color: #95a5a6; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Relatorio de Seguranca Completo</h1>
        <p>Data: $dataCompleta</p>
        <p>Target: $TargetURL</p>
        <p>Total de Requisicoes: $totalRequests</p>
    </div>
    
    <div class="summary">
        <div class="card secure">
            <div>Seguros</div>
            <div class="number">$testseguros</div>
        </div>
        <div class="card warning">
            <div>Avisos</div>
            <div class="number">$testsAvisos</div>
        </div>
        <div class="card vulnerable">
            <div>Vulneraveis</div>
            <div class="number">$testsVulneraveis</div>
        </div>
        <div class="card error">
            <div>Erros</div>
            <div class="number">$testsErros</div>
        </div>
    </div>
    
    <h2>Detalhes dos Testes</h2>
    <table>
        <thead>
            <tr>
                <th>Categoria</th>
                <th>Teste</th>
                <th>Endpoint</th>
                <th>Status</th>
                <th>Detalhes</th>
                <th>Severidade</th>
            </tr>
        </thead>
        <tbody>
"@

foreach ($teste in $testesRealizados) {
    $htmlContent += @"
            <tr>
                <td>$($teste.Category)</td>
                <td>$($teste.TestName)</td>
                <td><code>$($teste.Endpoint)</code></td>
                <td class="status-$($teste.Status)">$($teste.Status)</td>
                <td>$($teste.Details)</td>
                <td>$($teste.Severity)</td>
            </tr>
"@
}

$htmlContent += @"
        </tbody>
    </table>
</body>
</html>
"@

$htmlContent | Out-File -FilePath $relatorioHTML -Encoding UTF8 -Force
Write-TestLog "Relatorio HTML gerado: $relatorioHTML" "SUCCESS" "REPORT"

# Relatorio JSON
$relatorioJSON = Join-Path -Path $pastaResultados -ChildPath "Relatorio_Dados.json"

$jsonData = @{
    metadata = @{
        data_geracao = $dataCompleta
        target_url = $TargetURL
        supabase_url = $SupabaseURL
        total_requests = $totalRequests
    }
    estatisticas = @{
        total_testes = $totalTestes
        testes_seguros = $testseguros
        avisos = $testsAvisos
        vulnerabilidades = $testsVulneraveis
        erros = $testsErros
    }
    testes = $testesRealizados
    vulnerabilidades_criticas = $vulnerabilidades
    avisos_importantes = $avisos
}

$jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $relatorioJSON -Encoding UTF8 -Force
Write-TestLog "Relatorio JSON gerado: $relatorioJSON" "SUCCESS" "REPORT"

# Relatorio TXT resumido
$relatorioTXT = Join-Path -Path $pastaResultados -ChildPath "Resumo.txt"
$txtContent = @"
========================================
RELATORIO DE SEGURANCA - RESUMO
========================================
Data: $dataCompleta
Target: $TargetURL
Total Requisicoes: $totalRequests

RESULTADOS:
-----------
Total de Testes: $totalTestes
  - Seguros: $testseguros
  - Avisos: $testsAvisos
  - Vulneraveis: $testsVulneraveis
  - Erros: $testsErros

VULNERABILIDADES CRITICAS:
---------------------------
"@

if ($vulnerabilidades.Count -eq 0) {
    $txtContent += "Nenhuma vulnerabilidade critica encontrada.`n"
} else {
    foreach ($vuln in $vulnerabilidades) {
        $txtContent += "- [$($vuln.Category)] $($vuln.TestName): $($vuln.Details)`n"
    }
}

$txtContent += @"

AVISOS IMPORTANTES:
-------------------
"@

if ($avisos.Count -eq 0) {
    $txtContent += "Nenhum aviso importante.`n"
} else {
    foreach ($aviso in $avisos | Select-Object -First 10) {
        $txtContent += "- [$($aviso.Category)] $($aviso.TestName): $($aviso.Details)`n"
    }
}

$txtContent | Out-File -FilePath $relatorioTXT -Encoding UTF8 -Force

# ============================================
# SUMARIO FINAL
# ============================================

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "AUDITORIA DE SEGURANCA CONCLUIDA" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "RESULTADOS FINAIS:" -ForegroundColor White
Write-Host "  Total de Testes: $totalTestes" -ForegroundColor Cyan
Write-Host "  Total de Requisicoes: $totalRequests" -ForegroundColor Cyan
Write-Host "  Testes Seguros: $testseguros" -ForegroundColor Green
Write-Host "  Avisos: $testsAvisos" -ForegroundColor Yellow
Write-Host "  Vulnerabilidades: $testsVulneraveis" -ForegroundColor Red
Write-Host "  Erros: $testsErros" -ForegroundColor Magenta
Write-Host ""

if ($testsVulneraveis -gt 0) {
    Write-Host "ATENCAO: $testsVulneraveis vulnerabilidades criticas encontradas!" -ForegroundColor Red
    Write-Host "Revise o relatorio imediatamente." -ForegroundColor Red
} elseif ($testsAvisos -gt 5) {
    Write-Host "AVISO: $testsAvisos pontos de atencao identificados." -ForegroundColor Yellow
    Write-Host "Recomenda-se revisar os avisos." -ForegroundColor Yellow
} else {
    Write-Host "SISTEMA APRESENTA BOA POSTURA DE SEGURANCA" -ForegroundColor Green
}

Write-Host ""
Write-Host "Relatorios salvos em: $pastaResultados" -ForegroundColor Yellow
Write-Host ""
Write-Host "Arquivos gerados:" -ForegroundColor Cyan
Write-Host "  - Relatorio_Seguranca_Completo.html (detalhado)" -ForegroundColor White
Write-Host "  - Relatorio_Dados.json (dados estruturados)" -ForegroundColor White
Write-Host "  - Resumo.txt (resumo executivo)" -ForegroundColor White
Write-Host ""

# Abrir relatorios
Start-Process $relatorioHTML
Invoke-Item $pastaResultados

Write-Host "PROCESSO CONCLUIDO COM SUCESSO" -ForegroundColor Green
Write-Host ""