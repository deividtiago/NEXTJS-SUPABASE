# =========================================
# TESTE DE SEGURANÇA ULTRA ROBUSTO E COMPLETO
# Versão 3.4 - Testes de Segurança
# =========================================

param(
    [string]$TargetURL = "http://localhost:3000",
    [string]$SupabaseURL = "http://localhost:54321",
    [string]$SupabaseKey = $env:SUPABASE_KEY,
    [int]$Timeout = 30,
    [switch]$SlowMode = $false
)

# =========================================
# INICIALIZAÇÃO
# =========================================

Add-Type -AssemblyName System.Web

# Criar diretório para resultados
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$pastaResultados = Join-Path -Path $PSScriptRoot -ChildPath "Security_Audit_$timestamp"
New-Item -ItemType Directory -Force -Path $pastaResultados | Out-Null

# =========================================
# FUNÇÕES UTILITÁRIAS
# =========================================

function Write-Log {
    param([string]$Message, [string]$Type = "INFO")
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    $color = @{
        "ERROR" = "Red"
        "WARNING" = "Yellow"
        "INFO" = "Cyan"
        "SUCCESS" = "Green"
        "DEBUG" = "Gray"
    }
    
    if ($color.ContainsKey($Type)) {
        Write-Host "[$timestamp] $Message" -ForegroundColor $color[$Type]
    } else {
        Write-Host "[$timestamp] $Message"
    }
}

function Invoke-SafeRequest {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [string]$Body = $null,
        [string]$ContentType = "application/json"
    )
    
    try {
        $request = [System.Net.HttpWebRequest]::Create($Uri)
        $request.Method = $Method
        $request.Timeout = $Timeout * 1000
        $request.UserAgent = "SecurityAuditBot/3.4"
        
        foreach ($key in $Headers.Keys) {
            if ($key -eq "Content-Type") {
                $request.ContentType = $Headers[$key]
            } else {
                $request.Headers.Add($key, $Headers[$key])
            }
        }
        
        if ($Body -and $Method -in @("POST", "PUT", "PATCH")) {
            $byteArray = [System.Text.Encoding]::UTF8.GetBytes($Body)
            $request.ContentLength = $byteArray.Length
            
            $dataStream = $request.GetRequestStream()
            $dataStream.Write($byteArray, 0, $byteArray.Length)
            $dataStream.Close()
        }
        
        $response = $request.GetResponse()
        $streamReader = New-Object System.IO.StreamReader($response.GetResponseStream())
        $content = $streamReader.ReadToEnd()
        $streamReader.Close()
        
        return @{
            StatusCode = [int]$response.StatusCode
            Content = $content
            Headers = @{}
            Successful = $true
        }
        
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) {
            $errorResponse = $_.Exception.Response
            $errorStream = $errorResponse.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorStream)
            $errorContent = $reader.ReadToEnd()
            $reader.Close()
            
            return @{
                StatusCode = [int]$errorResponse.StatusCode
                Content = $errorContent
                Headers = @{}
                Successful = $false
            }
        }
        return @{StatusCode = 0; Content = $_.Exception.Message; Successful = $false}
    } catch {
        return @{StatusCode = 0; Content = $_.Exception.Message; Successful = $false}
    }
}

# =========================================
# TESTES DE SEGURANÇA
# =========================================

function Test-SQLInjection {
    Write-Log "Testando SQL Injection..." "INFO"
    
    $test = @{
        Category = "SQL Injection"
        TestName = "Basic SQLi"
        Endpoint = "$TargetURL/login"
        Method = "GET"
        Status = "SEGURO"
        Details = "0 vulnerabilidades"
        Severity = "INFO"
    }
    
    $payloads = @(
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "' UNION SELECT NULL--"
    )
    
    $detected = 0
    foreach ($payload in $payloads) {
        $encoded = [System.Web.HttpUtility]::UrlEncode($payload)
        $response = Invoke-SafeRequest -Uri "$TargetURL/login?email=$encoded"
        
        if ($response.Content -match "SQL|mysql|postgres|syntax|error") {
            $detected++
        }
        
        if ($SlowMode) { Start-Sleep -Milliseconds 100 }
    }
    
    if ($detected -gt 0) {
        $test.Status = "VULNERAVEL"
        $test.Details = "$detected vulnerabilidades detectadas"
        $test.Severity = "CRITICAL"
    }
    
    $test.RequestCount = $payloads.Count
    $test.Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    return $test
}

function Test-XSS {
    Write-Log "Testando XSS..." "INFO"
    
    $test = @{
        Category = "XSS"
        TestName = "Reflected XSS"
        Endpoint = "$TargetURL/search"
        Method = "GET"
        Status = "SEGURO"
        Details = "0 payloads refletidos"
        Severity = "INFO"
    }
    
    $payloads = @(
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')"
    )
    
    $reflected = 0
    foreach ($payload in $payloads) {
        $encoded = [System.Web.HttpUtility]::UrlEncode($payload)
        $response = Invoke-SafeRequest -Uri "$TargetURL/search?q=$encoded"
        
        if ($response.Content -match [regex]::Escape($payload)) {
            $reflected++
        }
    }
    
    if ($reflected -gt 0) {
        $test.Status = "VULNERAVEL"
        $test.Details = "$reflected payloads refletidos"
        $test.Severity = "HIGH"
    }
    
    $test.RequestCount = $payloads.Count
    $test.Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    return $test
}

function Test-Authentication {
    Write-Log "Testando Autenticacao..." "INFO"
    
    $test = @{
        Category = "Authentication"
        TestName = "Default Credentials"
        Endpoint = "$SupabaseURL/auth/v1/token"
        Method = "POST"
        Status = "SEGURO"
        Details = "0 credenciais funcionaram"
        Severity = "INFO"
    }
    
    if (-not $SupabaseKey) {
        $test.Status = "ERRO"
        $test.Details = "SupabaseKey nao configurada"
        return $test
    }
    
    $defaultCreds = @(
        @{email="admin@admin.com"; password="admin"},
        @{email="test@test.com"; password="test"}
    )
    
    $success = 0
    foreach ($cred in $defaultCreds) {
        $body = "email=$($cred.email)&password=$($cred.password)&grant_type=password"
        $headers = @{
            "apikey" = $SupabaseKey
            "Content-Type" = "application/x-www-form-urlencoded"
        }
        
        $response = Invoke-SafeRequest -Uri "$SupabaseURL/auth/v1/token" -Method "POST" -Headers $headers -Body $body
        
        if ($response.StatusCode -eq 200) {
            $success++
        }
    }
    
    if ($success -gt 0) {
        $test.Status = "VULNERAVEL"
        $test.Details = "$success credenciais padrao funcionaram"
        $test.Severity = "CRITICAL"
    }
    
    $test.RequestCount = $defaultCreds.Count
    $test.Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    return $test
}

function Test-RateLimiting {
    Write-Log "Testando Rate Limiting..." "INFO"
    
    $test = @{
        Category = "Rate Limiting"
        TestName = "Login Rate Limit"
        Endpoint = "$SupabaseURL/auth/v1/token"
        Method = "POST"
        Status = "AVISO"
        Details = "Teste basico"
        Severity = "MEDIUM"
    }
    
    if (-not $SupabaseKey) {
        $test.Status = "ERRO"
        $test.Details = "SupabaseKey nao configurada"
        return $test
    }
    
    $maxRequests = 10
    $blocked = $false
    
    for ($i = 1; $i -le $maxRequests; $i++) {
        $body = "email=test$i@test.com&password=wrong&grant_type=password"
        $headers = @{
            "apikey" = $SupabaseKey
            "Content-Type" = "application/x-www-form-urlencoded"
        }
        
        $response = Invoke-SafeRequest -Uri "$SupabaseURL/auth/v1/token" -Method "POST" -Headers $headers -Body $body
        
        if ($response.StatusCode -eq 429) {
            $blocked = $true
            $test.Details = "Bloqueado apos $i tentativas"
            $test.Status = "SEGURO"
            $test.Severity = "INFO"
            break
        }
        
        Start-Sleep -Milliseconds 50
    }
    
    if (-not $blocked) {
        $test.Details = "$maxRequests requisicoes sem bloqueio"
        $test.Status = "AVISO"
        $test.Severity = "MEDIUM"
    }
    
    $test.RequestCount = $maxRequests
    $test.Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    return $test
}

function Test-SecurityHeaders {
    Write-Log "Testando Security Headers..." "INFO"
    
    $test = @{
        Category = "API Security"
        TestName = "Security Headers"
        Endpoint = "$TargetURL"
        Method = "GET"
        Status = "SEGURO"
        Details = "Headers verificados"
        Severity = "INFO"
    }
    
    try {
        $response = Invoke-SafeRequest -Uri "$TargetURL"
        
        $requiredHeaders = @(
            "X-Content-Type-Options",
            "X-Frame-Options", 
            "X-XSS-Protection"
        )
        
        $missing = @()
        foreach ($header in $requiredHeaders) {
            if (-not $response.Headers[$header]) {
                $missing += $header
            }
        }
        
        if ($missing.Count -gt 0) {
            $test.Status = "AVISO"
            $test.Details = "$($missing.Count) headers ausentes: $($missing -join ', ')"
            $test.Severity = "LOW"
        }
    } catch {
        $test.Status = "ERRO"
        $test.Details = "Erro ao verificar headers"
    }
    
    $test.RequestCount = 1
    $test.Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    return $test
}

function Test-HTTPMethods {
    Write-Log "Testando Metodos HTTP..." "INFO"
    
    $test = @{
        Category = "API Security"
        TestName = "HTTP Methods"
        Endpoint = "$TargetURL/api"
        Method = "MULTIPLE"
        Status = "SEGURO"
        Details = "Metodos testados"
        Severity = "INFO"
    }
    
    $methods = @("GET", "POST", "PUT", "DELETE", "OPTIONS")
    $dangerous = @()
    
    foreach ($method in $methods) {
        $response = Invoke-SafeRequest -Uri "$TargetURL/api" -Method $method
        
        if ($method -in @("PUT", "DELETE") -and $response.StatusCode -lt 400) {
            $dangerous += "$method ($($response.StatusCode))"
        }
    }
    
    if ($dangerous.Count -gt 0) {
        $test.Status = "AVISO"
        $test.Details = "Metodos perigosos permitidos: $($dangerous -join ', ')"
        $test.Severity = "MEDIUM"
    }
    
    $test.RequestCount = $methods.Count
    $test.Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    return $test
}

function Test-BusinessLogic {
    Write-Log "Testando Business Logic..." "INFO"
    
    $test = @{
        Category = "Business Logic"
        TestName = "Multiple Registration"
        Endpoint = "$SupabaseURL/auth/v1/signup"
        Method = "POST"
        Status = "SEGURO"
        Details = "Registro unico"
        Severity = "INFO"
    }
    
    if (-not $SupabaseKey) {
        $test.Status = "ERRO"
        $test.Details = "SupabaseKey nao configurada"
        return $test
    }
    
    $testEmail = "multitest_$((Get-Random))@test.com"
    $registrations = 0
    
    for ($i = 1; $i -le 3; $i++) {
        $body = @{
            email = $testEmail
            password = "test123"
        } | ConvertTo-Json
        
        $headers = @{
            "apikey" = $SupabaseKey
            "Content-Type" = "application/json"
        }
        
        $response = Invoke-SafeRequest -Uri "$SupabaseURL/auth/v1/signup" -Method "POST" -Headers $headers -Body $body
        
        if ($response.StatusCode -eq 200) {
            $registrations++
        }
    }
    
    if ($registrations -gt 1) {
        $test.Status = "AVISO"
        $test.Details = "$registrations registros aceitos para mesmo email"
        $test.Severity = "LOW"
    }
    
    $test.RequestCount = 3
    $test.Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    return $test
}

# =========================================
# EXECUÇÃO DOS TESTES
# =========================================

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "AUDITORIA DE SEGURANCA" -ForegroundColor Cyan
Write-Host "Target: $TargetURL" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

$testFunctions = @(
    @{Name="Test-SQLInjection"; Description="SQL Injection"}
    @{Name="Test-XSS"; Description="Cross-Site Scripting"}
    @{Name="Test-Authentication"; Description="Autenticacao"}
    @{Name="Test-RateLimiting"; Description="Rate Limiting"}
    @{Name="Test-SecurityHeaders"; Description="Security Headers"}
    @{Name="Test-HTTPMethods"; Description="HTTP Methods"}
    @{Name="Test-BusinessLogic"; Description="Business Logic"}
)

$allResults = @()
$startTime = Get-Date

foreach ($testFunc in $testFunctions) {
    Write-Host ">> " -NoNewline -ForegroundColor Cyan
    Write-Host "$($testFunc.Description)..." -ForegroundColor White
    
    try {
        $result = & $testFunc.Name
        $allResults += $result
        
        $statusColor = @{
            "VULNERAVEL" = "Red"
            "AVISO" = "Yellow"
            "SEGURO" = "Green"
            "ERRO" = "Magenta"
        }
        
        Write-Host "  Status: " -NoNewline -ForegroundColor Gray
        Write-Host "$($result.Status) " -NoNewline -ForegroundColor $statusColor[$result.Status]
        Write-Host "($($result.Severity))" -ForegroundColor Gray
        
    } catch {
        Write-Host "  ERRO: $($_.Exception.Message)" -ForegroundColor Red
        
        $errorResult = @{
            Category = "ERROR"
            TestName = $testFunc.Name
            Status = "ERRO"
            Details = $_.Exception.Message
            Severity = "INFO"
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            RequestCount = 0
        }
        $allResults += $errorResult
    }
}

# =========================================
# RELATÓRIOS
# =========================================

$duration = [math]::Round(((Get-Date) - $startTime).TotalMinutes, 2)
$total = $allResults.Count
$vulnerable = ($allResults | Where-Object { $_.Status -eq "VULNERAVEL" }).Count
$warning = ($allResults | Where-Object { $_.Status -eq "AVISO" }).Count
$secure = ($allResults | Where-Object { $_.Status -eq "SEGURO" }).Count
$error = ($allResults | Where-Object { $_.Status -eq "ERRO" }).Count

# Calcular total de requests
$totalRequests = 0
foreach ($result in $allResults) {
    $totalRequests += $result.RequestCount
}

# Relatório JSON (compatível com formato anterior)
$jsonReport = @{
    vulnerabilidades_criticas = @()
    avisos_importantes = $allResults | Where-Object { $_.Status -eq "AVISO" }
    testes = $allResults
    estatisticas = @{
        vulnerabilidades = $vulnerable
        erros = $error
        avisos = $warning
        total_testes = $total
        testes_seguros = $secure
    }
    metadata = @{
        data_geracao = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
        supabase_url = $SupabaseURL
        total_requests = $totalRequests
        target_url = $TargetURL
    }
}

$jsonReportPath = Join-Path -Path $pastaResultados -ChildPath "Relatorio_Dados.json"
$jsonReport | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonReportPath -Encoding UTF8

# Relatório TXT simples
$txtReport = @"
========================================
RELATORIO DE SEGURANCA
========================================
Data: $(Get-Date -Format "dd/MM/yyyy HH:mm:ss")
Target: $TargetURL
Duracao: ${duration} minutos

RESUMO:
  Total de Testes: $total
  Seguros: $secure
  Avisos: $warning
  Vulnerabilidades: $vulnerable
  Erros: $error
  Total de Requisicoes: $totalRequests

DETALHES DOS TESTES:
"@

foreach ($result in $allResults) {
    $txtReport += @"
  
[$($result.Category)] $($result.TestName)
  Status: $($result.Status) ($($result.Severity))
  Endpoint: $($result.Endpoint)
  Method: $($result.Method)
  Detalhes: $($result.Details)
  Timestamp: $($result.Timestamp)
  Requests: $($result.RequestCount)
"@
}

$txtReportPath = Join-Path -Path $pastaResultados -ChildPath "Resumo.txt"
$txtReport | Out-File -FilePath $txtReportPath -Encoding UTF8

# =========================================
# RELATÓRIO FINAL
# =========================================

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "AUDITORIA CONCLUIDA" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "RESULTADOS:" -ForegroundColor White
Write-Host "  Total de Testes: $total" -ForegroundColor Cyan
Write-Host "  Seguros: $secure" -ForegroundColor Green
Write-Host "  Avisos: $warning" -ForegroundColor Yellow
Write-Host "  Vulnerabilidades: $vulnerable" -ForegroundColor $(if ($vulnerable -gt 0) { "Red" } else { "Green" })
Write-Host "  Erros: $error" -ForegroundColor Magenta
Write-Host "  Total Requisicoes: $totalRequests" -ForegroundColor Cyan
Write-Host ""
Write-Host "Duracao: ${duration} minutos" -ForegroundColor Cyan

if ($vulnerable -gt 0) {
    Write-Host ""
    Write-Host "ATENCAO: VULNERABILIDADES ENCONTRADAS!" -ForegroundColor Red
    foreach ($result in $allResults | Where-Object { $_.Status -eq "VULNERAVEL" }) {
        Write-Host "  [$($result.Severity)] $($result.TestName)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Relatorios salvos em:" -ForegroundColor Cyan
Write-Host "  $pastaResultados" -ForegroundColor Yellow
Write-Host ""
Write-Host "Arquivos gerados:" -ForegroundColor White
Write-Host "  - Relatorio_Dados.json (dados completos)" -ForegroundColor Gray
Write-Host "  - Resumo.txt (relatorio textual)" -ForegroundColor Gray

# Abrir pasta de resultados
try {
    Invoke-Item $pastaResultados
} catch {
    Write-Host "  Nota: Pasta criada em: $pastaResultados" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "PROCESSO CONCLUIDO" -ForegroundColor Green