# =========================================
# TESTE DE SEGURANCA SIMPLIFICADO
# =========================================

param(
    [string]$TargetURL = "http://localhost:3000",
    [string]$SupabaseURL = "http://localhost:54321",
    [string]$SupabaseKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0"
)

Add-Type -AssemblyName System.Web
$ErrorActionPreference = "SilentlyContinue"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "SECURITY TESTING FRAMEWORK - SIMPLIFIED" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Target: $TargetURL" -ForegroundColor Yellow
Write-Host "`n"

# ============================================
# CONFIGURAÇÃO
# ============================================

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$baseDir = Join-Path $PSScriptRoot "SecurityAudit_$timestamp"

$directories = @{
    Base = $baseDir
    Reports = Join-Path $baseDir "reports"
    Evidence = Join-Path $baseDir "evidence"
    Logs = Join-Path $baseDir "logs"
}

$directories.Values | ForEach-Object { New-Item -ItemType Directory -Force -Path $_ | Out-Null }

# ============================================
# VARIÁVEIS
# ============================================

$global:results = @()
$global:vulnerabilities = @()
$global:warnings = @()
$global:stats = @{
    TotalRequests = 0
    TotalTests = 0
    ExecutionTime = [System.Diagnostics.Stopwatch]::StartNew()
}

# ============================================
# FUNÇÕES
# ============================================

function Add-TestResult {
    param(
        [string]$Category,
        [string]$TestName,
        [string]$Details,
        [string]$Status,
        [string]$Severity = "INFO"
    )
    
    $result = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category = $Category
        TestName = $TestName
        Details = $Details
        Status = $Status
        Severity = $Severity
    }
    
    $global:results += $result
    $global:stats.TotalTests++
    
    if($Status -eq "VULNERABLE") { $global:vulnerabilities += $result }
    elseif($Status -eq "WARNING") { $global:warnings += $result }
    
    $color = switch($Status) {
        "VULNERABLE" { "Red" }
        "WARNING" { "Yellow" }
        "SECURE" { "Green" }
        default { "White" }
    }
    
    # Usar ${} para delimitar nomes de variáveis com caracteres especiais
    Write-Host "[$Status] $Category - ${TestName}: $Details" -ForegroundColor $color
}

# ============================================
# TESTES DE SEGURANÇA
# ============================================

Write-Host "Executing Security Tests..." -ForegroundColor Magenta
Write-Host "---------------------------" -ForegroundColor Magenta

# Teste 1: SQL Injection básico
Write-Host "`n[1/6] Testing SQL Injection..." -ForegroundColor Gray
$sqliPayloads = @("' OR '1'='1", "' AND 1=1--", "'; DROP TABLE users--")
$sqliDetected = 0

foreach($payload in $sqliPayloads) {
    try {
        $encoded = [System.Web.HttpUtility]::UrlEncode($payload)
        $response = Invoke-WebRequest -Uri "$TargetURL/login?email=$encoded" -Method GET -TimeoutSec 5
        $global:stats.TotalRequests++
        
        if($response.Content -match "error|SQL|mysql|syntax") {
            $sqliDetected++
        }
    } catch {
        $global:stats.TotalRequests++
    }
}

if($sqliDetected -gt 0) {
    Add-TestResult -Category "SQL Injection" -TestName "Basic SQLi Test" `
        -Details "$sqliDetected SQL injection attempts successful" `
        -Status "VULNERABLE" -Severity "CRITICAL"
} else {
    Add-TestResult -Category "SQL Injection" -TestName "Basic SQLi Test" `
        -Details "No SQL injection vulnerabilities detected" `
        -Status "SECURE" -Severity "INFO"
}

# Teste 2: XSS básico
Write-Host "`n[2/6] Testing XSS..." -ForegroundColor Gray
$xssPayloads = @("<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>")
$xssDetected = 0

foreach($payload in $xssPayloads) {
    try {
        $encoded = [System.Web.HttpUtility]::UrlEncode($payload)
        $response = Invoke-WebRequest -Uri "$TargetURL/search?q=$encoded" -Method GET -TimeoutSec 5
        $global:stats.TotalRequests++
        
        if($response.Content -match [regex]::Escape($payload)) {
            $xssDetected++
        }
    } catch {
        $global:stats.TotalRequests++
    }
}

if($xssDetected -gt 0) {
    Add-TestResult -Category "Cross-Site Scripting" -TestName "Basic XSS Test" `
        -Details "$xssDetected XSS payloads reflected" `
        -Status "VULNERABLE" -Severity "HIGH"
} else {
    Add-TestResult -Category "Cross-Site Scripting" -TestName "Basic XSS Test" `
        -Details "No XSS vulnerabilities detected" `
        -Status "SECURE" -Severity "INFO"
}

# Teste 3: Autenticação - Credenciais padrão
Write-Host "`n[3/6] Testing default credentials..." -ForegroundColor Gray
$defaultCreds = @(
    @{email="admin@admin.com"; password="admin"},
    @{email="administrator@localhost"; password="administrator"}
)

$credSuccess = 0
foreach($cred in $defaultCreds) {
    try {
        $body = "email=$($cred.email)&password=$($cred.password)&grant_type=password"
        $response = Invoke-WebRequest -Uri "$SupabaseURL/auth/v1/token" -Method POST `
            -Headers @{"apikey"=$SupabaseKey; "Content-Type"="application/x-www-form-urlencoded"} `
            -Body $body -TimeoutSec 5
        $global:stats.TotalRequests++
        
        if($response.StatusCode -eq 200) {
            $credSuccess++
        }
    } catch {
        $global:stats.TotalRequests++
    }
}

if($credSuccess -gt 0) {
    Add-TestResult -Category "Authentication" -TestName "Default Credentials" `
        -Details "$credSuccess successful logins with default credentials" `
        -Status "VULNERABLE" -Severity "CRITICAL"
} else {
    Add-TestResult -Category "Authentication" -TestName "Default Credentials" `
        -Details "No default credentials found" `
        -Status "SECURE" -Severity "INFO"
}

# Teste 4: Information Disclosure
Write-Host "`n[4/6] Testing information disclosure..." -ForegroundColor Gray
$sensitiveFiles = @("/.env", "/package.json")
$exposed = 0

foreach($file in $sensitiveFiles) {
    try {
        $response = Invoke-WebRequest -Uri "$TargetURL$file" -Method GET -TimeoutSec 5
        $global:stats.TotalRequests++
        
        if($response.StatusCode -eq 200) { 
            $exposed++ 
        }
    } catch {
        $global:stats.TotalRequests++
    }
}

if($exposed -gt 0) {
    Add-TestResult -Category "Information Disclosure" -TestName "Sensitive File Exposure" `
        -Details "$exposed sensitive files exposed" `
        -Status "WARNING" -Severity "MEDIUM"
} else {
    Add-TestResult -Category "Information Disclosure" -TestName "Sensitive File Exposure" `
        -Details "No sensitive files exposed" `
        -Status "SECURE" -Severity "INFO"
}

# Teste 5: Security Headers
Write-Host "`n[5/6] Testing security headers..." -ForegroundColor Gray
try {
    $response = Invoke-WebRequest -Uri "$TargetURL/" -Method GET -TimeoutSec 5
    $global:stats.TotalRequests++
    
    $requiredHeaders = @("X-Content-Type-Options", "X-Frame-Options")
    $missing = $requiredHeaders | Where-Object { -not $response.Headers[$_] }
    
    if($missing.Count -gt 0) {
        Add-TestResult -Category "Security Headers" -TestName "HTTP Security Headers" `
            -Details "$($missing.Count) headers missing: $($missing -join ', ')" `
            -Status "WARNING" -Severity "MEDIUM"
    } else {
        Add-TestResult -Category "Security Headers" -TestName "HTTP Security Headers" `
            -Details "All security headers present" `
            -Status "SECURE" -Severity "INFO"
    }
} catch {
    $global:stats.TotalRequests++
    Add-TestResult -Category "Security Headers" -TestName "HTTP Security Headers" `
        -Details "Could not test security headers" `
        -Status "ERROR" -Severity "INFO"
}

# Teste 6: API Endpoint Exposure
Write-Host "`n[6/6] Testing API endpoint exposure..." -ForegroundColor Gray
$apiEndpoints = @("/api/users", "/api/admin", "/api/config")
$accessible = 0

foreach($endpoint in $apiEndpoints) {
    try {
        $response = Invoke-WebRequest -Uri "$TargetURL$endpoint" -Method GET -TimeoutSec 5
        $global:stats.TotalRequests++
        
        if($response.StatusCode -eq 200) { 
            $accessible++ 
        }
    } catch {
        $global:stats.TotalRequests++
    }
}

if($accessible -gt 0) {
    Add-TestResult -Category "API Security" -TestName "API Endpoint Exposure" `
        -Details "$accessible API endpoints accessible without auth" `
        -Status "WARNING" -Severity "MEDIUM"
} else {
    Add-TestResult -Category "API Security" -TestName "API Endpoint Exposure" `
        -Details "API endpoints properly protected" `
        -Status "SECURE" -Severity "INFO"
}

# ============================================
# RELATÓRIOS
# ============================================

Write-Host "`n`n=========================================" -ForegroundColor Cyan
Write-Host "GENERATING REPORTS" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

$stats.ExecutionTime.Stop()
$executionMinutes = [Math]::Round($stats.ExecutionTime.Elapsed.TotalMinutes, 2)

# Estatísticas
$totalVulnerabilities = $global:vulnerabilities.Count
$totalWarnings = $global:warnings.Count
$totalSecure = ($global:results | Where-Object { $_.Status -eq "SECURE" }).Count
$totalErrors = ($global:results | Where-Object { $_.Status -eq "ERROR" }).Count

# Relatório TXT
$reportTXT = Join-Path $directories.Reports "security_report.txt"

$txtContent = "=========================================`n"
$txtContent += "SECURITY AUDIT REPORT`n"
$txtContent += "=========================================`n`n"
$txtContent += "Date: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')`n"
$txtContent += "Target: $TargetURL`n"
$txtContent += "Execution Time: $executionMinutes minutes`n"
$txtContent += "Total Requests: $($stats.TotalRequests)`n"
$txtContent += "Total Tests: $($stats.TotalTests)`n`n"

$txtContent += "OVERALL RESULTS:`n"
$txtContent += "=========================================`n"
$txtContent += "Total Tests: $($stats.TotalTests)`n"
$txtContent += "  Secure: $totalSecure`n"
$txtContent += "  Warnings: $totalWarnings`n"
$txtContent += "  Vulnerabilities: $totalVulnerabilities`n"
$txtContent += "  Errors: $totalErrors`n`n"

$txtContent += "DETAILED RESULTS:`n"
$txtContent += "=========================================`n"

foreach($result in $global:results) {
    $txtContent += "[$($result.Status)] $($result.Category) - $($result.TestName)`n"
    $txtContent += "  Details: $($result.Details)`n"
    $txtContent += "  Severity: $($result.Severity)`n"
    $txtContent += "  Time: $($result.Timestamp)`n`n"
}

$txtContent += "CRITICAL VULNERABILITIES:`n"
$txtContent += "=========================================`n"

if($global:vulnerabilities.Count -eq 0) {
    $txtContent += "None found - Excellent!`n`n"
} else {
    foreach($vuln in $global:vulnerabilities) {
        $txtContent += "[$($vuln.Severity)] $($vuln.Category) - $($vuln.TestName)`n"
        $txtContent += "  Details: $($vuln.Details)`n`n"
    }
}

$txtContent += "RECOMMENDATIONS:`n"
$txtContent += "=========================================`n"
$txtContent += "1. Implement parameterized queries to prevent SQL Injection`n"
$txtContent += "2. Add Content Security Policy headers to mitigate XSS`n"
$txtContent += "3. Remove all default accounts and credentials`n"
$txtContent += "4. Restrict access to sensitive files and directories`n"
$txtContent += "5. Enable security headers (X-Content-Type-Options, X-Frame-Options, HSTS)`n"
$txtContent += "6. Implement proper authentication for all API endpoints`n`n"

$txtContent += "=========================================`n"
$txtContent += "Report saved to: $reportTXT`n"
$txtContent += "Audit directory: $baseDir`n"
$txtContent += "=========================================`n"

$txtContent | Out-File -FilePath $reportTXT -Encoding UTF8

# Relatório JSON
$reportJSON = Join-Path $directories.Reports "audit_data.json"
$jsonData = @{
    metadata = @{
        timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        target = $TargetURL
        execution_time_minutes = $executionMinutes
        total_requests = $stats.TotalRequests
        total_tests = $stats.TotalTests
    }
    statistics = @{
        secure = $totalSecure
        warnings = $totalWarnings
        vulnerabilities = $totalVulnerabilities
        errors = $totalErrors
    }
    results = $global:results
}

$jsonData | ConvertTo-Json -Depth 5 | Out-File -FilePath $reportJSON -Encoding UTF8

# ============================================
# SUMÁRIO FINAL
# ============================================

Write-Host "`n=========================================" -ForegroundColor Green
Write-Host "AUDIT COMPLETED SUCCESSFULLY" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green

Write-Host "FINAL STATISTICS:" -ForegroundColor Cyan
Write-Host "  Total Tests: $($stats.TotalTests)" -ForegroundColor White
Write-Host "  Total Requests: $($stats.TotalRequests)" -ForegroundColor White
Write-Host "  Execution Time: $executionMinutes minutes" -ForegroundColor White
Write-Host "  Secure: $totalSecure" -ForegroundColor Green
Write-Host "  Warnings: $totalWarnings" -ForegroundColor Yellow
Write-Host "  Vulnerabilities: $totalVulnerabilities" -ForegroundColor Red
Write-Host "  Errors: $totalErrors" -ForegroundColor Magenta
Write-Host ""

if($totalVulnerabilities -gt 0) {
    Write-Host "CRITICAL: $totalVulnerabilities vulnerabilities found!" -ForegroundColor Red
    Write-Host "Immediate remediation required!" -ForegroundColor Red
} elseif($totalWarnings -gt 0) {
    Write-Host "WARNING: $totalWarnings issues require attention" -ForegroundColor Yellow
} else {
    Write-Host "EXCELLENT: System shows good security posture" -ForegroundColor Green
}

Write-Host ""
Write-Host "REPORTS GENERATED:" -ForegroundColor Cyan
Write-Host "  TXT Report: $reportTXT" -ForegroundColor White
Write-Host "  JSON Data: $reportJSON" -ForegroundColor White
Write-Host "  Audit Directory: $baseDir" -ForegroundColor White
Write-Host ""

# Abrir relatório
try {
    Invoke-Item $reportTXT
    Invoke-Item $directories.Reports
    Write-Host "Reports opened successfully" -ForegroundColor Green
} catch {
    Write-Host "Could not open reports automatically" -ForegroundColor Yellow
}

Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host "SECURITY AUDIT COMPLETE" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan