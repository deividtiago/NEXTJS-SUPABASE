# =========================================
# ADVANCED SECURITY TESTING FRAMEWORK
# =========================================

#region Parameters
param(
    [Parameter(Mandatory = $false)]
    [string]$TargetURL = "http://localhost:3000",
    
    [Parameter(Mandatory = $false)]
    [string]$SupabaseURL = "http://localhost:54321",
    
    [Parameter(Mandatory = $false)]
    [string]$SupabaseKey,
    
    [Parameter(Mandatory = $false)]
    [string]$WordlistPath,
    
    [Parameter(Mandatory = $false)]
    [int]$MaxConcurrentRequests = 5,
    
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
    
    $statusSymbol = switch($Status) {
        "VULNERABLE" { "[X]" }
        "WARNING" { "[!]" }
        "SECURE" { "[OK]" }
        "INFO" { "[i]" }
        "ERROR" { "[E]" }
        default { "[ ]" }
    }
    
    Write-Host "$statusSymbol " -NoNewline -ForegroundColor $color
    Write-Host "$Category - ${TestName}: $Details" -ForegroundColor $color
    
    # Log to file
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
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "       SECURITY TESTING FRAMEWORK                " -ForegroundColor Cyan
Write-Host "            Advanced Edition                     " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "`n"

Write-Host "=================================================" -ForegroundColor Yellow
Write-Host " Target:          $($TargetURL.PadRight(30))" -ForegroundColor Yellow
Write-Host " Scan Mode:       $($ScanMode.PadRight(30))" -ForegroundColor Yellow
Write-Host " Timestamp:       $((Get-Date -Format 'yyyy-MM-dd HH:mm:ss').PadRight(30))" -ForegroundColor Yellow
Write-Host "=================================================" -ForegroundColor Yellow
Write-Host "`n"
#endregion

#region Phase 1: Reconnaissance
Write-Host "`n=================================================" -ForegroundColor Magenta
Write-Host "PHASE 1: RECONNAISSANCE" -ForegroundColor Magenta
Write-Host "=================================================" -ForegroundColor Magenta

Write-Log "Starting Phase 1: Reconnaissance" -Console

# Get target IP
try {
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
        -Details "Target is not reachable" -Status "ERROR" -Severity "INFO"
    Write-Host "ERROR: Target is not reachable. Exiting..." -ForegroundColor Red
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
Write-Host "`n=================================================" -ForegroundColor Magenta
Write-Host "PHASE 2: VULNERABILITY SCANNING" -ForegroundColor Magenta
Write-Host "=================================================" -ForegroundColor Magenta

Write-Log "Starting Phase 2: Vulnerability Scanning" -Console

# Test 1: Advanced SQL Injection
Write-Host "`n[2.1] Testing SQL Injection (Advanced)..." -ForegroundColor Gray
$sqliPayloads = @(
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1' /*",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' AND 1=CAST((SELECT @@version) AS INT)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)--",
    "' OR IF(1=1,SLEEP(5),0)--"
)

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
    "<script>alert('XSS')</script>",
    "<script>confirm('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<svg onload=alert('XSS')>"
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

Write-Host "`nScan completed. Check the reports directory for detailed results." -ForegroundColor Green
Write-Host "Reports directory: $($directories.Reports)" -ForegroundColor Cyan

#endregion