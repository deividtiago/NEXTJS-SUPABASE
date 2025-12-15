# test-auth-endpoints.ps1
# Testes diretos nos endpoints do Supabase

$SUPABASE_URL = "http://localhost:54321"
$ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0"

$ENDPOINTS = @{
    "signup" = "/auth/v1/signup"
    "token" = "/auth/v1/token"
    "user" = "/auth/v1/user"
    "otp" = "/auth/v1/otp"
    "logout" = "/auth/v1/logout"
}

foreach ($name in $ENDPOINTS.Keys) {
    $endpoint = $ENDPOINTS[$name]
    $url = "$SUPABASE_URL$endpoint"
    
    Write-Host "🔐 Testando: $name ($endpoint)" -ForegroundColor Cyan
    
    # Criar arquivo de request para POST endpoints
    if ($name -in @("signup", "token", "otp")) {
        $requestFile = ".\temp-$name-request.txt"
        
        if ($name -eq "signup") {
            $data = '{"email":"test@example.com","password":"password123"}'
        } elseif ($name -eq "token") {
            $data = '{"email":"test@example.com","password":"password123","grant_type":"password"}'
        } elseif ($name -eq "otp") {
            $data = '{"email":"test@example.com","type":"magiclink"}'
        }
        
@"
POST $endpoint HTTP/1.1
Host: localhost:54321
Content-Type: application/json
apikey: $ANON_KEY
Content-Length: $($data.Length)

$data
"@ | Out-File -FilePath $requestFile
        
        sqlmap -r $requestFile `
            --batch `
            --level=3 `
            --risk=2 `
            --output-dir=".\resultados\supabase-auth\$name" `
            --flush-session
        
        Remove-Item $requestFile
    }
    # Teste GET para outros endpoints
    else {
        sqlmap -u $url `
            --headers="apikey: $ANON_KEY" `
            --batch `
            --level=2 `
            --risk=1 `
            --output-dir=".\resultados\supabase-auth\$name" `
            --flush-session
    }
}