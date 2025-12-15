# test-api-routes.ps1
# Testar API routes do Next.js que podem estar expostas

Write-Host "🔍 Testando API Routes do Next.js" -ForegroundColor Cyan

$API_ROUTES = @(
    "/api/auth",
    "/api/auth/login",
    "/api/auth/callback",
    "/api/auth/logout",
    "/api/auth/session",
    "/api/users",
    "/api/tickets"
)

foreach ($route in $API_ROUTES) {
    $url = "http://localhost:3000$route"
    Write-Host "🧪 Testando: $url" -ForegroundColor Yellow
    
    # Teste GET
    sqlmap -u $url `
        --batch `
        --level=1 `
        --risk=1 `
        --output-dir=".\resultados\api-routes\GET-$($route.Replace('/','-'))" `
        --flush-session
    
    # Teste POST se for rota de auth
    if ($route -like "*auth*") {
        $postFile = ".\temp-post-$($route.Replace('/','-')).txt"
@"
POST $route HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{"email":"test' OR '1'='1","password":"test"}
"@ | Out-File -FilePath $postFile
        
        sqlmap -r $postFile `
            --batch `
            --level=2 `
            --risk=1 `
            --output-dir=".\resultados\api-routes\POST-$($route.Replace('/','-'))" `
            --flush-session
        
        Remove-Item $postFile
    }
}