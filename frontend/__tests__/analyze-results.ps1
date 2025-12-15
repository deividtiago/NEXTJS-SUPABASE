# analyze-results.ps1
# Analisar resultados dos testes

Write-Host "📊 ANALISANDO RESULTADOS DOS TESTES" -ForegroundColor Cyan
Write-Host "======================================"

# Buscar por vulnerabilidades nos logs
$vulnerabilities = @()
$warnings = @()
$safeItems = @()

# Analisar todos os arquivos de log
Get-ChildItem -Path ".\resultados" -Recurse -Filter "*.log" | ForEach-Object {
    $content = Get-Content $_.FullName
    
    foreach ($line in $content) {
        if ($line -match "all tested parameters appear to be not injectable") {
            $safeItems += @{
                File = $_.Name
                Message = "Sem vulnerabilidades SQL Injection"
            }
        }
        elseif ($line -match "Parameter:.*injectable") {
            $vulnerabilities += @{
                File = $_.Name
                Line = $line
                Severity = "CRITICAL"
            }
        }
        elseif ($line -match "XSS") {
            $warnings += @{
                File = $_.Name
                Line = $line
                Severity = "MEDIUM"
            }
        }
    }
}

# Gerar relatório
$report = @"
# Relatório de Segurança - $(Get-Date)

## 📈 Estatísticas
- Testes realizados: $(Get-ChildItem ".\resultados" -Recurse -Filter "*.log" | Measure-Object).Count
- Vulnerabilidades críticas: $($vulnerabilities.Count)
- Avisos: $($warnings.Count)
- Itens seguros: $($safeItems.Count)

## 🔴 Vulnerabilidades Críticas
$($vulnerabilities | ForEach-Object { "- **$($_.File)**: $($_.Line)" } | Out-String)

## 🟡 Avisos
$($warnings | ForEach-Object { "- **$($_.File)**: $($_.Line)" } | Out-String)

## 🟢 Itens Seguros
$($safeItems | ForEach-Object { "- **$($_.File)**: $($_.Message)" } | Out-String)

## 🎯 Recomendações Imediatas
1. Corrigir vulnerabilidades SQL Injection encontradas
2. Implementar validação de inputs no frontend
3. Configurar headers de segurança
4. Habilitar rate limiting
"@

$report | Out-File ".\resultados\analise-final-$(Get-Date -Format 'yyyyMMdd').md"
Write-Host "📄 Relatório salvo: .\resultados\analise-final-$(Get-Date -Format 'yyyyMMdd').md"