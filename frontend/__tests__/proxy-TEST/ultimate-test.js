// __tests__/proxy-TEST/ultimate-test.js
const http = require('http');
const https = require('https');

class UltimateMiddlewareTester {
  constructor() {
    this.baseUrl = 'http://localhost:3000';
    this.timeout = 10000;
    this.testResults = [];
    this.detailedLogs = [];
  }

  log(message, type = 'info') {
    const timestamp = new Date().toISOString().split('T')[1].split('.')[0];
    const logEntry = `[${timestamp}] ${message}`;
    this.detailedLogs.push({ timestamp: Date.now(), message, type });
    
    const colors = {
      info: '\x1b[36m', // cyan
      success: '\x1b[32m', // green
      error: '\x1b[31m', // red
      warning: '\x1b[33m', // yellow
      debug: '\x1b[90m', // gray
    };
    
    const reset = '\x1b[0m';
    console.log(`${colors[type] || ''}${logEntry}${reset}`);
  }

  async makeRequest(url, method = 'GET', headers = {}, body = null) {
    const startTime = Date.now();
    const requestUrl = new URL(url, this.baseUrl);
    
    return new Promise((resolve) => {
      const options = {
        hostname: requestUrl.hostname,
        port: requestUrl.port || 3000,
        path: requestUrl.pathname + requestUrl.search,
        method,
        headers: {
          'User-Agent': 'Ultimate-Middleware-Tester/1.0',
          ...headers,
        },
        timeout: this.timeout,
      };

      const protocol = requestUrl.protocol === 'https:' ? https : http;
      const req = protocol.request(options, (res) => {
        const responseTime = Date.now() - startTime;
        
        let responseBody = '';
        res.on('data', (chunk) => {
          responseBody += chunk;
        });
        
        res.on('end', () => {
          const headers = {};
          Object.entries(res.headers).forEach(([key, value]) => {
            headers[key.toLowerCase()] = value;
          });

          resolve({
            url,
            method,
            statusCode: res.statusCode,
            statusMessage: res.statusMessage,
            headers,
            body: responseBody,
            responseTime,
            success: res.statusCode < 400,
          });
        });
      });

      req.on('error', (error) => {
        resolve({
          url,
          method,
          statusCode: 0,
          statusMessage: 'Request Failed',
          headers: {},
          body: '',
          responseTime: Date.now() - startTime,
          success: false,
          error: error.message,
        });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({
          url,
          method,
          statusCode: 0,
          statusMessage: 'Timeout',
          headers: {},
          body: '',
          responseTime: Date.now() - startTime,
          success: false,
          error: 'Request timeout',
        });
      });

      if (body && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
        req.write(body);
      }
      
      req.end();
    });
  }

  async testRoute(testCase) {
    this.log(`Testando: ${testCase.method || 'GET'} ${testCase.url}`, 'debug');
    
    const response = await this.makeRequest(
      testCase.url,
      testCase.method || 'GET',
      testCase.headers || {},
      testCase.body || null
    );

    // Análise da resposta
    const analysis = {
      passed: true,
      warnings: [],
      errors: [],
      details: [],
    };

    // Verificação de status code esperado
    if (testCase.expectedStatus && response.statusCode !== testCase.expectedStatus) {
      analysis.passed = false;
      analysis.errors.push(`Status esperado ${testCase.expectedStatus}, recebido ${response.statusCode}`);
    }

    // Verificação de redirecionamento
    if (testCase.shouldRedirect && !(response.statusCode >= 300 && response.statusCode < 400)) {
      analysis.passed = false;
      analysis.errors.push('Deveria redirecionar mas não redirecionou');
    }

    if (testCase.shouldNotRedirect && (response.statusCode >= 300 && response.statusCode < 400)) {
      analysis.passed = false;
      analysis.errors.push('Não deveria redirecionar mas redirecionou');
    }

    // Verificação de headers de segurança
    const requiredSecurityHeaders = [
      { name: 'x-content-type-options', expectedValue: 'nosniff' },
      { name: 'x-frame-options', expectedValue: 'DENY' },
      { name: 'x-xss-protection', expectedValue: '1; mode=block' },
      { name: 'referrer-policy', expectedValue: 'strict-origin-when-cross-origin' },
    ];

    requiredSecurityHeaders.forEach(({ name, expectedValue }) => {
      const actualValue = response.headers[name];
      
      if (!actualValue) {
        analysis.warnings.push(`Header de segurança ${name} ausente`);
      } else if (actualValue !== expectedValue) {
        analysis.warnings.push(`Header ${name} com valor inesperado: "${actualValue}" (esperado: "${expectedValue}")`);
      } else {
        analysis.details.push(`✅ ${name}: ${actualValue}`);
      }
    });

    // Verificação específica para APIs
    if (testCase.url.startsWith('/api/') && response.statusCode === 401) {
      try {
        const body = JSON.parse(response.body);
        if (body.error && body.message) {
          analysis.details.push(`✅ API retorna erro formatado corretamente: ${body.error} - ${body.message}`);
        }
      } catch {
        analysis.warnings.push('API 401 sem corpo JSON formatado');
      }
    }

    // Verificação de location header para redirecionamentos
    if (response.statusCode >= 300 && response.statusCode < 400) {
      const location = response.headers.location;
      if (location) {
        analysis.details.push(`↪️ Redireciona para: ${location}`);
        
        // Verifica se o redirecionamento inclui o redirect param
        if (location.includes('redirect=')) {
          analysis.details.push('✅ Redirecionamento inclui parâmetro redirect');
        }
      } else {
        analysis.warnings.push('Redirecionamento sem header Location');
      }
    }

    // Análise de tempo de resposta
    if (response.responseTime > 1000) {
      analysis.warnings.push(`Tempo de resposta alto: ${response.responseTime}ms`);
    }

    const result = {
      testCase,
      response,
      analysis,
      timestamp: Date.now(),
    };

    this.testResults.push(result);
    this.printTestResult(result);

    return result;
  }

  printTestResult(result) {
    const { testCase, response, analysis } = result;
    const icon = analysis.passed ? '✅' : '❌';
    
    console.log(`\n${icon} ${testCase.description || testCase.url}`);
    console.log(`   Método: ${testCase.method || 'GET'}`);
    console.log(`   URL: ${testCase.url}`);
    console.log(`   Status: ${response.statusCode} ${response.statusMessage}`);
    console.log(`   Tempo: ${response.responseTime}ms`);
    
    if (response.error) {
      console.log(`   ❌ Erro: ${response.error}`);
    }

    analysis.details.forEach(detail => {
      console.log(`   ${detail}`);
    });

    analysis.warnings.forEach(warning => {
      console.log(`   ⚠️  ${warning}`);
    });

    analysis.errors.forEach(error => {
      console.log(`   ❌ ${error}`);
    });
  }

  async runComprehensiveTests() {
    this.log('🚀 TESTE COMPREENSIVO DO MIDDLEWARE PROXY.TS', 'success');
    this.log('='.repeat(70), 'success');
    this.log(`URL Base: ${this.baseUrl}`, 'info');
    this.log('Testando todos os cenários possíveis...\n', 'info');

    // TODOS OS TESTES POSSÍVEIS
    const testSuite = [
      // ================== ROTAS PÚBLICAS (deveriam passar) ==================
      {
        category: 'Rotas Públicas',
        description: 'Home page - deve ser acessível sem autenticação',
        url: '/',
        expectedStatus: 200,
        shouldNotRedirect: true,
      },
      {
        category: 'Rotas Públicas',
        description: 'Página de login - deve ser acessível',
        url: '/login',
        expectedStatus: 200,
        shouldNotRedirect: true,
      },
      {
        category: 'Rotas Públicas',
        description: 'Página de registro - pode não existir (404 OK)',
        url: '/register',
        shouldNotRedirect: true,
        // Não verifica status específico pois pode não existir
      },
      {
        category: 'Rotas Públicas',
        description: 'Página de erro - deve ser acessível',
        url: '/error',
        shouldNotRedirect: true,
      },

      // ================== ROTAS PROTEGIDAS (deveriam redirecionar) ==================
      {
        category: 'Rotas Protegidas',
        description: 'Tickets - deve redirecionar para login sem auth',
        url: '/tickets',
        shouldRedirect: true,
      },
      {
        category: 'Rotas Protegidas',
        description: 'Dashboard - deve redirecionar para login sem auth',
        url: '/dashboard',
        shouldRedirect: true,
      },
      {
        category: 'Rotas Protegidas',
        description: 'Profile - deve redirecionar para login sem auth',
        url: '/profile',
        shouldRedirect: true,
      },
      {
        category: 'Rotas Protegidas',
        description: 'Settings - deve redirecionar para login sem auth',
        url: '/settings',
        shouldRedirect: true,
      },
      {
        category: 'Rotas Protegidas',
        description: 'Tickets com ID - deve redirecionar para login sem auth',
        url: '/tickets/123',
        shouldRedirect: true,
      },
      {
        category: 'Rotas Protegidas',
        description: 'Dashboard aninhado - deve redirecionar para login sem auth',
        url: '/dashboard/analytics',
        shouldRedirect: true,
      },

      // ================== APIs ==================
      {
        category: 'APIs Públicas',
        description: 'API auth callback - pode não existir (404 OK)',
        url: '/api/auth/callback',
        shouldNotRedirect: true,
      },
      {
        category: 'APIs Públicas',
        description: 'API auth qualquer - deve ser pública',
        url: '/api/auth/anything',
        shouldNotRedirect: true,
      },
      {
        category: 'APIs Protegidas',
        description: 'API protegida - deve retornar 401 sem auth',
        url: '/api/protected/data',
        expectedStatus: 401,
        shouldNotRedirect: true,
      },
      {
        category: 'APIs Protegidas',
        description: 'API protegida aninhada - deve retornar 401 sem auth',
        url: '/api/protected/v1/users',
        expectedStatus: 401,
        shouldNotRedirect: true,
      },

      // ================== ARQUIVOS ESTÁTICOS ==================
      {
        category: 'Arquivos Estáticos',
        description: 'Favicon - deve ser servido normalmente',
        url: '/favicon.ico',
        expectedStatus: 200,
        shouldNotRedirect: true,
      },
      {
        category: 'Arquivos Estáticos',
        description: 'Robots.txt - pode não existir (404 OK)',
        url: '/robots.txt',
        shouldNotRedirect: true,
      },
      {
        category: 'Arquivos Estáticos',
        description: 'Arquivo Next.js estático - deve passar',
        url: '/_next/static/test.js',
        shouldNotRedirect: true,
      },
      {
        category: 'Arquivos Estáticos',
        description: 'Arquivo com extensão .css - deve passar',
        url: '/styles.css',
        shouldNotRedirect: true,
      },
      {
        category: 'Arquivos Estáticos',
        description: 'Imagem - deve passar',
        url: '/image.jpg',
        shouldNotRedirect: true,
      },

      // ================== MÉTODOS HTTP DIFERENTES ==================
      {
        category: 'Métodos HTTP',
        description: 'POST em rota protegida - deve redirecionar',
        url: '/tickets',
        method: 'POST',
        shouldRedirect: true,
      },
      {
        category: 'Métodos HTTP',
        description: 'PUT em rota protegida - deve redirecionar',
        url: '/tickets',
        method: 'PUT',
        shouldRedirect: true,
      },
      {
        category: 'Métodos HTTP',
        description: 'DELETE em rota protegida - deve redirecionar',
        url: '/tickets',
        method: 'DELETE',
        shouldRedirect: true,
      },

      // ================== TESTES COM COOKIES (simulando auth) ==================
      {
        category: 'Com Autenticação',
        description: 'Tickets COM cookie de auth - não deve redirecionar',
        url: '/tickets',
        headers: { 'Cookie': 'sb-access-token=mock-valid-token' },
        shouldNotRedirect: true,
      },
      {
        category: 'Com Autenticação',
        description: 'Login COM auth - deve redirecionar para tickets',
        url: '/login',
        headers: { 'Cookie': 'sb-access-token=mock-valid-token' },
        shouldRedirect: true,
      },

      // ================== TESTES DE EDGE CASES ==================
      {
        category: 'Edge Cases',
        description: 'URL com query parameters - deve tratar corretamente',
        url: '/tickets?status=open&page=2',
        shouldRedirect: true,
      },
      {
        category: 'Edge Cases',
        description: 'URL com hash - deve ignorar hash',
        url: '/tickets#section',
        shouldRedirect: true,
      },
      {
        category: 'Edge Cases',
        description: 'URL muito longa - deve tratar',
        url: '/dashboard/' + 'a'.repeat(50),
        shouldRedirect: true,
      },
      {
        category: 'Edge Cases',
        description: 'Rota inexistente - pode 404',
        url: '/esta-rota-nao-existe',
        shouldNotRedirect: true,
      },
    ];

    // Executar testes por categoria
    const categories = {};
    testSuite.forEach(test => {
      if (!categories[test.category]) {
        categories[test.category] = [];
      }
      categories[test.category].push(test);
    });

    for (const [category, tests] of Object.entries(categories)) {
      this.log(`\n📂 ${category}`, 'info');
      this.log('-'.repeat(50), 'info');
      
      for (const test of tests) {
        await this.testRoute(test);
        await new Promise(resolve => setTimeout(resolve, 100)); // Rate limiting
      }
    }

    // Análise final
    this.generateComprehensiveReport();
  }

  generateComprehensiveReport() {
    this.log('\n' + '='.repeat(70), 'success');
    this.log('📊 RELATÓRIO COMPLETO DO MIDDLEWARE', 'success');
    this.log('='.repeat(70), 'success');

    // Estatísticas gerais
    const totalTests = this.testResults.length;
    const passedTests = this.testResults.filter(r => r.analysis.passed).length;
    const failedTests = totalTests - passedTests;
    const successRate = (passedTests / totalTests) * 100;

    this.log(`\n📈 ESTATÍSTICAS:`, 'info');
    this.log(`   Total de testes: ${totalTests}`, 'info');
    this.log(`   ✅ Passaram: ${passedTests}`, 'success');
    this.log(`   ❌ Falharam: ${failedTests}`, failedTests > 0 ? 'error' : 'info');
    this.log(`   📊 Taxa de sucesso: ${successRate.toFixed(1)}%`, 
      successRate > 90 ? 'success' : successRate > 70 ? 'warning' : 'error');

    // Tempo médio
    const avgTime = this.testResults.reduce((sum, r) => sum + r.response.responseTime, 0) / totalTests;
    this.log(`   ⏱️  Tempo médio: ${avgTime.toFixed(0)}ms`, 'info');

    // Análise por categoria
    this.log(`\n🏷️  DESEMPENHO POR CATEGORIA:`, 'info');
    
    const categoryStats = {};
    this.testResults.forEach(result => {
      const category = result.testCase.category;
      if (!categoryStats[category]) {
        categoryStats[category] = { total: 0, passed: 0 };
      }
      categoryStats[category].total++;
      if (result.analysis.passed) categoryStats[category].passed++;
    });

    Object.entries(categoryStats).forEach(([category, stats]) => {
      const rate = (stats.passed / stats.total) * 100;
      const icon = rate > 90 ? '✅' : rate > 70 ? '⚠️' : '❌';
      this.log(`   ${icon} ${category.padEnd(25)}: ${stats.passed}/${stats.total} (${rate.toFixed(0)}%)`, 
        rate > 90 ? 'success' : rate > 70 ? 'warning' : 'error');
    });

    // Headers de segurança
    this.log(`\n🛡️  HEADERS DE SEGURANÇA:`, 'info');
    
    const securityHeaders = ['x-content-type-options', 'x-frame-options', 'x-xss-protection', 'referrer-policy'];
    const headerStats = {};
    
    this.testResults.forEach(result => {
      securityHeaders.forEach(header => {
        if (!headerStats[header]) headerStats[header] = { present: 0, total: 0 };
        headerStats[header].total++;
        if (result.response.headers[header]) headerStats[header].present++;
      });
    });

    securityHeaders.forEach(header => {
      const stats = headerStats[header];
      const rate = (stats.present / stats.total) * 100;
      const icon = rate > 95 ? '✅' : rate > 80 ? '⚠️' : '❌';
      this.log(`   ${icon} ${header.padEnd(25)}: ${stats.present}/${stats.total} (${rate.toFixed(0)}%)`, 
        rate > 95 ? 'success' : rate > 80 ? 'warning' : 'error');
    });

    // Redirecionamentos
    const redirects = this.testResults.filter(r => 
      r.response.statusCode >= 300 && r.response.statusCode < 400
    );
    
    this.log(`\n🔄 REDIRECIONAMENTOS:`, 'info');
    this.log(`   Total: ${redirects.length}`, 'info');
    
    if (redirects.length > 0) {
      redirects.forEach(r => {
        const location = r.response.headers.location || 'N/A';
        this.log(`   ↪️  ${r.testCase.url.padEnd(30)} → ${location}`, 'debug');
      });
    }

    // Problemas identificados
    const errors = this.testResults.filter(r => !r.analysis.passed);
    
    if (errors.length > 0) {
      this.log(`\n🔴 PROBLEMAS IDENTIFICADOS (${errors.length}):`, 'error');
      
      errors.forEach((error, index) => {
        this.log(`\n   ${index + 1}. ${error.testCase.description}`, 'error');
        this.log(`      URL: ${error.testCase.url}`, 'error');
        this.log(`      Status: ${error.response.statusCode}`, 'error');
        
        if (error.analysis.errors.length > 0) {
          error.analysis.errors.forEach(err => {
            this.log(`      ❌ ${err}`, 'error');
          });
        }
        
        if (error.analysis.warnings.length > 0) {
          error.analysis.warnings.forEach(warn => {
            this.log(`      ⚠️  ${warn}`, 'warning');
          });
        }
      });
    }

    // Recomendações
    this.log(`\n💡 RECOMENDAÇÕES:`, 'info');
    
    const homePageTest = this.testResults.find(r => r.testCase.url === '/');
    if (homePageTest && homePageTest.response.statusCode === 307) {
      this.log(`   1. A home page (/) está redirecionando para login.`, 'warning');
      this.log(`      → Verifique se '/' está na lista PUBLIC_ROUTES do middleware`, 'warning');
    }

    const missingSecurityHeaders = securityHeaders.filter(header => {
      const stats = headerStats[header];
      return stats && (stats.present / stats.total) < 0.9;
    });
    
    if (missingSecurityHeaders.length > 0) {
      this.log(`   2. Headers de segurança ausentes em muitas respostas:`, 'warning');
      missingSecurityHeaders.forEach(header => {
        this.log(`      → ${header}`, 'warning');
      });
    }

    const slowTests = this.testResults.filter(r => r.response.responseTime > 1000);
    if (slowTests.length > 0) {
      this.log(`   3. ${slowTests.length} testes com resposta lenta (>1s):`, 'warning');
      slowTests.slice(0, 3).forEach(test => {
        this.log(`      → ${test.testCase.url}: ${test.response.responseTime}ms`, 'warning');
      });
    }

    // Verificação de consistência
    const protectedRoutes = this.testResults.filter(r => 
      r.testCase.category === 'Rotas Protegidas' && 
      r.response.statusCode < 300
    );
    
    if (protectedRoutes.length > 0) {
      this.log(`   4. ${protectedRoutes.length} rotas protegidas acessíveis sem autenticação:`, 'error');
      protectedRoutes.forEach(route => {
        this.log(`      → ${route.testCase.url} retornou ${route.response.statusCode}`, 'error');
      });
    }

    // Sucesso geral
    if (successRate > 90) {
      this.log(`\n🎉 EXCELENTE! Middleware funcionando muito bem!`, 'success');
    } else if (successRate > 70) {
      this.log(`\n⚠️  BOM, mas há espaço para melhorias.`, 'warning');
    } else {
      this.log(`\n🔴 ATENÇÃO! O middleware precisa de ajustes.`, 'error');
    }

    // Exportar relatório
    this.log(`\n📁 Relatório detalhado salvo em memória.`, 'info');
    this.log(`   Testes executados: ${this.detailedLogs.length} logs`, 'info');
    this.log(`   Último teste: ${new Date().toLocaleTimeString()}`, 'info');
  }
}

// Execução principal
async function main() {
  console.clear();
  
  const tester = new UltimateMiddlewareTester();
  
  console.log('='.repeat(70));
  console.log('🚀 ULTIMATE MIDDLEWARE TEST SUITE');
  console.log('='.repeat(70));
  console.log('\n⚠️  IMPORTANTE: Certifique-se de que o servidor está rodando');
  console.log('   Execute em outro terminal: npm run dev\n');
  
  console.log('⏳ Iniciando testes em 3 segundos...\n');
  
  // Contagem regressiva
  for (let i = 3; i > 0; i--) {
    console.log(`   ${i}...`);
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  
  try {
    await tester.runComprehensiveTests();
  } catch (error) {
    console.error('\n❌ ERRO CRÍTICO:', error);
    process.exit(1);
  }
}

// Executar se chamado diretamente
if (require.main === module) {
  main().catch(console.error);
}

// Exportar para uso em outros testes
module.exports = UltimateMiddlewareTester;