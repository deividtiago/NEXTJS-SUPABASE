// __tests__/proxy-TEST/real-test.js
const http = require('http');

class MiddlewareTester {
  constructor() {
    this.baseUrl = 'http://localhost:3000';
    this.timeout = 5000;
  }

  async testRoute(url, expectedStatus, description, cookies = {}) {
    const startTime = Date.now();
    
    return new Promise((resolve) => {
      const requestUrl = new URL(url, this.baseUrl);
      
      const options = {
        hostname: requestUrl.hostname,
        port: requestUrl.port || 3000,
        path: requestUrl.pathname + requestUrl.search,
        method: 'GET',
        timeout: this.timeout,
        headers: {
          'User-Agent': 'Middleware-Tester/1.0',
        },
      };

      // Adiciona cookies se fornecidos
      if (cookies && Object.keys(cookies).length > 0) {
        const cookieString = Object.entries(cookies)
          .map(([key, value]) => `${key}=${value}`)
          .join('; ');
        options.headers.Cookie = cookieString;
      }

      const req = http.request(options, (res) => {
        const responseTime = Date.now() - startTime;
        
        const headers = {};
        Object.entries(res.headers).forEach(([key, value]) => {
          if (typeof value === 'string') {
            headers[key.toLowerCase()] = value;
          } else if (Array.isArray(value)) {
            headers[key.toLowerCase()] = value.join(', ');
          }
        });

        const result = {
          url,
          expectedStatus,
          actualStatus: res.statusCode || 0,
          passed: res.statusCode === expectedStatus,
          headers,
          responseTime,
        };

        this.printResult(description, result);
        resolve(result);
      });

      req.on('error', (error) => {
        const responseTime = Date.now() - startTime;
        const result = {
          url,
          expectedStatus,
          actualStatus: 0,
          passed: false,
          headers: {},
          responseTime,
          error: error.message,
        };

        this.printResult(description, result);
        resolve(result);
      });

      req.on('timeout', () => {
        req.destroy();
        const responseTime = Date.now() - startTime;
        const result = {
          url,
          expectedStatus,
          actualStatus: 0,
          passed: false,
          headers: {},
          responseTime,
          error: 'Timeout',
        };

        this.printResult(description, result);
        resolve(result);
      });

      req.end();
    });
  }

  printResult(description, result) {
    const icon = result.passed ? '✅' : '❌';
    
    console.log(`${icon} ${description}`);
    console.log(`  URL: ${result.url}`);
    console.log(`  Esperado: ${result.expectedStatus}, Recebido: ${result.actualStatus}`);
    console.log(`  Tempo: ${result.responseTime}ms`);
    
    if (result.error) {
      console.log(`  Erro: ${result.error}`);
    }

    // Mostra headers importantes
    const importantHeaders = [
      'x-content-type-options',
      'x-frame-options', 
      'location',
      'content-type',
    ];

    importantHeaders.forEach(header => {
      if (result.headers[header]) {
        console.log(`  ${header}: ${result.headers[header]}`);
      }
    });

    console.log('');
  }

  async runAllTests() {
    console.log('🚀 TESTANDO MIDDLEWARE DO PROXY.TS');
    console.log('='.repeat(50));
    console.log(`URL base: ${this.baseUrl}`);
    console.log(`Certifique-se de que o servidor está rodando: npm run dev\n`);

    const tests = [
      // Rotas públicas (deveriam retornar 200)
      { url: '/', expected: 200, desc: 'Home page pública', cookies: {} },
      { url: '/login', expected: 200, desc: 'Página de login pública', cookies: {} },
      { url: '/register', expected: 200, desc: 'Página de registro pública', cookies: {} },
      { url: '/forgot-password', expected: 200, desc: 'Página de recuperação', cookies: {} },
      
      // Rotas protegidas sem autenticação (deveriam redirecionar - 307)
      { url: '/tickets', expected: 307, desc: 'Tickets sem autenticação', cookies: {} },
      { url: '/dashboard', expected: 307, desc: 'Dashboard sem autenticação', cookies: {} },
      { url: '/profile', expected: 307, desc: 'Profile sem autenticação', cookies: {} },
      { url: '/settings', expected: 307, desc: 'Settings sem autenticação', cookies: {} },
      
      // APIs
      { url: '/api/auth/callback', expected: 200, desc: 'API auth callback pública', cookies: {} },
      { url: '/api/protected/data', expected: 401, desc: 'API protegida sem auth', cookies: {} },
      
      // Arquivos estáticos
      { url: '/favicon.ico', expected: 200, desc: 'Favicon', cookies: {} },
      { url: '/robots.txt', expected: 200, desc: 'Robots.txt', cookies: {} },
    ];

    const results = [];
    
    for (const test of tests) {
      const result = await this.testRoute(
        test.url, 
        test.expected, 
        test.desc, 
        test.cookies
      );
      results.push(result);
      
      // Pequena pausa entre requisições
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    this.printSummary(results);
    
    // Verificação de headers de segurança
    this.checkSecurityHeaders(results[0]);
  }

  printSummary(results) {
    const passed = results.filter(r => r.passed).length;
    const total = results.length;
    const percentage = (passed / total) * 100;
    
    console.log('\n📊 RESUMO DOS TESTES');
    console.log('='.repeat(50));
    console.log(`Total de testes: ${total}`);
    console.log(`Passaram: ${passed}`);
    console.log(`Falharam: ${total - passed}`);
    console.log(`Taxa de sucesso: ${percentage.toFixed(1)}%\n`);
    
    // Tempo médio
    const avgTime = results.reduce((sum, r) => sum + r.responseTime, 0) / total;
    console.log(`Tempo médio de resposta: ${avgTime.toFixed(2)}ms`);
    
    // Testes que falharam
    const failedTests = results.filter(r => !r.passed);
    if (failedTests.length > 0) {
      console.log('\n🔍 TESTES QUE FALHARAM:');
      failedTests.forEach(test => {
        console.log(`- ${test.url}`);
        console.log(`  Esperado: ${test.expectedStatus}, Recebido: ${test.actualStatus}`);
        if (test.error) console.log(`  Erro: ${test.error}`);
      });
    }
    
    if (passed === total) {
      console.log('\n🎉 PARABÉNS! Todos os testes passaram!');
    } else {
      console.log('\n⚠️  Alguns testes falharam. Verifique seu middleware.');
      process.exit(1);
    }
  }

  checkSecurityHeaders(result) {
    console.log('\n🛡️ VERIFICAÇÃO DE HEADERS DE SEGURANÇA');
    console.log('='.repeat(50));
    
    const requiredHeaders = [
      { key: 'x-content-type-options', expected: 'nosniff' },
      { key: 'x-frame-options', expected: 'DENY' },
      { key: 'x-xss-protection', expected: '1; mode=block' },
      { key: 'referrer-policy', expected: 'strict-origin-when-cross-origin' },
    ];
    
    let allPresent = true;
    
    requiredHeaders.forEach(({ key, expected }) => {
      const actual = result.headers[key];
      const hasHeader = !!actual;
      const matches = actual === expected;
      
      if (hasHeader && matches) {
        console.log(`✅ ${key}: ${actual} (CORRETO)`);
      } else if (hasHeader && !matches) {
        console.log(`⚠️  ${key}: ${actual} (esperado: ${expected})`);
        allPresent = false;
      } else {
        console.log(`❌ ${key}: AUSENTE (esperado: ${expected})`);
        allPresent = false;
      }
    });
    
    if (allPresent) {
      console.log('\n✅ Todos os headers de segurança estão presentes e corretos!');
    } else {
      console.log('\n⚠️  Alguns headers de segurança estão faltando ou incorretos.');
    }
  }
}

// Executar se chamado diretamente
if (require.main === module) {
  const tester = new MiddlewareTester();
  
  console.log('⏳ Aguardando 3 segundos para garantir que o servidor está pronto...');
  
  setTimeout(async () => {
    try {
      await tester.runAllTests();
    } catch (error) {
      console.error('❌ Erro ao executar testes:', error);
      process.exit(1);
    }
  }, 3000);
}

module.exports = MiddlewareTester;