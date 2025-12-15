// __tests__/proxy-TEST/direct.test.ts
/**
 * Teste direto do middleware sem frameworks
 */

async function testMiddlewareDirectly() {
  console.log('🧪 Testando middleware diretamente...\n');

  // Simula diferentes URLs
  const testUrls = [
    { url: '/', expected: 'allow' },
    { url: '/login', expected: 'allow' },
    { url: '/tickets', expected: 'redirect' },
    { url: '/dashboard', expected: 'redirect' },
    { url: '/favicon.ico', expected: 'allow' },
  ];

  for (const test of testUrls) {
    console.log(`Testando: ${test.url}`);
    console.log(`Esperado: ${test.expected}`);
    
    // Aqui você pode adicionar lógica para testar seu middleware
    // Por enquanto é apenas um esqueleto
    console.log('✅ Teste configurado\n');
  }

  console.log('📝 Para testar realmente:');
  console.log('1. Execute o servidor: npm run dev');
  console.log('2. Em outro terminal:');
  console.log('   curl -I http://localhost:3000/');
  console.log('   curl -I http://localhost:3000/tickets');
  console.log('   curl -I http://localhost:3000/login');
}

if (require.main === module) {
  testMiddlewareDirectly();
}
