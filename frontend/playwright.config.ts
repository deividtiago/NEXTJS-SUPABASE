import { defineConfig, devices } from '@playwright/test';

/**
 * Configuração do Playwright para testes do Nav Component
 * 
 * Este arquivo deve estar na RAIZ do projeto (mesmo nível que package.json)
 */

export default defineConfig({
  // Diretório onde estão os testes
  testDir: './__tests__',
  
  // Rodar testes em paralelo
  fullyParallel: true,
  
  // Proibir .only em CI
  forbidOnly: !!process.env.CI,
  
  // Retry em caso de falha (2x em CI, 0 em dev)
  retries: process.env.CI ? 2 : 0,
  
  // Workers (1 em CI para estabilidade, automático em dev)
  workers: process.env.CI ? 1 : undefined,
  
  // Timeout de 30 segundos por teste
  timeout: 30000,
  
  // Relatórios
  reporter: [
    ['html', { outputFolder: 'playwright-report' }],
    ['list'],
    ['json', { outputFile: 'test-results/results.json' }]
  ],
  
  // Configurações globais
  use: {
    // URL base para todos os testes
    baseURL: 'http://localhost:3000',
    
    // Traces apenas em retry (economiza espaço)
    trace: 'on-first-retry',
    
    // Screenshots apenas em falhas
    screenshot: 'only-on-failure',
    
    // Vídeos apenas em falhas
    video: 'retain-on-failure',
    
    // Timeout para ações (clicks, etc)
    actionTimeout: 10000,
    
    // Timeout para navegação
    navigationTimeout: 30000
  },

  // Projetos de teste (diferentes browsers/devices)
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] }
    },
    
    // Descomente para testar em outros browsers:
    // {
    //   name: 'firefox',
    //   use: { ...devices['Desktop Firefox'] }
    // },
    // {
    //   name: 'webkit',
    //   use: { ...devices['Desktop Safari'] }
    // },
    
    // Mobile
    // {
    //   name: 'Mobile Chrome',
    //   use: { ...devices['Pixel 5'] }
    // },
    // {
    //   name: 'Mobile Safari',
    //   use: { ...devices['iPhone 12'] }
    // }
  ],

  // Configuração de servidor local (opcional)
  // Descomente se quiser que o Playwright inicie seu servidor automaticamente
  // webServer: {
  //   command: 'npm run dev',
  //   url: 'http://localhost:3000',
  //   reuseExistingServer: !process.env.CI,
  //   timeout: 120000
  // }
});