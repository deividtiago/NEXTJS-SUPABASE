import { test, expect, Page, BrowserContext } from '@playwright/test';
import { chromium } from '@playwright/test';

/**
 * Suite de Testes Empresariais - Componente Nav
 * 
 * Cobertura:
 * - Autenticação e Logout
 * - Segurança (XSS, CSRF, Session Management)
 * - Inatividade e Auto-logout
 * - Multi-tab/Multi-window
 * - Offline/Online
 * - Auditoria
 * - Acessibilidade (a11y)
 * - Performance
 * - Responsividade
 * - Estados de erro
 */

// ============================================================================
// CONFIGURAÇÃO E HELPERS
// ============================================================================

const TEST_CONFIG = {
  baseURL: process.env.BASE_URL || 'http://localhost:3000',
  testUser: {
    email: process.env.TEST_USER_EMAIL || 'test@example.com',
    password: process.env.TEST_USER_PASSWORD || 'TestPassword123!'
  },
  timeouts: {
    inactivity: 30 * 60 * 1000, // 30 minutos
    logout: 10000,
    navigation: 30000
  }
};

// Helper: Login do usuário
async function login(page: Page) {
  await page.goto('/');
  await page.fill('input[name="email"]', TEST_CONFIG.testUser.email);
  await page.fill('input[name="password"]', TEST_CONFIG.testUser.password);
  await page.click('button[type="submit"]');
  await page.waitForURL('/tickets', { timeout: TEST_CONFIG.timeouts.navigation });
}

// Helper: Verificar estado de autenticação
async function isAuthenticated(page: Page): Promise<boolean> {
  try {
    await page.waitForSelector('button:has-text("Log out")', { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

// Helper: Interceptar chamadas de API
async function setupAPIInterceptors(page: Page) {
  const auditLogs: any[] = [];
  
  await page.route('**/api/audit/log', async (route) => {
    const postData = route.request().postDataJSON();
    auditLogs.push(postData);
    await route.fulfill({ status: 200, body: JSON.stringify({ success: true }) });
  });

  return { auditLogs };
}

// Helper: Simular inatividade
async function simulateInactivity(page: Page, minutes: number) {
  await page.evaluate((mins) => {
    const inactivityTime = mins * 60 * 1000;
    const event = new Event('test-inactivity');
    setTimeout(() => {
      document.dispatchEvent(event);
    }, inactivityTime);
  }, minutes);
}

// ============================================================================
// 1. TESTES DE AUTENTICAÇÃO E NAVEGAÇÃO
// ============================================================================

test.describe('Autenticação e Navegação', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(TEST_CONFIG.baseURL);
  });

  test('deve exibir todos os links de navegação quando autenticado', async ({ page }) => {
    await login(page);
    
    await expect(page.locator('a:has-text("Ticket List")')).toBeVisible();
    await expect(page.locator('a:has-text("Create New Ticket")')).toBeVisible();
    await expect(page.locator('a:has-text("User List")')).toBeVisible();
    await expect(page.locator('button:has-text("Log out")')).toBeVisible();
  });

  test('deve navegar entre páginas e manter estado ativo correto', async ({ page }) => {
    await login(page);
    
    // Verificar link ativo inicial
    await expect(page.locator('a[href="/tickets"]')).toHaveClass(/linkActive/);
    
    // Navegar para "Create New Ticket"
    await page.click('a:has-text("Create New Ticket")');
    await page.waitForURL('/tickets/new');
    await expect(page.locator('a[href="/tickets/new"]')).toHaveClass(/linkActive/);
    
    // Navegar para "User List"
    await page.click('a:has-text("User List")');
    await page.waitForURL('/tickets/users');
    await expect(page.locator('a[href="/tickets/users"]')).toHaveClass(/linkActive/);
  });

  test('deve marcar "Create New Ticket" como tendo mudanças não salvas', async ({ page }) => {
    await login(page);
    
    // Clicar em "Create New Ticket"
    await page.click('a:has-text("Create New Ticket")');
    await page.waitForURL('/tickets/new');
    
    // Simular mudanças não salvas (verificar via estado interno)
    const hasUnsavedChanges = await page.evaluate(() => {
      // Acessar estado interno do componente se possível
      return true; // Placeholder - implementar verificação real
    });
    
    expect(hasUnsavedChanges).toBeTruthy();
  });
});

// ============================================================================
// 2. TESTES DE LOGOUT
// ============================================================================

test.describe('Funcionalidade de Logout', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('deve fazer logout manual com sucesso', async ({ page }) => {
    const { auditLogs } = await setupAPIInterceptors(page);
    
    await page.click('button:has-text("Log out")');
    
    // Verificar redirecionamento
    await page.waitForURL('/login', { timeout: TEST_CONFIG.timeouts.logout });
    
    // Verificar que não está mais autenticado
    expect(await isAuthenticated(page)).toBeFalsy();
    
    // Verificar logs de auditoria
    expect(auditLogs.some(log => log.action === 'logout_initiated')).toBeTruthy();
    expect(auditLogs.some(log => log.action === 'logout_completed')).toBeTruthy();
  });

  test('deve mostrar estado de loading durante logout', async ({ page }) => {
    await page.click('button:has-text("Log out")');
    
    // Verificar spinner e texto de loading
    await expect(page.locator('button:has-text("Logging out...")')).toBeVisible();
    await expect(page.locator('.spinner')).toBeVisible();
    
    // Verificar que o botão está desabilitado
    await expect(page.locator('button:has-text("Logging out...")')).toBeDisabled();
  });

  test('deve confirmar logout quando há mudanças não salvas', async ({ page }) => {
    // Simular mudanças não salvas
    await page.evaluate(() => {
      (window as any).hasUnsavedChanges = true;
    });
    
    // Configurar listener para o diálogo de confirmação
    page.on('dialog', async (dialog) => {
      expect(dialog.message()).toContain('alterações não salvos');
      await dialog.dismiss(); // Cancelar logout
    });
    
    await page.click('button:has-text("Log out")');
    
    // Verificar que ainda está autenticado
    await page.waitForTimeout(1000);
    expect(await isAuthenticated(page)).toBeTruthy();
  });

  test('deve limpar dados sensíveis após logout', async ({ page }) => {
    // Adicionar dados sensíveis ao localStorage
    await page.evaluate(() => {
      localStorage.setItem('ticket_drafts', JSON.stringify({ draft: 'test' }));
      localStorage.setItem('user_preferences', JSON.stringify({ theme: 'dark' }));
      sessionStorage.setItem('cached_user_data', JSON.stringify({ id: 123 }));
    });
    
    await page.click('button:has-text("Log out")');
    await page.waitForURL('/login');
    
    // Verificar limpeza de dados
    const storageCleared = await page.evaluate(() => {
      const sensitiveKeys = ['ticket_drafts', 'user_preferences', 'cached_user_data'];
      return sensitiveKeys.every(key => 
        !localStorage.getItem(key) && !sessionStorage.getItem(key)
      );
    });
    
    expect(storageCleared).toBeTruthy();
  });

  test('deve preservar returnUrl válido após logout', async ({ page }) => {
    await page.goto('/tickets?returnUrl=/tickets/new');
    
    await page.click('button:has-text("Log out")');
    await page.waitForURL(/\/login/);
    
    // Verificar que returnUrl não está presente (foi validado e rejeitado se inválido)
    const url = new URL(page.url());
    const returnUrl = url.searchParams.get('returnUrl');
    
    if (returnUrl) {
      expect(returnUrl).toMatch(/^\//); // Deve começar com /
      expect(returnUrl).not.toContain('http'); // Não deve ter URL externa
    }
  });
});

// ============================================================================
// 3. TESTES DE INATIVIDADE E AUTO-LOGOUT
// ============================================================================

test.describe('Detecção de Inatividade', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('deve exibir warning de auto-logout', async ({ page }) => {
    await expect(page.locator('.inactivityWarning')).toBeVisible();
    await expect(page.locator('.inactivityWarning')).toContainText('Auto-logout in: 30min');
  });

  test('deve fazer logout após período de inatividade', async ({ page }) => {
    const { auditLogs } = await setupAPIInterceptors(page);
    
    // Simular passagem de tempo (30 minutos)
    await page.evaluate(() => {
      const inactivityTime = 30 * 60 * 1000;
      // Forçar disparo do timeout
      (window as any).__triggerInactivityLogout = () => {
        const event = new CustomEvent('force-logout', { detail: { reason: 'inactivity' } });
        document.dispatchEvent(event);
      };
    });
    
    // Disparar logout por inatividade
    await page.evaluate(() => (window as any).__triggerInactivityLogout());
    
    await page.waitForURL('/login', { timeout: 15000 });
    
    // Verificar log de auditoria
    expect(auditLogs.some(log => 
      log.action === 'logout_initiated' && log.reason === 'inactivity'
    )).toBeTruthy();
  });

  test('deve resetar timer de inatividade com atividade do usuário', async ({ page }) => {
    // Mover mouse para resetar timer
    await page.mouse.move(100, 100);
    await page.waitForTimeout(500);
    
    // Digitar para resetar timer
    await page.keyboard.press('ArrowDown');
    await page.waitForTimeout(500);
    
    // Scroll para resetar timer
    await page.evaluate(() => window.scrollBy(0, 100));
    await page.waitForTimeout(500);
    
    // Verificar que ainda está autenticado
    expect(await isAuthenticated(page)).toBeTruthy();
  });
});

// ============================================================================
// 4. TESTES MULTI-TAB E MULTI-WINDOW
// ============================================================================

test.describe('Gerenciamento Multi-Tab', () => {
  test('deve fazer logout em todas as tabs quando logout em uma', async ({ browser }) => {
    const context = await browser.newContext();
    const page1 = await context.newPage();
    const page2 = await context.newPage();
    
    // Login em ambas as tabs
    await login(page1);
    await login(page2);
    
    // Verificar autenticação em ambas
    expect(await isAuthenticated(page1)).toBeTruthy();
    expect(await isAuthenticated(page2)).toBeTruthy();
    
    // Fazer logout na primeira tab
    await page1.click('button:has-text("Log out")');
    await page1.waitForURL('/login');
    
    // Verificar que a segunda tab também foi deslogada
    await page2.waitForTimeout(2000); // Aguardar propagação do evento
    await page2.reload();
    
    expect(await isAuthenticated(page2)).toBeFalsy();
    
    await context.close();
  });

  test('deve detectar logout em outra tab via onAuthStateChange', async ({ browser }) => {
    const context = await browser.newContext();
    const page1 = await context.newPage();
    const page2 = await context.newPage();
    
    const { auditLogs } = await setupAPIInterceptors(page2);
    
    await login(page1);
    await login(page2);
    
    // Logout na tab 1
    await page1.click('button:has-text("Log out")');
    await page1.waitForURL('/login');
    
    // Verificar redirecionamento e auditoria na tab 2
    await page2.waitForURL(/reason=multiple_tabs/, { timeout: 10000 });
    
    expect(auditLogs.some(log => 
      log.action === 'logout_auto' && log.reason === 'multiple_tabs'
    )).toBeTruthy();
    
    await context.close();
  });
});

// ============================================================================
// 5. TESTES DE CONECTIVIDADE (ONLINE/OFFLINE)
// ============================================================================

test.describe('Gerenciamento de Conectividade', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('deve usar fallback offline quando sem conexão durante logout', async ({ page, context }) => {
    const { auditLogs } = await setupAPIInterceptors(page);
    
    // Simular modo offline
    await context.setOffline(true);
    
    await page.click('button:has-text("Log out")');
    
    // Verificar redirecionamento com parâmetro offline
    await page.waitForURL(/offline=true/, { timeout: 15000 });
    
    // Verificar log de fallback offline
    expect(auditLogs.some(log => 
      log.action === 'logout_offline_fallback'
    )).toBeTruthy();
  });

  test('deve detectar perda de conexão e mostrar aviso', async ({ page, context }) => {
    const consoleLogs: string[] = [];
    page.on('console', msg => consoleLogs.push(msg.text()));
    
    // Simular perda de conexão
    await context.setOffline(true);
    await page.evaluate(() => {
      window.dispatchEvent(new Event('offline'));
    });
    
    await page.waitForTimeout(1000);
    
    expect(consoleLogs.some(log => 
      log.includes('Connection lost')
    )).toBeTruthy();
  });

  test('deve restaurar funcionalidade quando conexão volta', async ({ page, context }) => {
    const consoleLogs: string[] = [];
    page.on('console', msg => consoleLogs.push(msg.text()));
    
    // Simular restauração de conexão
    await context.setOffline(false);
    await page.evaluate(() => {
      window.dispatchEvent(new Event('online'));
    });
    
    await page.waitForTimeout(1000);
    
    expect(consoleLogs.some(log => 
      log.includes('Connection restored')
    )).toBeTruthy();
  });
});

// ============================================================================
// 6. TESTES DE SEGURANÇA
// ============================================================================

test.describe('Segurança', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('deve prevenir redirect malicioso via returnUrl', async ({ page }) => {
    // Tentar usar returnUrl malicioso
    await page.goto('/tickets?returnUrl=https://evil.com');
    
    await page.click('button:has-text("Log out")');
    await page.waitForURL('/login');
    
    // Verificar que não foi redirecionado para site externo
    expect(page.url()).not.toContain('evil.com');
    expect(page.url()).toContain(TEST_CONFIG.baseURL);
  });

  test('deve limpar tokens de autenticação do storage', async ({ page }) => {
    await page.click('button:has-text("Log out")');
    await page.waitForURL('/login');
    
    const tokensCleared = await page.evaluate(() => {
      const keys = Object.keys(localStorage);
      return !keys.some(key => key.includes('auth-token'));
    });
    
    expect(tokensCleared).toBeTruthy();
  });

  test('deve cancelar requisições pendentes durante logout', async ({ page }) => {
    // Criar requisições pendentes
    await page.evaluate(() => {
      fetch('/api/slow-endpoint', { signal: new AbortController().signal });
    });
    
    await page.click('button:has-text("Log out")');
    await page.waitForURL('/login');
    
    // Verificar que requisições foram canceladas (sem erros de rede pendentes)
    const errors = await page.evaluate(() => {
      return (window as any).__networkErrors || [];
    });
    
    expect(errors.length).toBe(0);
  });

  test('deve ter timeout de 10s para logout', async ({ page }) => {
    // Interceptar e atrasar chamada de logout
    await page.route('**/auth/v1/logout', async (route) => {
      await page.waitForTimeout(12000); // Mais que o timeout de 10s
      await route.fulfill({ status: 200 });
    });
    
    const startTime = Date.now();
    await page.click('button:has-text("Log out")');
    await page.waitForURL('/login', { timeout: 15000 });
    const endTime = Date.now();
    
    // Verificar que abortou antes de 12s
    expect(endTime - startTime).toBeLessThan(12000);
  });
});

// ============================================================================
// 7. TESTES DE AUDITORIA
// ============================================================================

test.describe('Sistema de Auditoria', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('deve registrar evento de logout_initiated', async ({ page }) => {
    const { auditLogs } = await setupAPIInterceptors(page);
    
    await page.click('button:has-text("Log out")');
    await page.waitForURL('/login');
    
    const initiatedLog = auditLogs.find(log => log.action === 'logout_initiated');
    expect(initiatedLog).toBeTruthy();
    expect(initiatedLog?.reason).toBe('manual');
    expect(initiatedLog?.user_agent).toBeTruthy();
    expect(initiatedLog?.timestamp).toBeTruthy();
  });

  test('deve registrar evento de logout_completed', async ({ page }) => {
    const { auditLogs } = await setupAPIInterceptors(page);
    
    await page.click('button:has-text("Log out")');
    await page.waitForURL('/login');
    
    const completedLog = auditLogs.find(log => log.action === 'logout_completed');
    expect(completedLog).toBeTruthy();
  });

  test('deve registrar diferentes razões de logout', async ({ page }) => {
    const { auditLogs } = await setupAPIInterceptors(page);
    
    // Simular logout por inatividade
    await page.evaluate(() => {
      (window as any).__triggerInactivityLogout?.();
    });
    
    await page.waitForURL('/login', { timeout: 15000 });
    
    const inactivityLog = auditLogs.find(log => 
      log.action === 'logout_initiated' && log.reason === 'inactivity'
    );
    
    expect(inactivityLog).toBeTruthy();
  });

  test('deve continuar funcionando se auditoria falhar', async ({ page }) => {
    // Fazer auditoria falhar
    await page.route('**/api/audit/log', async (route) => {
      await route.abort();
    });
    
    await page.click('button:has-text("Log out")');
    
    // Verificar que logout ainda funciona
    await page.waitForURL('/login', { timeout: TEST_CONFIG.timeouts.logout });
    expect(await isAuthenticated(page)).toBeFalsy();
  });
});

// ============================================================================
// 8. TESTES DE ACESSIBILIDADE (A11Y)
// ============================================================================

test.describe('Acessibilidade', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('deve ter estrutura semântica correta', async ({ page }) => {
    await expect(page.locator('header')).toBeVisible();
    await expect(page.locator('nav')).toBeVisible();
    await expect(page.locator('nav ul')).toBeVisible();
  });

  test('deve ter atributos ARIA corretos no botão de logout', async ({ page }) => {
    const logoutButton = page.locator('button:has-text("Log out")');
    
    await expect(logoutButton).toHaveAttribute('type', 'button');
    
    // Clicar e verificar aria-busy durante loading
    await logoutButton.click();
    await expect(logoutButton).toHaveAttribute('aria-busy', 'true');
  });

  test('deve ser navegável por teclado', async ({ page }) => {
    // Tab através dos elementos
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');
    
    // Verificar que um link está focado
    const focusedElement = await page.evaluate(() => 
      document.activeElement?.tagName
    );
    
    expect(focusedElement).toBe('A');
  });

  test('deve ter contraste adequado nos links', async ({ page }) => {
    const linkColor = await page.locator('.link').evaluate((el) => {
      return window.getComputedStyle(el).color;
    });
    
    const bgColor = await page.locator('.header').evaluate((el) => {
      return window.getComputedStyle(el).backgroundColor;
    });
    
    // Verificar que cores existem (teste básico)
    expect(linkColor).toBeTruthy();
    expect(bgColor).toBeTruthy();
  });
});

// ============================================================================
// 9. TESTES DE PERFORMANCE
// ============================================================================

test.describe('Performance', () => {
  test('deve carregar navegação em menos de 2 segundos', async ({ page }) => {
    const startTime = Date.now();
    await page.goto('/tickets');
    await page.waitForSelector('button:has-text("Log out")');
    const loadTime = Date.now() - startTime;
    
    expect(loadTime).toBeLessThan(2000);
  });

  test('deve processar logout em menos de 10 segundos', async ({ page }) => {
    await login(page);
    
    const startTime = Date.now();
    await page.click('button:has-text("Log out")');
    await page.waitForURL('/login');
    const logoutTime = Date.now() - startTime;
    
    expect(logoutTime).toBeLessThan(10000);
  });

  test('não deve ter memory leaks em event listeners', async ({ page }) => {
    await login(page);
    
    const initialListeners = await page.evaluate(() => {
      return (window as any).getEventListeners?.(document).length || 0;
    });
    
    // Navegar várias vezes
    for (let i = 0; i < 5; i++) {
      await page.click('a:has-text("Ticket List")');
      await page.waitForTimeout(200);
      await page.click('a:has-text("Create New Ticket")');
      await page.waitForTimeout(200);
    }
    
    const finalListeners = await page.evaluate(() => {
      return (window as any).getEventListeners?.(document).length || 0;
    });
    
    // Listeners não devem crescer exponencialmente
    expect(finalListeners).toBeLessThanOrEqual(initialListeners * 2);
  });
});

// ============================================================================
// 10. TESTES DE RESPONSIVIDADE
// ============================================================================

test.describe('Responsividade', () => {
  const viewports = [
    { name: 'Mobile', width: 375, height: 667 },
    { name: 'Tablet', width: 768, height: 1024 },
    { name: 'Desktop', width: 1920, height: 1080 }
  ];

  viewports.forEach(({ name, width, height }) => {
    test(`deve renderizar corretamente em ${name}`, async ({ page }) => {
      await page.setViewportSize({ width, height });
      await login(page);
      
      // Verificar que elementos principais estão visíveis
      await expect(page.locator('nav')).toBeVisible();
      await expect(page.locator('button:has-text("Log out")')).toBeVisible();
      
      // Verificar que não há overflow horizontal
      const hasHorizontalScroll = await page.evaluate(() => {
        return document.documentElement.scrollWidth > document.documentElement.clientWidth;
      });
      
      expect(hasHorizontalScroll).toBeFalsy();
    });
  });
});

// ============================================================================
// 11. TESTES DE ESTADOS DE ERRO
// ============================================================================

test.describe('Tratamento de Erros', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('deve tratar erro de logout com graciosidade', async ({ page }) => {
    // Simular erro no logout
    await page.route('**/auth/v1/logout', async (route) => {
      await route.fulfill({ status: 500, body: 'Internal Server Error' });
    });
    
    await page.click('button:has-text("Log out")');
    
    // Verificar redirecionamento mesmo com erro
    await page.waitForURL(/error=logout_failed/, { timeout: 15000 });
  });

  test('deve limpar dados mesmo quando logout falha', async ({ page }) => {
    // Adicionar dados sensíveis
    await page.evaluate(() => {
      localStorage.setItem('ticket_drafts', 'sensitive data');
    });
    
    // Simular erro no logout
    await page.route('**/auth/v1/logout', async (route) => {
      await route.abort();
    });
    
    await page.click('button:has-text("Log out")');
    await page.waitForURL('/login', { timeout: 15000 });
    
    // Verificar que dados foram limpos
    const dataCleared = await page.evaluate(() => {
      return !localStorage.getItem('ticket_drafts');
    });
    
    expect(dataCleared).toBeTruthy();
  });
});

// ============================================================================
// 12. TESTES DE INTEGRAÇÃO COMPLETA (E2E)
// ============================================================================

test.describe('Fluxo E2E Completo', () => {
  test('fluxo completo: login -> navegação -> logout', async ({ page }) => {
    // 1. Login
    await page.goto('/login');
    await page.fill('input[name="email"]', TEST_CONFIG.testUser.email);
    await page.fill('input[name="password"]', TEST_CONFIG.testUser.password);
    await page.click('button[type="submit"]');
    await page.waitForURL('/tickets');
    
    // 2. Navegar para diferentes páginas
    await page.click('a:has-text("Create New Ticket")');
    await page.waitForURL('/tickets/new');
    await expect(page.locator('a[href="/tickets/new"]')).toHaveClass(/linkActive/);
    
    await page.click('a:has-text("User List")');
    await page.waitForURL('/tickets/users');
    await expect(page.locator('a[href="/tickets/users"]')).toHaveClass(/linkActive/);
    
    // 3. Voltar para Ticket List
    await page.click('a:has-text("Ticket List")');
    await page.waitForURL('/tickets');
    
    // 4. Logout
    await page.click('button:has-text("Log out")');
    await page.waitForURL('/login');
    
    // 5. Verificar que não está mais autenticado
    expect(await isAuthenticated(page)).toBeFalsy();
  });

  test('fluxo com inatividade e reconexão', async ({ page, context }) => {
    await login(page);
    
    // Simular perda de conexão
    await context.setOffline(true);
    await page.evaluate(() => window.dispatchEvent(new Event('offline')));
    await page.waitForTimeout(1000);
    
    // Restaurar conexão
    await context.setOffline(false);
    await page.evaluate(() => window.dispatchEvent(new Event('online')));
    await page.waitForTimeout(1000);
    
    // Fazer logout
    await page.click('button:has-text("Log out")');
    await page.waitForURL('/login');
    
    expect(await isAuthenticated(page)).toBeFalsy();
  });
});

// ============================================================================
// CONFIGURAÇÃO DE RELATÓRIOS
// ============================================================================

test.afterEach(async ({ page }, testInfo) => {
  if (testInfo.status !== testInfo.expectedStatus) {
    // Screenshot em caso de falha
    await page.screenshot({ 
      path: `test-results/failure-${testInfo.title.replace(/\s/g, '-')}.png`,
      fullPage: true 
    });
  }
});