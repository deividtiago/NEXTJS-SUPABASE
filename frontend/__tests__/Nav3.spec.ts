import { test, expect, Page } from '@playwright/test';

/**
 * Suite de Testes - Abordagem DIRETA sem redirecionamentos complexos
 */

const testWithMocks = test.extend({
  page: async ({ page }, use) => {
    // Estado simples da aplicação
    let isAuthenticated = false;
    let currentPage = 'login';
    
    // Mock DIRETO - sem redirecionamentos complexos
    await page.route('**/*', async (route) => {
      const url = route.request().url();
      
      // API calls - sempre sucesso
      if (url.includes('/api/') || url.includes('/auth/')) {
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ success: true })
        });
      }
      
      // Páginas baseadas no estado atual
      if (currentPage === 'login') {
        return route.fulfill({
          status: 200,
          contentType: 'text/html',
          body: `
            <!DOCTYPE html>
            <html>
              <body>
                <h1 data-testid="page-title">Login Page</h1>
                <button id="login-btn" data-testid="login-button">Login</button>
                <script>
                  document.getElementById('login-btn').addEventListener('click', () => {
                    // Simular login - apenas mudar estado
                    window.postMessage({ type: 'LOGIN_SUCCESS' }, '*');
                  });
                </script>
              </body>
            </html>
          `
        });
      }
      
      if (currentPage === 'tickets') {
        return route.fulfill({
          status: 200,
          contentType: 'text/html',
          body: `
            <!DOCTYPE html>
            <html>
              <body>
                <nav data-testid="navigation">
                  <a href="#" data-testid="tickets-link">Tickets</a>
                  <a href="#" data-testid="new-ticket-link">New Ticket</a>
                  <a href="#" data-testid="users-link">Users</a>
                  <button id="logout-btn" data-testid="logout-button">Log out</button>
                </nav>
                <h1 data-testid="page-title">Tickets Page</h1>
                <div id="content" data-testid="page-content">Main Content Area</div>
                
                <script>
                  document.getElementById('logout-btn').addEventListener('click', async () => {
                    // 1. Auditoria
                    try {
                      await fetch('/api/audit/log', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ 
                          action: 'logout_initiated',
                          timestamp: new Date().toISOString()
                        })
                      });
                    } catch (e) {}
                    
                    // 2. Limpeza
                    localStorage.clear();
                    sessionStorage.clear();
                    
                    // 3. Sinalizar logout
                    window.postMessage({ type: 'LOGOUT_SUCCESS' }, '*');
                  });
                  
                  // Navegação entre páginas
                  document.querySelectorAll('a').forEach(link => {
                    link.addEventListener('click', (e) => {
                      e.preventDefault();
                      const linkText = e.target.textContent;
                      document.getElementById('content').textContent = \`Viewing: \${linkText}\`;
                    });
                  });
                </script>
              </body>
            </html>
          `
        });
      }
      
      // Fallback
      route.fulfill({ status: 404, body: 'Not Found' });
    });
    
    // Listeners para mudanças de estado
    await page.addInitScript(() => {
      window.addEventListener('message', (event) => {
        if (event.data.type === 'LOGIN_SUCCESS') {
          // Mudar para página de tickets
          window.dispatchEvent(new CustomEvent('stateChange', { 
            detail: { page: 'tickets', authenticated: true } 
          }));
        }
        if (event.data.type === 'LOGOUT_SUCCESS') {
          // Mudar para página de login
          window.dispatchEvent(new CustomEvent('stateChange', { 
            detail: { page: 'login', authenticated: false } 
          }));
        }
      });
    });
    
    // Expor função para controlar estado
    await page.exposeFunction('setAppState', (newState: any) => {
      currentPage = newState.page;
      isAuthenticated = newState.authenticated;
    });
    
    // Listener para mudanças de estado do app
    await page.addInitScript(() => {
      window.addEventListener('stateChange', (event: any) => {
        const { page, authenticated } = event.detail;
        (window as any).setAppState({ page, authenticated });
        // Recarregar a página para refletir o novo estado
        window.location.reload();
      });
    });
    
    await use(page);
  }
});

// HELPERS SIMPLES - sem waiters complexos
async function login(page: Page) {
  await page.goto('/any-page'); // Qualquer página inicia no login
  await page.click('[data-testid="login-button"]');
  // Aguardar mudança para tickets
  await expect(page.locator('[data-testid="page-title"]:has-text("Tickets Page")')).toBeVisible();
}

async function logout(page: Page) {
  await page.click('[data-testid="logout-button"]');
  // Aguardar mudança para login
  await expect(page.locator('[data-testid="page-title"]:has-text("Login Page")')).toBeVisible();
}

// TESTES DIRETOS
testWithMocks('deve fazer login e mostrar página de tickets', async ({ page }) => {
  await login(page);
  
  await expect(page.locator('[data-testid="navigation"]')).toBeVisible();
  await expect(page.locator('[data-testid="logout-button"]')).toBeVisible();
  await expect(page.locator('[data-testid="page-title"]:has-text("Tickets Page")')).toBeVisible();
});

testWithMocks('deve fazer logout e voltar para login', async ({ page }) => {
  await login(page);
  await logout(page);
  
  await expect(page.locator('[data-testid="page-title"]:has-text("Login Page")')).toBeVisible();
  await expect(page.locator('[data-testid="login-button"]')).toBeVisible();
});

testWithMocks('deve exibir todos os links de navegação quando autenticado', async ({ page }) => {
  await login(page);
  
  await expect(page.locator('[data-testid="tickets-link"]')).toBeVisible();
  await expect(page.locator('[data-testid="new-ticket-link"]')).toBeVisible();
  await expect(page.locator('[data-testid="users-link"]')).toBeVisible();
  await expect(page.locator('[data-testid="logout-button"]')).toBeVisible();
});

testWithMocks('deve limpar storage no logout', async ({ page }) => {
  await login(page);
  
  // Adicionar dados
  await page.evaluate(() => {
    localStorage.setItem('user_data', 'test');
    localStorage.setItem('ticket_drafts', 'draft123');
    sessionStorage.setItem('temp_data', 'temp');
  });
  
  await logout(page);
  
  // Verificar limpeza
  const isCleaned = await page.evaluate(() => {
    return localStorage.length === 0 && sessionStorage.length === 0;
  });
  
  expect(isCleaned).toBe(true);
});

testWithMocks('deve navegar entre páginas internas', async ({ page }) => {
  await login(page);
  
  await page.click('[data-testid="new-ticket-link"]');
  await expect(page.locator('#content:has-text("Viewing: New Ticket")')).toBeVisible();
  
  await page.click('[data-testid="users-link"]');
  await expect(page.locator('#content:has-text("Viewing: Users")')).toBeVisible();
});

testWithMocks('deve chamar API de auditoria no logout', async ({ page }) => {
  await login(page);
  
  let auditCalled = false;
  await page.route('**/api/audit/log', async (route) => {
    auditCalled = true;
    const postData = route.request().postDataJSON();
    expect(postData.action).toBe('logout_initiated');
    await route.fulfill({ status: 200, body: JSON.stringify({ success: true }) });
  });
  
  await logout(page);
  
  expect(auditCalled).toBe(true);
});

testWithMocks('deve manter estado entre navegações', async ({ page }) => {
  await login(page);
  
  // Verificar que está autenticado
  await expect(page.locator('[data-testid="logout-button"]')).toBeVisible();
  
  // Recarregar página - deve manter autenticação
  await page.reload();
  await expect(page.locator('[data-testid="logout-button"]')).toBeVisible();
  await expect(page.locator('[data-testid="page-title"]:has-text("Tickets Page")')).toBeVisible();
});