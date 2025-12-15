// Nav1.test.tsx - VERSÃO FINAL CORRIGIDA
// ============================================
// IMPORTANTE: Mocks DEVEM vir ANTES dos imports
// ============================================

// Mock next/navigation
jest.mock('next/navigation', () => ({
  usePathname: jest.fn(),
  useRouter: jest.fn(),
}));

// Mock do Supabase Client
jest.mock('@/supabase-utils/browserClient', () => ({
  getSupabaseBrowserClient: jest.fn(),
}));

// MOCK PARA CSS MODULES
jest.mock('@/components/tickets/nav/Nav.module.css', () => ({
  header: 'header',
  nav: 'nav', 
  navList: 'navList',
  link: 'link',
  linkActive: 'linkActive',
  logoutButton: 'logoutButton',
  spinner: 'spinner',
  inactivityWarning: 'inactivityWarning',
  divider: 'divider',
}));

// AGORA podemos importar
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { usePathname, useRouter } from 'next/navigation';
import Nav from '@/components/tickets/nav';
import { getSupabaseBrowserClient } from '@/supabase-utils/browserClient';

// Mock do fetch global
global.fetch = jest.fn();

// ============================================
// SETUP DO SUPABASE MOCK
// ============================================

const mockSupabaseClient = {
  auth: {
    signOut: jest.fn(),
    onAuthStateChange: jest.fn(),
  },
  supabaseUrl: 'https://test.supabase.co',
};

// ============================================
// TESTES
// ============================================

describe('Nav Component', () => {
  let mockRouter: any;
  let mockAuthStateChangeCallback: any;

  beforeEach(() => {
    // Reset de todos os mocks
    jest.clearAllMocks();
    jest.useFakeTimers();

    // Configurar mock do Supabase
    (getSupabaseBrowserClient as jest.Mock).mockReturnValue(mockSupabaseClient);

    // Mock do router
    mockRouter = {
      push: jest.fn(),
      refresh: jest.fn(),
      replace: jest.fn(),
      back: jest.fn(),
    };
    (useRouter as jest.Mock).mockReturnValue(mockRouter);
    (usePathname as jest.Mock).mockReturnValue('/tickets');

    // Reset Supabase mock functions
    mockSupabaseClient.auth.signOut = jest.fn().mockResolvedValue({ error: null });
    mockSupabaseClient.auth.onAuthStateChange = jest.fn((callback) => {
      mockAuthStateChangeCallback = callback;
      return {
        data: {
          subscription: {
            unsubscribe: jest.fn(),
          },
        },
      };
    });

    // Mock do fetch para auditoria
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: async () => ({}),
    });

    // Mock do localStorage
    global.Storage.prototype.removeItem = jest.fn();
    global.Storage.prototype.getItem = jest.fn();
    global.Storage.prototype.setItem = jest.fn();
    global.Storage.prototype.clear = jest.fn();

    // Mock do navigator.onLine
    Object.defineProperty(navigator, 'onLine', {
      value: true,
      writable: true,
    });

    // Mock do window.confirm
    global.confirm = jest.fn(() => true);

    // Mock simplificado do window.location
    delete (window as any).location;
    (window as any).location = {
      search: '',
      href: 'http://localhost:3000/tickets',
    };

    // Mock de caches API
    global.caches = {
      keys: jest.fn().mockResolvedValue([]),
      delete: jest.fn().mockResolvedValue(true),
    } as any;
  });

  afterEach(() => {
    jest.runOnlyPendingTimers();
    jest.useRealTimers();
  });

  // ============================================
  // TESTES BÁSICOS
  // ============================================

  describe('Renderização básica', () => {
    it('deve renderizar todos os links de navegação', () => {
      render(<Nav />);

      expect(screen.getByText('Ticket List')).toBeInTheDocument();
      expect(screen.getByText('Create New Ticket')).toBeInTheDocument();
      expect(screen.getByText('User List')).toBeInTheDocument();
      expect(screen.getByText('Log out')).toBeInTheDocument();
    });

    it('deve destacar o link ativo corretamente', () => {
      (usePathname as jest.Mock).mockReturnValue('/tickets/new');
      render(<Nav />);

      const createTicketLink = screen.getByText('Create New Ticket');
      expect(createTicketLink.closest('a')).toHaveAttribute('href', '/tickets/new');
    });

    it('deve exibir indicador de inatividade', () => {
      render(<Nav />);

      expect(screen.getByText(/Auto-logout in:/)).toBeInTheDocument();
      expect(screen.getByText(/30min/)).toBeInTheDocument();
    });
  });

  // ============================================
  // TESTES DE LOGOUT
  // ============================================

  describe('Funcionalidade de Logout', () => {
    it('deve realizar logout manual com sucesso', async () => {
      render(<Nav />);

      const logoutButton = screen.getByRole('button', { name: /log out/i });
      
      await act(async () => {
        fireEvent.click(logoutButton);
      });

      await waitFor(() => {
        expect(mockSupabaseClient.auth.signOut).toHaveBeenCalledTimes(1);
      });

      expect(global.fetch).toHaveBeenCalled();
      expect(mockRouter.push).toHaveBeenCalledWith('/');
    });

    it('deve exibir estado de loading durante logout', async () => {
      render(<Nav />);

      const logoutButton = screen.getByRole('button', { name: /log out/i });
      
      fireEvent.click(logoutButton);

      expect(screen.getByText(/logging out/i)).toBeInTheDocument();
      expect(logoutButton).toBeDisabled();

      await waitFor(() => {
        expect(mockSupabaseClient.auth.signOut).toHaveBeenCalled();
      });
    });

    it('deve pedir confirmação se houver mudanças não salvas', async () => {
      render(<Nav />);

      const createLink = screen.getByText('Create New Ticket');
      fireEvent.click(createLink);

      const logoutButton = screen.getByRole('button', { name: /log out/i });
      global.confirm = jest.fn(() => false);

      await act(async () => {
        fireEvent.click(logoutButton);
      });

      expect(global.confirm).toHaveBeenCalledWith(
        expect.stringContaining('alterações não salvos')
      );
      expect(mockSupabaseClient.auth.signOut).not.toHaveBeenCalled();
    });

    it('deve lidar com erro de logout graciosamente', async () => {
      mockSupabaseClient.auth.signOut.mockResolvedValue({
        error: { message: 'Erro de rede' },
      });

      render(<Nav />);

      const logoutButton = screen.getByRole('button', { name: /log out/i });
      
      await act(async () => {
        fireEvent.click(logoutButton);
      });

      await waitFor(() => {
        expect(mockRouter.push).toHaveBeenCalledWith('/login?error=logout_failed');
      });
    });
  });

  // ============================================
  // TESTES DE INATIVIDADE CORRIGIDOS
  // ============================================

  describe('Detecção de inatividade', () => {
    it('deve configurar timer de inatividade', () => {
      // Spy nas funções de timer
      const setTimeoutSpy = jest.spyOn(global, 'setTimeout');
      
      render(<Nav />);

      // Verificar se setTimeout foi chamado para inatividade
      expect(setTimeoutSpy).toHaveBeenCalled();
      
      // Limpar spy
      setTimeoutSpy.mockRestore();
    });

    it('deve resetar timer ao detectar atividade do mouse', () => {
      // Spies para as funções de timer
      const setTimeoutSpy = jest.spyOn(global, 'setTimeout');
      const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');
      
      render(<Nav />);

      // Limpar chamadas iniciais
      setTimeoutSpy.mockClear();
      clearTimeoutSpy.mockClear();

      // Simular atividade do mouse
      act(() => {
        fireEvent.mouseMove(document);
      });

      // Deve ter resetado o timer
      expect(clearTimeoutSpy).toHaveBeenCalled();
      expect(setTimeoutSpy).toHaveBeenCalled();

      // Limpar spies
      setTimeoutSpy.mockRestore();
      clearTimeoutSpy.mockRestore();
    });

    it('deve fazer logout após período de inatividade', async () => {
      render(<Nav />);

      // Avançar o tempo em 30 minutos + um pouco mais
      await act(async () => {
        jest.advanceTimersByTime(30 * 60 * 1000 + 1000);
      });

      await waitFor(() => {
        expect(mockSupabaseClient.auth.signOut).toHaveBeenCalled();
      });

      expect(global.fetch).toHaveBeenCalledWith(
        '/api/audit/log',
        expect.objectContaining({
          body: expect.stringContaining('inactivity'),
        })
      );
    });
  });

  // ============================================
  // TESTES ADICIONAIS DE SEGURANÇA
  // ============================================

  describe('Segurança e auditoria', () => {
    it('deve registrar eventos de auditoria', async () => {
      render(<Nav />);

      const logoutButton = screen.getByRole('button', { name: /log out/i });
      
      await act(async () => {
        fireEvent.click(logoutButton);
      });

      await waitFor(() => {
        expect(global.fetch).toHaveBeenCalledWith(
          '/api/audit/log',
          expect.objectContaining({
            method: 'POST',
            body: expect.stringContaining('logout_initiated'),
          })
        );
      });
    });

    it('deve limpar dados sensíveis no logout', async () => {
      render(<Nav />);

      const logoutButton = screen.getByRole('button', { name: /log out/i });
      
      await act(async () => {
        fireEvent.click(logoutButton);
      });

      await waitFor(() => {
        expect(localStorage.removeItem).toHaveBeenCalledWith('ticket_drafts');
        expect(localStorage.removeItem).toHaveBeenCalledWith('user_preferences');
        expect(localStorage.removeItem).toHaveBeenCalledWith('form_data');
        expect(localStorage.removeItem).toHaveBeenCalledWith('cached_user_data');
        expect(sessionStorage.clear).toHaveBeenCalled();
      });
    });
  });
});