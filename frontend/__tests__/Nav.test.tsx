import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { usePathname, useRouter } from 'next/navigation';

import { getSupabaseBrowserClient } from '@/supabase-utils/browserClient';
import Nav from '@/components/tickets/nav';

// Mocks
jest.mock('next/navigation', () => ({
  usePathname: jest.fn(),
  useRouter: jest.fn(),
}));

jest.mock('@/supabase-utils/browserClient', () => ({
  getSupabaseBrowserClient: jest.fn(),
}));

// Mock do fetch global
global.fetch = jest.fn();

describe('Nav Component', () => {
  let mockRouter: any;
  let mockSupabase: any;
  let mockAuthStateChangeCallback: any;

  beforeEach(() => {
    // Reset de todos os mocks
    jest.clearAllMocks();
    jest.useFakeTimers();

    // Mock do router
    mockRouter = {
      push: jest.fn(),
      refresh: jest.fn(),
    };
    (useRouter as jest.Mock).mockReturnValue(mockRouter);
    (usePathname as jest.Mock).mockReturnValue('/tickets');

    // Mock do Supabase
    mockSupabase = {
      auth: {
        signOut: jest.fn().mockResolvedValue({ error: null }),
        onAuthStateChange: jest.fn((callback) => {
          mockAuthStateChangeCallback = callback;
          return {
            data: {
              subscription: {
                unsubscribe: jest.fn(),
              },
            },
          };
        }),
      },
      supabaseUrl: 'https://test.supabase.co',
    };
    (getSupabaseBrowserClient as jest.Mock).mockReturnValue(mockSupabase);

    // Mock do fetch para auditoria
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: async () => ({}),
    });

    // Mock do localStorage e sessionStorage
    const localStorageMock = {
      getItem: jest.fn(),
      setItem: jest.fn(),
      removeItem: jest.fn(),
      clear: jest.fn(),
    };
    const sessionStorageMock = {
      getItem: jest.fn(),
      setItem: jest.fn(),
      removeItem: jest.fn(),
      clear: jest.fn(),
    };
    Object.defineProperty(window, 'localStorage', { value: localStorageMock, writable: true });
    Object.defineProperty(window, 'sessionStorage', { value: sessionStorageMock, writable: true });

    // Mock do navigator
    Object.defineProperty(window.navigator, 'onLine', {
      writable: true,
      value: true,
    });

    // Mock do window.confirm
    window.confirm = jest.fn(() => true);
  });

  afterEach(() => {
    jest.runOnlyPendingTimers();
    jest.useRealTimers();
  });

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
      expect(createTicketLink).toHaveClass('linkActive');
    });

    it('deve exibir indicador de inatividade', () => {
      render(<Nav />);

      expect(screen.getByText(/Auto-logout in:/)).toBeInTheDocument();
      expect(screen.getByText(/30min/)).toBeInTheDocument();
    });
  });

  describe('Funcionalidade de Logout', () => {
    it('deve realizar logout manual com sucesso', async () => {
      render(<Nav />);

      const logoutButton = screen.getByText('Log out');
      
      await act(async () => {
        fireEvent.click(logoutButton);
      });

      await waitFor(() => {
        expect(mockSupabase.auth.signOut).toHaveBeenCalledTimes(1);
      });

      expect(global.fetch).toHaveBeenCalledWith(
        '/api/audit/log',
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('logout_initiated'),
        })
      );

      expect(window.localStorage.removeItem).toHaveBeenCalled();
      expect(window.sessionStorage.clear).toHaveBeenCalled();
      expect(mockRouter.push).toHaveBeenCalledWith('/');
      expect(mockRouter.refresh).toHaveBeenCalled();
    });

    it('deve exibir estado de loading durante logout', async () => {
      render(<Nav />);

      const logoutButton = screen.getByText('Log out');
      
      await act(async () => {
        fireEvent.click(logoutButton);
      });

      expect(screen.getByText('Logging out...')).toBeInTheDocument();
      expect(logoutButton).toBeDisabled();

      await waitFor(() => {
        expect(screen.getByText('Log out')).toBeInTheDocument();
      });
    });

    it('deve pedir confirmação se houver mudanças não salvas', async () => {
      render(<Nav />);

      // Simular mudanças não salvas
      const createLink = screen.getByText('Create New Ticket');
      fireEvent.click(createLink);

      const logoutButton = screen.getByText('Log out');
      window.confirm = jest.fn(() => false);

      await act(async () => {
        fireEvent.click(logoutButton);
      });

      expect(window.confirm).toHaveBeenCalledWith(
        expect.stringContaining('alterações não salvos')
      );
      expect(mockSupabase.auth.signOut).not.toHaveBeenCalled();
    });

    it('deve limpar dados sensíveis no logout', async () => {
      render(<Nav />);

      const logoutButton = screen.getByText('Log out');
      
      await act(async () => {
        fireEvent.click(logoutButton);
      });

      await waitFor(() => {
        expect(window.localStorage.removeItem).toHaveBeenCalledWith('ticket_drafts');
        expect(window.localStorage.removeItem).toHaveBeenCalledWith('user_preferences');
        expect(window.localStorage.removeItem).toHaveBeenCalledWith('form_data');
        expect(window.localStorage.removeItem).toHaveBeenCalledWith('cached_user_data');
        expect(window.sessionStorage.clear).toHaveBeenCalled();
      });
    });

    it('deve lidar com erro de logout graciosamente', async () => {
      mockSupabase.auth.signOut.mockResolvedValue({
        error: { message: 'Network error' },
      });

      render(<Nav />);

      const logoutButton = screen.getByText('Log out');
      
      await act(async () => {
        fireEvent.click(logoutButton);
      });

      await waitFor(() => {
        expect(mockRouter.push).toHaveBeenCalledWith('/login?error=logout_failed');
      });
    });

    it('deve lidar com logout offline', async () => {
      Object.defineProperty(window.navigator, 'onLine', {
        writable: true,
        value: false,
      });

      render(<Nav />);

      const logoutButton = screen.getByText('Log out');
      
      await act(async () => {
        fireEvent.click(logoutButton);
      });

      await waitFor(() => {
        expect(mockRouter.push).toHaveBeenCalledWith('/login?offline=true');
        expect(window.localStorage.removeItem).toHaveBeenCalled();
      });
    });
  });

  describe('Inatividade', () => {
    it('deve configurar timer de inatividade', () => {
      render(<Nav />);

      expect(setTimeout).toHaveBeenCalled();
    });

    it('deve fazer logout após período de inatividade', async () => {
      render(<Nav />);

      // Avançar 30 minutos
      await act(async () => {
        jest.advanceTimersByTime(30 * 60 * 1000);
      });

      await waitFor(() => {
        expect(mockSupabase.auth.signOut).toHaveBeenCalled();
      });

      expect(global.fetch).toHaveBeenCalledWith(
        '/api/audit/log',
        expect.objectContaining({
          body: expect.stringContaining('inactivity'),
        })
      );
    });

    it('deve resetar timer ao detectar atividade', async () => {
      render(<Nav />);

      // Avançar 15 minutos
      act(() => {
        jest.advanceTimersByTime(15 * 60 * 1000);
      });

      // Simular atividade
      act(() => {
        fireEvent.mouseMove(document);
      });

      // Avançar mais 20 minutos (total 35, mas resetou)
      act(() => {
        jest.advanceTimersByTime(20 * 60 * 1000);
      });

      // Não deve ter feito logout ainda
      expect(mockSupabase.auth.signOut).not.toHaveBeenCalled();
    });

    it('deve detectar múltiplos tipos de atividade', () => {
      render(<Nav />);

      const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];

      events.forEach((eventType) => {
        act(() => {
          const event = new Event(eventType);
          document.dispatchEvent(event);
        });
      });

      // Timer deve ter sido resetado múltiplas vezes
      expect(clearTimeout).toHaveBeenCalled();
    });
  });

  describe('Mudanças de estado de autenticação', () => {
    it('deve lidar com SIGNED_OUT em outra aba', async () => {
      render(<Nav />);

      await act(async () => {
        mockAuthStateChangeCallback('SIGNED_OUT', null);
      });

      await waitFor(() => {
        expect(global.fetch).toHaveBeenCalledWith(
          '/api/audit/log',
          expect.objectContaining({
            body: expect.stringContaining('multiple_tabs'),
          })
        );
      });
    });

    it('deve resetar timer ao renovar token', async () => {
      render(<Nav />);

      await act(async () => {
        mockAuthStateChangeCallback('TOKEN_REFRESHED', {});
      });

      // Deve ter limpado e recriado o timer
      expect(clearTimeout).toHaveBeenCalled();
      expect(setTimeout).toHaveBeenCalled();
    });

    it('deve atualizar página ao atualizar usuário', async () => {
      render(<Nav />);

      await act(async () => {
        mockAuthStateChangeCallback('USER_UPDATED', {});
      });

      expect(mockRouter.refresh).toHaveBeenCalled();
    });
  });

  describe('Prevenção de navegação', () => {
    it('deve prevenir fechamento de página com dados não salvos', () => {
      render(<Nav />);

      // Simular mudanças não salvas
      const createLink = screen.getByText('Create New Ticket');
      fireEvent.click(createLink);

      const event = new Event('beforeunload') as BeforeUnloadEvent;
      const preventDefaultSpy = jest.spyOn(event, 'preventDefault');

      window.dispatchEvent(event);

      expect(preventDefaultSpy).toHaveBeenCalled();
    });
  });

  describe('Validação de segurança', () => {
    it('deve validar returnUrl para prevenir redirects maliciosos', async () => {
      // Simular URL com returnUrl malicioso
      delete (window as any).location;
      (window as any).location = {
        search: '?returnUrl=https://malicious.com',
      };

      render(<Nav />);

      const logoutButton = screen.getByText('Log out');
      
      await act(async () => {
        fireEvent.click(logoutButton);
      });

      await waitFor(() => {
        // Deve usar URL segura padrão
        expect(mockRouter.push).toHaveBeenCalledWith('/');
      });
    });

    it('deve aceitar returnUrl relativo válido', async () => {
      delete (window as any).location;
      (window as any).location = {
        search: '?returnUrl=/dashboard',
      };

      render(<Nav />);

      const logoutButton = screen.getByText('Log out');
      
      await act(async () => {
        fireEvent.click(logoutButton);
      });

      await waitFor(() => {
        expect(mockRouter.push).toHaveBeenCalledWith('/dashboard');
      });
    });

    it('deve prevenir múltiplos logouts simultâneos', async () => {
      render(<Nav />);

      const logoutButton = screen.getByText('Log out');
      
      // Clicar múltiplas vezes rapidamente
      await act(async () => {
        fireEvent.click(logoutButton);
        fireEvent.click(logoutButton);
        fireEvent.click(logoutButton);
      });

      await waitFor(() => {
        // Deve ter chamado signOut apenas uma vez
        expect(mockSupabase.auth.signOut).toHaveBeenCalledTimes(1);
      });
    });
  });

  describe('Auditoria', () => {
    it('deve registrar todas as etapas do logout', async () => {
      render(<Nav />);

      const logoutButton = screen.getByText('Log out');
      
      await act(async () => {
        fireEvent.click(logoutButton);
      });

      await waitFor(() => {
        expect(global.fetch).toHaveBeenCalledWith(
          '/api/audit/log',
          expect.objectContaining({
            body: expect.stringContaining('logout_initiated'),
          })
        );

        expect(global.fetch).toHaveBeenCalledWith(
          '/api/audit/log',
          expect.objectContaining({
            body: expect.stringContaining('logout_completed'),
          })
        );
      });
    });

    it('não deve bloquear logout se auditoria falhar', async () => {
      (global.fetch as jest.Mock).mockRejectedValue(new Error('Audit failed'));

      render(<Nav />);

      const logoutButton = screen.getByText('Log out');
      
      await act(async () => {
        fireEvent.click(logoutButton);
      });

      await waitFor(() => {
        // Logout deve continuar mesmo com falha na auditoria
        expect(mockSupabase.auth.signOut).toHaveBeenCalled();
        expect(mockRouter.push).toHaveBeenCalled();
      });
    });
  });

  describe('Limpeza de recursos', () => {
    it('deve limpar timers ao desmontar componente', () => {
      const { unmount } = render(<Nav />);

      unmount();

      expect(clearTimeout).toHaveBeenCalled();
    });

    it('deve remover event listeners ao desmontar', () => {
      const removeEventListenerSpy = jest.spyOn(document, 'removeEventListener');
      const { unmount } = render(<Nav />);

      unmount();

      expect(removeEventListenerSpy).toHaveBeenCalledWith('mousedown', expect.any(Function));
      expect(removeEventListenerSpy).toHaveBeenCalledWith('mousemove', expect.any(Function));
    });
  });
});