// lib/security/ip-detection.ts

/**
 * ✅ Serviço robusto de detecção de IP com fallbacks múltiplos
 * 
 * Estratégia:
 * 1. Tenta múltiplos serviços em paralelo (race condition)
 * 2. Cache local para reduzir chamadas
 * 3. Fallback para fingerprint do navegador se tudo falhar
 * 4. Sistema continua funcionando mesmo sem IP real
 */

interface IPDetectionResult {
  ip: string;
  source: 'ipify' | 'ipapi' | 'cloudflare' | 'fingerprint' | 'fallback';
  reliable: boolean;
  timestamp: number;
}

export class IPDetectionService {
  private static cache: IPDetectionResult | null = null;
  private static readonly CACHE_DURATION = 5 * 60 * 1000; // 5 minutos

  /**
   * ✅ Lista de serviços de detecção de IP (em ordem de preferência)
   */
  private static readonly IP_SERVICES = [
    {
      name: 'ipify' as const,
      url: 'https://api.ipify.org?format=json',
      parser: (data: any) => data.ip,
      timeout: 10000 // ✅ 10s para conexões lentas (3G/4G)
    },
    {
      name: 'ipapi' as const,
      url: 'https://ipapi.co/json/',
      parser: (data: any) => data.ip,
      timeout: 10000
    },
    {
      name: 'cloudflare' as const,
      url: 'https://www.cloudflare.com/cdn-cgi/trace',
      parser: (text: string) => {
        const match = text.match(/ip=([^\n]+)/);
        return match ? match[1] : null;
      },
      timeout: 10000,
      isText: true
    },
    // ✅ NOVO: Serviços adicionais para maior resiliência
    {
      name: 'icanhazip' as const,
      url: 'https://icanhazip.com',
      parser: (text: string) => text.trim(),
      timeout: 10000,
      isText: true
    },
    {
      name: 'ipecho' as const,
      url: 'https://ipecho.net/plain',
      parser: (text: string) => text.trim(),
      timeout: 10000,
      isText: true
    }
  ];

  /**
   * ✅ Método principal: tenta múltiplos serviços em paralelo
   */
  static async getClientIP(): Promise<IPDetectionResult> {
    // 1. Verificar cache
    if (this.cache && Date.now() - this.cache.timestamp < this.CACHE_DURATION) {
      return this.cache;
    }

    try {
      // 2. Tentar serviços em paralelo (race condition - primeiro que responder)
      const result = await this.tryMultipleServices();
      
      if (result) {
        this.cache = result;
        return result;
      }
    } catch (error) {
      console.warn('Todos os serviços de IP falharam:', error);
    }

    // 3. Fallback: usar fingerprint do navegador
    const fallbackResult = this.getFallbackIP();
    this.cache = fallbackResult;
    return fallbackResult;
  }

  /**
   * ✅ Tenta múltiplos serviços em paralelo
   */
  private static async tryMultipleServices(): Promise<IPDetectionResult | null> {
    const promises = this.IP_SERVICES.map(service => 
      this.fetchFromService(service)
    );

    try {
      // Promise.race: retorna o primeiro que resolver
      const result = await Promise.race(promises);
      return result;
    } catch (error) {
      // Se todos falharem, Promise.race rejeita
      return null;
    }
  }

  /**
   * ✅ Fetch de um serviço específico com timeout
   */
  private static async fetchFromService(
    service: typeof IPDetectionService.IP_SERVICES[0]
  ): Promise<IPDetectionResult> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), service.timeout);

    try {
      const response = await fetch(service.url, {
        signal: controller.signal,
        mode: 'cors',
        cache: 'no-cache'
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      let ip: string;
      
      if (service.isText) {
        const text = await response.text();
        ip = service.parser(text);
      } else {
        const data = await response.json();
        ip = service.parser(data);
      }

      if (!ip || !this.isValidIP(ip)) {
        throw new Error('Invalid IP received');
      }

      return {
        ip,
        source: service.name,
        reliable: true,
        timestamp: Date.now()
      };

    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }

  /**
   * ✅ Fallback: gera um "pseudo-IP" baseado no fingerprint do navegador
   * 
   * IMPORTANTE: Não é um IP real, mas serve para:
   * - Rate limiting básico (mesmo navegador = mesmo fingerprint)
   * - Auditoria (identificar sessões suspeitas)
   * - Sistema continua funcionando
   */
  private static getFallbackIP(): IPDetectionResult {
    const fingerprint = this.generateBrowserFingerprint();
    
    return {
      ip: `fp-${fingerprint}`, // Prefixo "fp-" indica fingerprint
      source: 'fingerprint',
      reliable: false,
      timestamp: Date.now()
    };
  }

  /**
   * ✅ Gera fingerprint único do navegador
   */
  private static generateBrowserFingerprint(): string {
    const components = [
      navigator.userAgent,
      navigator.language,
      screen.width,
      screen.height,
      screen.colorDepth,
      new Date().getTimezoneOffset(),
      navigator.hardwareConcurrency || 0,
      navigator.deviceMemory || 0
    ];

    const fingerprint = components.join('|');
    return this.simpleHash(fingerprint);
  }

  /**
   * ✅ Hash simples para fingerprint
   */
  private static simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return Math.abs(hash).toString(36).substring(0, 10);
  }

  /**
   * ✅ Valida formato de IP
   */
  private static isValidIP(ip: string): boolean {
    // IPv4
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(ip)) {
      const parts = ip.split('.').map(Number);
      return parts.every(part => part >= 0 && part <= 255);
    }

    // IPv6 (validação simplificada)
    const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
    return ipv6Regex.test(ip);
  }

  /**
   * ✅ Limpar cache (útil para testes)
   */
  static clearCache(): void {
    this.cache = null;
  }

  /**
   * ✅ Obter status do cache
   */
  static getCacheStatus(): { cached: boolean; age?: number; source?: string } {
    if (!this.cache) {
      return { cached: false };
    }

    return {
      cached: true,
      age: Date.now() - this.cache.timestamp,
      source: this.cache.source
    };
  }
}

/**
 * ✅ Helper function para uso em componentes
 */
export async function getClientIP(): Promise<string> {
  const result = await IPDetectionService.getClientIP();
  return result.ip;
}

/**
 * ✅ Helper function que retorna também metadados
 */
export async function getClientIPWithMetadata(): Promise<IPDetectionResult> {
  return await IPDetectionService.getClientIP();
}