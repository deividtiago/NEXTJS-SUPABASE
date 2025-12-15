// lib/security/password-strength-checker.ts
import { PASSWORD_REQUIREMENTS } from './password-requirements';

export interface PasswordStrength {
  isStrong: boolean;
  feedback: string;
  passedChecks: number;
}

export class PasswordStrengthChecker {
  /**
   * ✅ VALIDAÇÃO CENTRALIZADA - mesma em todos os componentes
   * Usa PASSWORD_REQUIREMENTS como single source of truth
   */
  static check(password: string): PasswordStrength {
    const checks = {
      length: password.length >= PASSWORD_REQUIREMENTS.minLength,
      hasUpperCase: PASSWORD_REQUIREMENTS.requireUppercase ? /[A-Z]/.test(password) : true,
      hasLowerCase: PASSWORD_REQUIREMENTS.requireLowercase ? /[a-z]/.test(password) : true,
      hasNumbers: PASSWORD_REQUIREMENTS.requireNumbers ? /[0-9]/.test(password) : true,
      hasSpecialChar: PASSWORD_REQUIREMENTS.requireSpecialChars ? /[!@#$%^&*(),.?":{}|<>]/.test(password) : true,
    }

    const passedChecks = Object.values(checks).filter(Boolean).length
    const isStrong = passedChecks >= 4 // Pelo menos 4 dos 5 critérios

    // ✅ Feedback específico apenas para UI de criação de senha
    // Não expõe informações sensíveis
    const feedback = !checks.length ? 'Mínimo 8 caracteres' :
                    !checks.hasUpperCase ? 'Inclua letras maiúsculas' :
                    !checks.hasLowerCase ? 'Inclua letras minúsculas' :
                    !checks.hasNumbers ? 'Inclua números' :
                    !checks.hasSpecialChar ? 'Inclua caracteres especiais' : ''

    return { isStrong, feedback, passedChecks }
  }

  static getStrengthColor(strength: number): string {
    switch (strength) {
      case 1: return 'bg-red-500'
      case 2: return 'bg-orange-500'
      case 3: return 'bg-yellow-500'
      case 4: return 'bg-green-500'
      case 5: return 'bg-green-600'
      default: return 'bg-gray-200'
    }
  }

  static getStrengthText(strength: number): string {
    switch (strength) {
      case 1: return 'Muito fraca'
      case 2: return 'Fraca'
      case 3: return 'Média'
      case 4: return 'Forte'
      case 5: return 'Muito forte'
      default: return 'Muito fraca'
    }
  }

  /**
   * ✅ Validação rápida para formulários
   */
  static isValid(password: string): boolean {
    return this.check(password).isStrong
  }

  /**
   * ✅ Validação mínima (apenas tamanho) para compatibilidade
   */
  static meetsMinimumRequirements(password: string): boolean {
    return password.length >= PASSWORD_REQUIREMENTS.minLength
  }
}