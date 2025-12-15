// lib/security/password-requirements.ts

/**
 * ✅ SINGLE SOURCE OF TRUTH para requisitos de senha
 * Usado por TODOS os componentes para garantir consistência
 */
export const PASSWORD_REQUIREMENTS = {
  minLength: 8,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
} as const;

/**
 * ✅ Mensagens padronizadas - seguras para exibir ao usuário
 * Genéricas o suficiente para não dar pistas a atacantes
 */
export const PASSWORD_MESSAGES = {
  tooShort: "A senha deve ter pelo menos 8 caracteres",
  weak: "A senha não atende aos requisitos de segurança",
  mismatch: "As senhas não coincidem",
  requirements: "A senha deve conter: maiúsculas, minúsculas, números e caracteres especiais"
} as const;

/**
 * ✅ Mensagens genéricas para autenticação
 * NUNCA revela se email existe ou se senha está errada
 */
export const AUTH_MESSAGES = {
  invalidCredentials: "Email ou senha incorretos",
  accountLocked: "Muitas tentativas. Tente novamente em alguns minutos",
  genericError: "Erro ao processar sua solicitação. Tente novamente",
  rateLimitExceeded: "Muitas tentativas. Aguarde antes de tentar novamente",
  suspiciousActivity: "Atividade incomum detectada. Aguarde alguns minutos",
  
  // ✅ NOVAS MENSAGES ADICIONADAS
  emailAlreadyRegistered: "Este email já está cadastrado. Faça login ou recupere sua senha.",
  emailNotConfirmed: "Confirme seu email antes de fazer login. Verifique sua caixa de entrada.",
  emailError: "Erro com o email. Verifique se está correto e tente novamente.",
  rateLimitHour: "Muitas tentativas recentes. Aguarde 1 hora antes de tentar novamente.",
  invalidCredentialsDetailed: "Email ou senha incorretos. Verifique suas credenciais.",
  fillRequiredFields: "Preencha email e senha."
} as const;

/**
 * ✅ Mensagens específicas apenas para SIGNUP
 * Aqui podemos ser mais específicos pois não há risco de enumeration
 */
export const SIGNUP_MESSAGES = {
  passwordTooShort: PASSWORD_MESSAGES.tooShort,
  passwordWeak: PASSWORD_MESSAGES.weak,
  passwordMismatch: PASSWORD_MESSAGES.mismatch,
  emailInvalid: "Email inválido",
  emailDisposable: "Emails temporários não são aceitos",
  success: "Conta criada! Verifique seu email para confirmar"
} as const;

/**
 * ✅ Rate limiting constants
 */
export const RATE_LIMITS = {
  maxLoginAttempts: 5,
  loginWindowMinutes: 15,
  maxPasswordResetAttempts: 3,
  passwordResetWindowMinutes: 60,
  backoffSeconds: 30
} as const;