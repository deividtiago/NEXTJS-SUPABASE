// src/components/login/formTypes.ts
export type FormType = "pw-login" | "magic-link" | "password-recovery";

// Constantes com tipos explícitos
export const FORM_TYPES = {
  PASSWORD_LOGIN: "pw-login" as FormType,
  MAGIC_LINK: "magic-link" as FormType,
  PASSWORD_RECOVERY: "password-recovery" as FormType,
};