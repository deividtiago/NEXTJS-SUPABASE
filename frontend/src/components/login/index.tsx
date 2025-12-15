// src/components/login/index.tsx - CORRIGIDO
'use client'
import { getSupabaseBrowserClient } from "@/supabase-utils/browserClient";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import styles from "./Login.module.css";
import { FormType } from "./formTypes";

interface LoginProps {
  formType?: FormType;
}

export default function Login({ formType = "pw-login" }: LoginProps) {
  const emailInputRef = useRef<HTMLInputElement>(null);
  const passwordInputRef = useRef<HTMLInputElement>(null);
  const supabase = getSupabaseBrowserClient();
  const router = useRouter();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const isPasswordRecovery = formType === "password-recovery";
  const isPasswordLogin = formType === "pw-login";
  const isMagicLinkLogin = formType === "magic-link";

  useEffect(() => {
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((event, session) => {
      console.log("Auth state changed:", event, session?.user?.email);
      if (event === "SIGNED_IN") {
        router.push("/tickets");
        router.refresh();
      }
    });

    return () => subscription.unsubscribe();
  }, [supabase.auth, router]);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setIsLoading(true);
    setError(null);
    setSuccessMessage(null);

    try {
      const email = emailInputRef.current?.value;
      const password = passwordInputRef.current?.value;

      if (!email) {
        throw new Error("Email é obrigatório");
      }

      if (isPasswordLogin) {
        const formData = new FormData();
        formData.append('email', email);
        if (password) formData.append('password', password);

        console.log("Enviando login para:", email);
        
        const response = await fetch('/auth/pw-login', {
          method: 'POST',
          body: formData,
        });

        const data = await response.json();
        console.log("Resposta do login:", data);
        
        if (!response.ok) {
          throw new Error(data.error || "Erro desconhecido no login");
        }

        if (data.success) {
          setSuccessMessage("Login realizado com sucesso! Redirecionando...");
          
          setTimeout(() => {
            router.push('/tickets');
            router.refresh(); 
          }, 300); 
        } else {
          throw new Error(data.error || "Login falhou");
        }
        
      } else if (isMagicLinkLogin) {
        console.log("Enviando magic link customizado para:", email);
        
        const response = await fetch('/auth/magic-link', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ email }),
        });

        const data = await response.json();
        
        if (!response.ok) {
          throw new Error(data.error || "Erro ao enviar magic link");
        }

        setSuccessMessage(data.message || "Magic link enviado! Verifique seu email.");
        
        setTimeout(() => {
          router.push(data.redirect || '/magic-thanks');
        }, 500);

      } else if (isPasswordRecovery) {
        console.log("Enviando recuperação para:", email);
        
        // 🔥 CORREÇÃO: USAR SUA API EM VEZ DO SUPABASE DIRETO
        const response = await fetch('/auth/magic-link', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ 
            email,
            type: 'recovery' // 🔥 PASSAR O TYPE RECOVERY!
          }),
        });

        const data = await response.json();
        
        if (!response.ok) {
          throw new Error(data.error || "Erro ao enviar link de recuperação");
        }

        setSuccessMessage(data.message || "Link de recuperação enviado! Verifique seu email.");
        
        setTimeout(() => {
          router.push(data.redirect || '/magic-thanks?type=recovery');
        }, 1500);
      }
    } catch (err: any) {
      console.error("Erro no login:", err);
      setError(err.message || "Ocorreu um erro. Tente novamente.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <>
      <form onSubmit={handleSubmit}>
        {isPasswordRecovery && (
          <input type="hidden" name="type" value="recovery" />
        )}

        <article className={styles.loginContainer}>
          <header className={styles.loginHeader}>
            {isPasswordRecovery ? "Recuperar Senha" : "Login"}
          </header>
          
          {error && (
            <div className={styles.errorMessage}>
              {error}
            </div>
          )}
          
          {successMessage && (
            <div className={styles.successMessage}>
              {successMessage}
            </div>
          )}
          
          <fieldset className={styles.fieldset} disabled={isLoading}>
            <label htmlFor="email" className={styles.label}>
              Email
              <input
                ref={emailInputRef}
                type="email"
                id="email"
                name="email"
                required
                className={styles.input}
                autoComplete="email"
                disabled={isLoading}
              />
            </label>
            
            {isPasswordLogin && (
              <label htmlFor="password" className={styles.label}>
                Senha
                <input
                  ref={passwordInputRef}
                  type="password"
                  id="password"
                  name="password"
                  required
                  className={styles.input}
                  autoComplete="current-password"
                  disabled={isLoading}
                />
              </label>
            )}
          </fieldset>

          <div className={styles.linksContainer}>
            {!isPasswordLogin && (
              <Link
                href={{
                  pathname: "/login",
                  query: { type: "password" },
                }}
                className={styles.navLink}
              >
                Login com Senha
              </Link>
            )}
            {!isMagicLinkLogin && (
              <Link
                href={{
                  pathname: "/login",
                  query: { type: "magiclink" },
                }}
                className={styles.navLink}
              >
                Login com Magic Link
              </Link>
            )}
          </div>

          <button 
            type="submit"
            className={styles.submitButton}
            disabled={isLoading}
          >
            {isLoading ? "Processando..." : 
              isPasswordLogin ? "Entrar com Senha" :
              isPasswordRecovery ? "Recuperar Senha" :
              "Enviar Magic Link"}
          </button>

          {!isPasswordRecovery && (
            <div className={styles.recoveryLink}>
              <Link
                href={{
                  pathname: "/login",
                  query: { type: "recovery" },
                }}
              >
                Esqueceu sua senha?
              </Link>
            </div>
          )}
        </article>
      </form>
    </>
  );
}