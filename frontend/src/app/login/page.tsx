// src/app/login/page.tsx
import LoginComponent from '@/components/login/index'
import { FormType } from '@/components/login/formTypes';

export default async function LoginPage({ 
  searchParams 
}: { 
  searchParams: Promise<{ type?: string }> 
}) {
  const params = await searchParams;
  
  // Mapeia para o tipo correto
  const getFormType = (type?: string): FormType => {
    switch(type) {
      case "magiclink":
      case "magic-link":
        return "magic-link";
      case "recovery":
      case "password-recovery":
        return "password-recovery";
      case "password":
      case "pw-login":
      default:
        return "pw-login";
    }
  };
  
  const formType = getFormType(params.type);
  
  return <LoginComponent formType={formType} />;
}