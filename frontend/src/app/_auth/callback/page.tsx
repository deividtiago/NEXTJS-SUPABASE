// app/auth/callback/page.tsx
'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { supabaseClient } from '@/lib/supabase-client'

export default function AuthCallback() {
  const router = useRouter()
  const supabase = supabaseClient()
  const [processing, setProcessing] = useState(true)

  useEffect(() => {
    let isMounted = true
    let timeoutId: NodeJS.Timeout

    const handleCallback = async () => {
      try {
        console.log('🔐 Processando callback de autenticação...')
        
        const { data, error } = await supabase.auth.getSession()
        
        if (!isMounted) return

        if (error) {
          console.error('❌ Erro no callback:', error)
          router.push('/auth?error=callback_failed')
          return
        }

        if (data?.session) {
          console.log('✅ Login bem-sucedido - redirecionando para página principal')
          // ✅ CORRIGIDO: Timeout para evitar redirecionamentos muito rápidos
          timeoutId = setTimeout(() => {
            if (isMounted) {
              router.push('/')
            }
          }, 1000)
        } else {
          console.log('❌ Sem sessão - redirecionando para login')
          timeoutId = setTimeout(() => {
            if (isMounted) {
              router.push('/auth')
            }
          }, 1000)
        }
      } catch (err) {
        console.error('❌ Erro inesperado:', err)
        if (isMounted) {
          router.push('/auth')
        }
      } finally {
        if (isMounted) {
          setProcessing(false)
        }
      }
    }

    // ✅ CORRIGIDO: Delay inicial para evitar condições de corrida
    const initialDelay = setTimeout(() => {
      handleCallback()
    }, 500)

    // ✅ CORRIGIDO: Cleanup completo
    return () => {
      isMounted = false
      clearTimeout(initialDelay)
      clearTimeout(timeoutId)
    }
  }, [router, supabase.auth])

  return (
    <div style={{ 
      display: 'flex', 
      justifyContent: 'center', 
      alignItems: 'center', 
      height: '100vh',
      flexDirection: 'column',
      gap: '1rem'
    }}>
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      <div style={{ fontSize: '1.125rem', fontWeight: '500' }}>
        {processing ? 'Processando login...' : 'Redirecionando...'}
      </div>
      <div style={{ fontSize: '0.875rem', color: '#6B7280' }}>
        Aguarde um momento
      </div>
    </div>
  )
}