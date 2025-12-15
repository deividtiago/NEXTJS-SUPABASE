// supabase-utils/server.ts
import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

export async function createClient() { // ← Função async
  const cookieStore = await cookies() // ← COM await

  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        get(name: string) {
          return cookieStore.get(name)?.value
        },
        set(name: string, value: string, options: any) {
          try {
            cookieStore.set(name, value, options)
          } catch (error) {
            // Server Component
          }
        },
        remove(name: string, options: any) {
          try {
            cookieStore.delete(name) // ← Ou .set com valor vazio
          } catch (error) {
            // Server Component
          }
        },
      },
    }
  )
}