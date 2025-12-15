import { createServerClient } from "@supabase/ssr"
import { cookies } from "next/headers"

export const getSupabaseCookiesUtilClient = async () => {
    const cookieStore = await cookies();
    //const cookieStore = cookies();

    return createServerClient(
        process.env.NEXT_PUBLIC_SUPABASE_URL!,
        process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
        {
            cookies:{
                getAll() {
                    // 1. Lê cookies da requisição
                    // 2. Inclui tokens JWT se existirem
                    return cookieStore.getAll();
                },
                setAll(cookiesToSet) {
                    try {
                        // 3. Escreve cookies na resposta
                        // 4. Configura HttpOnly, Secure, SameSite
                        cookiesToSet.forEach(({ name, value, options})=> {
                            cookieStore.set(name, value, options);
                        });
                    }catch {}
                },
            },
        }
    );
};