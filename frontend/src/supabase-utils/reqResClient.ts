import { createServerClient, serializeCookieHeader } from "@supabase/ssr";
import { SupabaseClient } from "@supabase/supabase-js";
import { NextRequest, NextResponse } from "next/server"

interface CookieToSet {
    name: string;
    value: string;
    options: any;
}

interface GetSupabaseClientParams {
    request: NextRequest | any;
    response?: NextResponse | any;
}

interface GetSupabaseClientResult {
    supabase: SupabaseClient;
    response: { value: NextResponse | any};
}

export const getSupabaseReqResClient = ({
    request, response: responseInput,
}: GetSupabaseClientParams): GetSupabaseClientResult => {
    let response = {
        value: responseInput ?? NextResponse.next({request: request}),

    };
    const supabase = createServerClient(
        process.env.NEXT_PUBLIC_SUPABASE_URL!,
        process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
        {
            cookies:{
                getAll(){
                    if("getAll" in request.cookies){
                        // ambiente middleware: usa API moderna de cookies
                        return request.cookies.getAll();
                    }else{
                        // Cookies vêm como objeto simples
                        // roteador de paginas ; não middleware
                        return Object.keys(request.cookies).map((name) => ({
                            name,
                            value: request.cookies[name],
                        }));
                    }
                },

                //Escrita de cookies
                setAll(cookiesToSet){
                    if("getAll" in request.cookies) {
                        //MIDDLEWARE: usa NextResponse para gerenciar cookies
                        cookiesToSet.forEach(({ name, value, options }) =>{
                            request.cookies.set(name, value);
                        });

                        response.value = NextResponse.next({
                            request,
                        });

                        cookiesToSet.forEach(({ name, value, options }) => {
                            response.value.cookies.set(name, value, options);
                        });
                    } else {
                        // Usa headers Set-Cookie tradicionais
                        // roteador de paginas / nao middleware
                        responseInput.setHeader(
                            "Set-Cookie",
                            cookiesToSet.map(({ name, value, options })=>
                                serializeCookieHeader(name, value, options)
                            )
                        )
                    }
                }
            }
        }
    )
    return {supabase, response};
};