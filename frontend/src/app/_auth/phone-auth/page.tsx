// src/app/auth/phone-auth/page.tsx
'use client'
import { supabaseClient } from "@/lib/supabase-client";
import { ChangeEvent, FormEvent, useState } from "react"
import { useRouter } from "next/navigation";

export default function PhoneAuth() {
    const supabase = supabaseClient();
    const router = useRouter();
    const [phone, setPhone] = useState("");
    const [otp, setOtp] = useState("");
    const [message, setMessage] = useState("");
    const [loading, setLoading] = useState(false);
    const [otpSent, setOtpSent] = useState(false);

    // Função para enviar código SMS
    const handleSendOTP = async (e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        setMessage("");
        setLoading(true);

        try {
            // Validar formato do telefone (deve incluir código do país)
            const phoneRegex = /^\+[1-9]\d{10,14}$/;
            if (!phoneRegex.test(phone)) {
                setMessage("Formato inválido. Use: +55 (código do país) + DDD + número");
                setLoading(false);
                return;
            }

            const { error } = await supabase.auth.signInWithOtp({
                phone: phone,
            });

            if (error) {
                console.error("Erro ao enviar OTP:", error);
                setMessage(`Erro: ${error.message}`);
            } else {
                setMessage("Código enviado! Verifique suas mensagens SMS.");
                setOtpSent(true);
            }
        } catch (error) {
            console.error("Erro inesperado:", error);
            setMessage("Erro inesperado. Tente novamente.");
        } finally {
            setLoading(false);
        }
    };

    // Função para verificar código OTP
    const handleVerifyOTP = async (e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        setMessage("");
        setLoading(true);

        try {
            const { data, error } = await supabase.auth.verifyOtp({
                phone: phone,
                token: otp,
                type: 'sms'
            });

            if (error) {
                console.error("Erro ao verificar OTP:", error);
                setMessage(`Erro: ${error.message}`);
            } else if (data.session) {
                setMessage("Login realizado com sucesso!");
                setTimeout(() => {
                    router.push('/');
                }, 500);
            } else {
                setMessage("Código incorreto. Tente novamente.");
            }
        } catch (error) {
            console.error("Erro inesperado:", error);
            setMessage("Erro inesperado. Tente novamente.");
        } finally {
            setLoading(false);
        }
    };

    const handleResendOTP = async () => {
        setLoading(true);
        setMessage("");

        try {
            const { error } = await supabase.auth.signInWithOtp({
                phone: phone,
            });

            if (error) {
                setMessage(`Erro ao reenviar: ${error.message}`);
            } else {
                setMessage("Código reenviado!");
            }
        } catch (error) {
            console.error("Erro ao reenviar:", error);
            setMessage("Erro ao reenviar código.");
        } finally {
            setLoading(false);
        }
    };

    if (otpSent) {
        return (
            <div className="flex min-h-screen items-center justify-center bg-zinc-50 font-sans dark:bg-black">
                <main className="flex min-h-screen w-full max-w-3xl flex-col items-center justify-between py-32 px-16 bg-white dark:bg-black sm:items-start">
                    <div className="w-full max-w-md mx-auto">
                        <h2 className="text-2xl font-bold mb-6 text-center dark:text-white">
                            Verificar Código
                        </h2>
                        
                        {/* Tabs de navegação */}
                        <div className="flex gap-2 mb-6">
                            <button
                                onClick={() => router.push('/auth')}
                                className="flex-1 py-2 rounded-lg transition-colors bg-gray-200 text-gray-700 dark:bg-gray-800 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-700"
                            >
                                📧 Email
                            </button>
                            <button
                                className="flex-1 py-2 rounded-lg transition-colors bg-blue-500 text-white"
                            >
                                📱 Telefone
                            </button>
                        </div>
                        
                        {message && (
                            <div className={`p-3 mb-4 rounded-lg ${
                                message.includes("Erro") || message.includes("incorreto")
                                    ? "bg-red-50 border border-red-200 text-red-800 dark:bg-red-900/20 dark:border-red-800 dark:text-red-200" 
                                    : "bg-green-50 border border-green-200 text-green-800 dark:bg-green-900/20 dark:border-green-800 dark:text-green-200"
                            }`}>
                                {message}
                            </div>
                        )}

                        <form onSubmit={handleVerifyOTP} className="space-y-4">
                            <div>
                                <label className="block text-sm font-medium mb-1 dark:text-gray-300">
                                    Telefone
                                </label>
                                <input
                                    type="tel"
                                    value={phone}
                                    disabled
                                    className="w-full px-4 py-2 border border-gray-300 rounded-lg bg-gray-100 dark:bg-gray-800 dark:border-gray-700 dark:text-white"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium mb-1 dark:text-gray-300">
                                    Código de Verificação
                                </label>
                                <input
                                    type="text"
                                    placeholder="000000"
                                    value={otp}
                                    onChange={(e: ChangeEvent<HTMLInputElement>) => 
                                        setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))
                                    }
                                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-800 dark:border-gray-700 dark:text-white text-center text-2xl tracking-widest"
                                    required
                                    disabled={loading}
                                    maxLength={6}
                                />
                                <p className="text-sm text-gray-600 dark:text-gray-400 mt-2">
                                    Digite o código de 6 dígitos enviado via SMS
                                </p>
                            </div>
                            
                            <button
                                type="submit"
                                className="w-full px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed"
                                disabled={loading || otp.length !== 6}
                            >
                                {loading ? "Verificando..." : "Verificar Código"}
                            </button>
                        </form>
                        
                        <div className="mt-4 text-center space-y-2">
                            <button
                                onClick={handleResendOTP}
                                className="text-blue-500 hover:text-blue-600 dark:text-blue-400 dark:hover:text-blue-300 text-sm"
                                disabled={loading}
                            >
                                Reenviar código
                            </button>
                            
                            <div>
                                <button
                                    onClick={() => {
                                        setOtpSent(false);
                                        setOtp("");
                                        setMessage("");
                                    }}
                                    className="text-gray-500 hover:text-gray-600 dark:text-gray-400 dark:hover:text-gray-300 text-sm"
                                    disabled={loading}
                                >
                                    ← Usar outro número
                                </button>
                            </div>
                        </div>
                    </div>
                </main>
            </div>
        );
    }

    return (
        <div className="flex min-h-screen items-center justify-center bg-zinc-50 font-sans dark:bg-black">
            <main className="flex min-h-screen w-full max-w-3xl flex-col items-center justify-between py-32 px-16 bg-white dark:bg-black sm:items-start">
                <div className="w-full max-w-md mx-auto">
                    <h2 className="text-2xl font-bold mb-6 text-center dark:text-white">
                        Login com Telefone
                    </h2>
                    
                    {/* Tabs de navegação */}
                    <div className="flex gap-2 mb-6">
                        <button
                            onClick={() => router.push('/auth')}
                            className="flex-1 py-2 rounded-lg transition-colors bg-gray-200 text-gray-700 dark:bg-gray-800 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-700"
                        >
                            📧 Email
                        </button>
                        <button
                            className="flex-1 py-2 rounded-lg transition-colors bg-blue-500 text-white"
                        >
                            📱 Telefone
                        </button>
                    </div>
                    
                    {message && (
                        <div className={`p-3 mb-4 rounded-lg ${
                            message.includes("Erro") || message.includes("inválido")
                                ? "bg-red-50 border border-red-200 text-red-800 dark:bg-red-900/20 dark:border-red-800 dark:text-red-200" 
                                : "bg-green-50 border border-green-200 text-green-800 dark:bg-green-900/20 dark:border-green-800 dark:text-green-200"
                        }`}>
                            {message}
                        </div>
                    )}
                    
                    <form onSubmit={handleSendOTP} className="space-y-4">
                        <div>
                            <label className="block text-sm font-medium mb-1 dark:text-gray-300">
                                Número de Telefone
                            </label>
                            <input
                                type="tel"
                                placeholder="+5511999999999"
                                value={phone}
                                onChange={(e: ChangeEvent<HTMLInputElement>) => 
                                    setPhone(e.target.value)
                                }
                                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-800 dark:border-gray-700 dark:text-white"
                                required
                                disabled={loading}
                            />
                            <p className="text-sm text-gray-600 dark:text-gray-400 mt-2">
                                Exemplo: +5511999999999 (código do país + DDD + número)
                            </p>
                        </div>
                        
                        <button
                            type="submit"
                            className="w-full px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed"
                            disabled={loading}
                        >
                            {loading ? "Enviando..." : "Enviar Código SMS"}
                        </button>
                    </form>
                </div>
            </main>
        </div>
    );
}