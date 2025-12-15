// src/app/profile/add-phone.tsx
// Componente para adicionar telefone depois do cadastro
'use client'
import { supabaseClient } from "@/lib/supabase-client";
import { ChangeEvent, FormEvent, useState, useEffect } from "react"

export default function AddPhone() {
    const supabase = supabaseClient();
    const [user, setUser] = useState<any>(null);
    const [phone, setPhone] = useState("");
    const [otp, setOtp] = useState("");
    const [message, setMessage] = useState("");
    const [loading, setLoading] = useState(false);
    const [otpSent, setOtpSent] = useState(false);

    useEffect(() => {
        const getUser = async () => {
            const { data: { user } } = await supabase.auth.getUser();
            setUser(user);
            
            // Se já tem telefone, mostrar
            if (user?.phone) {
                setPhone(user.phone);
            }
        };
        getUser();
    }, []);

    const handleSendOTP = async (e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        setMessage("");
        setLoading(true);

        try {
            const phoneRegex = /^\+[1-9]\d{10,14}$/;
            if (!phoneRegex.test(phone)) {
                setMessage("Formato inválido. Use: +5511999999999");
                setLoading(false);
                return;
            }

            const { error } = await supabase.auth.updateUser({
                phone: phone
            });

            if (error) {
                setMessage(`Erro: ${error.message}`);
            } else {
                setMessage("Código enviado! Verifique seu SMS.");
                setOtpSent(true);
            }
        } catch (error) {
            setMessage("Erro inesperado.");
        } finally {
            setLoading(false);
        }
    };

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
                setMessage(`Erro: ${error.message}`);
            } else if (data.user) {
                setMessage("Telefone adicionado com sucesso!");
                setOtpSent(false);
                setOtp("");
                
                // Atualizar usuário
                const { data: { user } } = await supabase.auth.getUser();
                setUser(user);
            }
        } catch (error) {
            setMessage("Erro inesperado.");
        } finally {
            setLoading(false);
        }
    };

    // Se usuário já tem telefone verificado
    if (user?.phone && !otpSent) {
        return (
            <div className="max-w-md mx-auto p-6 bg-white dark:bg-gray-900 rounded-lg shadow">
                <h3 className="text-xl font-bold mb-4 dark:text-white">
                    📱 Telefone
                </h3>
                
                <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-lg mb-4">
                    <p className="text-sm text-green-800 dark:text-green-200">
                        ✅ Telefone verificado
                    </p>
                    <p className="font-semibold dark:text-white mt-1">
                        {user.phone}
                    </p>
                </div>

                <button
                    onClick={() => {
                        setPhone("");
                        setMessage("");
                    }}
                    className="w-full px-4 py-2 bg-gray-200 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-700"
                >
                    Alterar telefone
                </button>
            </div>
        );
    }

    // Se está esperando OTP
    if (otpSent) {
        return (
            <div className="max-w-md mx-auto p-6 bg-white dark:bg-gray-900 rounded-lg shadow">
                <h3 className="text-xl font-bold mb-4 dark:text-white">
                    Verificar Telefone
                </h3>
                
                {message && (
                    <div className={`p-3 mb-4 rounded-lg ${
                        message.includes("Erro")
                            ? "bg-red-50 text-red-800 dark:bg-red-900/20 dark:text-red-200" 
                            : "bg-green-50 text-green-800 dark:bg-green-900/20 dark:text-green-200"
                    }`}>
                        {message}
                    </div>
                )}

                <div className="mb-4 p-3 bg-blue-50 dark:bg-blue-900/20 rounded">
                    <p className="text-sm dark:text-blue-200">
                        Código enviado para: <strong>{phone}</strong>
                    </p>
                </div>

                <form onSubmit={handleVerifyOTP} className="space-y-4">
                    <div>
                        <label className="block text-sm font-medium mb-1 dark:text-gray-300">
                            Código (6 dígitos)
                        </label>
                        <input
                            type="text"
                            placeholder="000000"
                            value={otp}
                            onChange={(e: ChangeEvent<HTMLInputElement>) => 
                                setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))
                            }
                            className="w-full px-4 py-2 border rounded-lg dark:bg-gray-800 dark:border-gray-700 dark:text-white text-center text-2xl tracking-widest"
                            required
                            maxLength={6}
                        />
                    </div>
                    
                    <button
                        type="submit"
                        className="w-full px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600"
                        disabled={loading || otp.length !== 6}
                    >
                        {loading ? "Verificando..." : "Verificar"}
                    </button>

                    <button
                        type="button"
                        onClick={() => {
                            setOtpSent(false);
                            setOtp("");
                        }}
                        className="w-full px-4 py-2 bg-gray-200 dark:bg-gray-800 rounded-lg"
                    >
                        Voltar
                    </button>
                </form>
            </div>
        );
    }

    // Formulário para adicionar telefone
    return (
        <div className="max-w-md mx-auto p-6 bg-white dark:bg-gray-900 rounded-lg shadow">
            <h3 className="text-xl font-bold mb-4 dark:text-white">
                📱 Adicionar Telefone
            </h3>
            
            {message && (
                <div className={`p-3 mb-4 rounded-lg ${
                    message.includes("Erro")
                        ? "bg-red-50 text-red-800 dark:bg-red-900/20 dark:text-red-200" 
                        : "bg-green-50 text-green-800 dark:bg-green-900/20 dark:text-green-200"
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
                        className="w-full px-4 py-2 border rounded-lg dark:bg-gray-800 dark:border-gray-700 dark:text-white"
                        required
                    />
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                        Formato: +5511999999999 (código do país + DDD + número)
                    </p>
                </div>
                
                <button
                    type="submit"
                    className="w-full px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600"
                    disabled={loading}
                >
                    {loading ? "Enviando..." : "Enviar Código SMS"}
                </button>
            </form>
        </div>
    );
}