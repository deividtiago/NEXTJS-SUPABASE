'use client'

import { useEffect, useState, useCallback } from "react";
import { supabaseClient } from '@/lib/supabase-client'
import { User } from '@supabase/supabase-js'

interface Tarefa {
    id: number;
    created_at: string;
    user_id: string;
    titulo: string;
    descricao: string | null;
    concluida: boolean;
    updated_at: string;
}

export default function Manager() {
    const supabase = supabaseClient(); 
    const [user, setUser] = useState<User | null>(null);
    const [novaTarefa, setNovaTarefa] = useState({ titulo: "", descricao: "" });
    const [tarefas, setTarefas] = useState<Tarefa[]>([]);
    const [editandoId, setEditandoId] = useState<number | null>(null);
    const [descricaoEditada, setDescricaoEditada] = useState("");
    const [tituloEditado, setTituloEditado] = useState("");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    const fetchTarefas = useCallback(async () => {
        setLoading(true);
        setError("");
        
        try {
            const { data: { user: currentUser } } = await supabase.auth.getUser();
            
            if (!currentUser) {
                setError("Usuário não autenticado");
                return;
            }

            const { error, data } = await supabase
                .from("manager")
                .select("*")
                .eq("user_id", currentUser.id)
                .order("created_at", { ascending: false });

            if (error) {
                console.error("Erro ao buscar tarefas:", error.message);
                setError("Erro ao carregar tarefas");
                return;
            }
            
            setTarefas(data || []);
        } catch (err) {
            console.error("Erro inesperado:", err);
            setError("Erro inesperado ao carregar tarefas");
        } finally {
            setLoading(false);
        }
    }, [supabase]);

    useEffect(() => {
        // Get initial user
        const getUser = async () => {
            const { data: { user: currentUser } } = await supabase.auth.getUser();
            setUser(currentUser);
            
            if (currentUser) {
                fetchTarefas();
            }
        };

        getUser();
    }, [supabase, fetchTarefas]);

    useEffect(() => {
        if (!user) return;

        // Subscribe to realtime changes (filtered by user)
        const channel = supabase
            .channel('manager_changes')
            .on(
                'postgres_changes',
                {
                    event: '*',
                    schema: 'public',
                    table: 'manager',
                    filter: `user_id=eq.${user.id}` // Filtrar apenas tarefas do usuário
                },
                (payload) => {
                    console.log('Mudança detectada:', payload);
                    fetchTarefas();
                }
            )
            .subscribe();

        return () => {
            supabase.removeChannel(channel);
        };
    }, [user, supabase, fetchTarefas]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        
        if (!novaTarefa.titulo.trim()) {
            setError("O título é obrigatório");
            return;
        }

        if (!user) {
            setError("Usuário não autenticado");
            return;
        }

        setLoading(true);
        setError("");

        try {
            console.log("Tentando inserir tarefa:", {
                titulo: novaTarefa.titulo,
                descricao: novaTarefa.descricao,
                user_id: user.id
            });

            const { error, data } = await supabase
                .from("manager")
                .insert({
                    titulo: novaTarefa.titulo,
                    descricao: novaTarefa.descricao || "",
                    user_id: user.id
                })
                .select();

            if (error) {
                console.error("Erro Supabase:", {
                    message: error.message,
                    details: error.details,
                    hint: error.hint,
                    code: error.code
                });
                setError(`Erro ao adicionar tarefa: ${error.message}`);
                return;
            }

            console.log("Tarefa inserida com sucesso:", data);
            setNovaTarefa({ titulo: "", descricao: "" });
            await fetchTarefas();
        } catch (err) {
            console.error("Erro inesperado:", err);
            setError(`Erro inesperado: ${err instanceof Error ? err.message : 'Desconhecido'}`);
        } finally {
            setLoading(false);
        }
    };

    const updateTarefa = async (id: number) => {
        if (!tituloEditado.trim()) {
            setError("O título não pode estar vazio");
            return;
        }

        setLoading(true);
        setError("");

        try {
            const { error } = await supabase
                .from("manager")
                .update({
                    titulo: tituloEditado,
                    descricao: descricaoEditada
                })
                .eq("id", id);

            if (error) {
                console.error("Erro ao atualizar tarefa:", error.message);
                setError("Erro ao atualizar tarefa");
                return;
            }

            setEditandoId(null);
            setDescricaoEditada("");
            setTituloEditado("");
            await fetchTarefas();
        } catch (err) {
            console.error("Erro inesperado:", err);
            setError("Erro inesperado ao atualizar tarefa");
        } finally {
            setLoading(false);
        }
    };

    const toggleConcluida = async (id: number, concluidaAtual: boolean) => {
        setLoading(true);
        setError("");

        try {
            const { error } = await supabase
                .from("manager")
                .update({ concluida: !concluidaAtual })
                .eq("id", id);

            if (error) {
                console.error("Erro ao atualizar status:", error.message);
                setError("Erro ao atualizar status");
                return;
            }

            await fetchTarefas();
        } catch (err) {
            console.error("Erro inesperado:", err);
            setError("Erro inesperado ao atualizar status");
        } finally {
            setLoading(false);
        }
    };

    const deleteTarefa = async (id: number) => {
        if (!confirm("Tem certeza que deseja excluir esta tarefa?")) {
            return;
        }

        setLoading(true);
        setError("");

        try {
            const { error } = await supabase
                .from("manager")
                .delete()
                .eq("id", id);

            if (error) {
                console.error("Erro ao deletar tarefa:", error.message);
                setError("Erro ao deletar tarefa");
                return;
            }

            await fetchTarefas();
        } catch (err) {
            console.error("Erro inesperado:", err);
            setError("Erro inesperado ao deletar tarefa");
        } finally {
            setLoading(false);
        }
    };

    const handleLogout = async () => {
        await supabase.auth.signOut();
        window.location.href = '/login'; // Ajuste conforme sua rota de login
    };

    const iniciarEdicao = (tarefa: Tarefa) => {
        setEditandoId(tarefa.id);
        setTituloEditado(tarefa.titulo);
        setDescricaoEditada(tarefa.descricao || "");
    };

    const cancelarEdicao = () => {
        setEditandoId(null);
        setTituloEditado("");
        setDescricaoEditada("");
    };

    if (!user) {
        return (
            <div className="w-full flex items-center justify-center min-h-screen">
                <div className="text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
                    <p className="text-gray-600 dark:text-gray-400">Verificando autenticação...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="w-full max-w-4xl mx-auto px-4 py-8">
            {/* Header com info do usuário */}
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-3xl font-bold dark:text-white">
                    Gerenciador de Tarefas
                </h1>
                <div className="flex items-center gap-4">
                    <span className="text-sm text-gray-600 dark:text-gray-400">
                        {user.email}
                    </span>
                    <button
                        onClick={handleLogout}
                        className="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 transition-colors dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600"
                    >
                        Sair
                    </button>
                </div>
            </div>

            {error && (
                <div className="mb-4 p-3 bg-red-50 border border-red-200 text-red-800 rounded-lg dark:bg-red-900/20 dark:border-red-800 dark:text-red-200">
                    {error}
                </div>
            )}

            {/* Formulário para adicionar nova tarefa */}
            <form onSubmit={handleSubmit} className="mb-6 space-y-3 bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
                <input 
                    type="text"
                    placeholder="Título da tarefa *"
                    value={novaTarefa.titulo}
                    onChange={(e) =>
                        setNovaTarefa((prev) => ({ ...prev, titulo: e.target.value }))
                    }
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                    disabled={loading}
                    required
                />
                <textarea 
                    placeholder="Descrição da tarefa (opcional)"
                    value={novaTarefa.descricao}
                    onChange={(e) =>
                        setNovaTarefa((prev) => ({ ...prev, descricao: e.target.value }))
                    }
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600 dark:text-white resize-none"
                    rows={3}
                    disabled={loading}
                    required
                />
                <button 
                    type="submit"
                    className="w-full px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed font-medium"
                    disabled={loading}
                >
                    {loading ? "Adicionando..." : "Adicionar Tarefa"}
                </button>
            </form>

            {/* Estatísticas */}
            <div className="mb-6 grid grid-cols-3 gap-4">
                <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-sm text-center">
                    <p className="text-2xl font-bold text-blue-500">{tarefas.length}</p>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Total</p>
                </div>
                <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-sm text-center">
                    <p className="text-2xl font-bold text-green-500">
                        {tarefas.filter(t => t.concluida).length}
                    </p>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Concluídas</p>
                </div>
                <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-sm text-center">
                    <p className="text-2xl font-bold text-orange-500">
                        {tarefas.filter(t => !t.concluida).length}
                    </p>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Pendentes</p>
                </div>
            </div>

            {/* Lista de tarefas */}
            {loading && tarefas.length === 0 ? (
                <div className="text-center py-8">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto mb-2"></div>
                    <p className="text-gray-600 dark:text-gray-400">Carregando tarefas...</p>
                </div>
            ) : tarefas.length === 0 ? (
                <div className="text-center py-12 bg-white dark:bg-gray-800 rounded-lg shadow-sm">
                    <svg className="w-16 h-16 mx-auto mb-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                    </svg>
                    <p className="text-gray-500 dark:text-gray-400 text-lg">
                        Nenhuma tarefa cadastrada
                    </p>
                    <p className="text-gray-400 dark:text-gray-500 text-sm mt-2">
                        Adicione sua primeira tarefa acima!
                    </p>
                </div>
            ) : (
                <ul className="space-y-3">
                    {tarefas.map((tarefa) => (
                        <li
                            key={tarefa.id}
                            className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 shadow-sm hover:shadow-md transition-shadow"
                        >
                            {editandoId === tarefa.id ? (
                                // Modo de edição
                                <div className="space-y-3">
                                    <input
                                        type="text"
                                        value={tituloEditado}
                                        onChange={(e) => setTituloEditado(e.target.value)}
                                        className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                                        placeholder="Título"
                                        disabled={loading}
                                    />
                                    <textarea 
                                        value={descricaoEditada}
                                        onChange={(e) => setDescricaoEditada(e.target.value)}
                                        className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600 dark:text-white resize-none"
                                        placeholder="Descrição"
                                        rows={3}
                                        disabled={loading}
                                    />
                                    <div className="flex gap-2">
                                        <button 
                                            onClick={() => updateTarefa(tarefa.id)}
                                            className="flex-1 px-4 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600 transition-colors disabled:bg-gray-400 font-medium"
                                            disabled={loading}
                                        >
                                            Salvar
                                        </button>
                                        <button 
                                            onClick={cancelarEdicao}
                                            className="flex-1 px-4 py-2 bg-gray-500 text-white rounded-lg hover:bg-gray-600 transition-colors disabled:bg-gray-400 font-medium"
                                            disabled={loading}
                                        >
                                            Cancelar
                                        </button>
                                    </div>
                                </div>
                            ) : (
                                // Modo de visualização
                                <div>
                                    <div className="flex items-start gap-3 mb-3">
                                        <input
                                            type="checkbox"
                                            checked={tarefa.concluida}
                                            onChange={() => toggleConcluida(tarefa.id, tarefa.concluida)}
                                            className="mt-1 h-5 w-5 rounded border-gray-300 text-blue-600 focus:ring-blue-500 cursor-pointer"
                                            disabled={loading}
                                        />
                                        <div className="flex-1">
                                            <h3 className={`text-lg font-semibold dark:text-white ${
                                                tarefa.concluida ? 'line-through text-gray-500 dark:text-gray-500' : ''
                                            }`}>
                                                {tarefa.titulo}
                                            </h3>
                                            {tarefa.descricao && (
                                                <p className={`text-gray-700 dark:text-gray-300 mt-1 ${
                                                    tarefa.concluida ? 'line-through text-gray-500 dark:text-gray-500' : ''
                                                }`}>
                                                    {tarefa.descricao}
                                                </p>
                                            )}
                                            <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                                                Criada em: {new Date(tarefa.created_at).toLocaleString('pt-BR')}
                                            </p>
                                        </div>
                                    </div>
                                    <div className="flex gap-2">
                                        <button 
                                            onClick={() => iniciarEdicao(tarefa)}
                                            className="flex-1 px-4 py-2 bg-yellow-500 text-white rounded-lg hover:bg-yellow-600 transition-colors disabled:bg-gray-400 font-medium"
                                            disabled={loading}
                                        >
                                            Editar
                                        </button>
                                        <button 
                                            onClick={() => deleteTarefa(tarefa.id)}
                                            className="flex-1 px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors disabled:bg-gray-400 font-medium"
                                            disabled={loading}
                                        >
                                            Excluir
                                        </button>
                                    </div>
                                </div>
                            )}
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
}