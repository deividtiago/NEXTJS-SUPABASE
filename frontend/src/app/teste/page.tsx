'use client';

import {useEffect, useState} from 'react';
import { supabaseClient } from '@/lib/supabase-client'

export default function TestPage() {
    const [status, setStatus] = useState('Testando conexão...');
    const [users, setUsers] = useState<any[]>([]);

    useEffect(() => {
        async function testarConexao() {
            const supabase = supabaseClient();

            try{
                //Teste tabela users
                const { data, error , count} = await supabase
                .from('users')
                .select('*', {count: 'exact'})
                .limit(5);

                if(error) {
                    setStatus('Erro na tabela Users: ' + error.message);
                } else {
                    setStatus(`CONECTADO! Encontrados ${count} usuários`);
                    setUsers(data || []);
                    console.log('Usuários: ' , data);
                }
            }catch (error: any) { 
                    setStatus ('Erro: ' + error.message);
            }
        }
        testarConexao();
    }, []);

    return(
        <div style={{padding:'20px' , fontFamily: 'Arial'}}>
            <h1>Teste do Supabase - Verificando tabela users</h1>
            <p><strong>Status:</strong> {status} </p>

            {users.length > 0 && 
                (
                    <div style={{ marginTop:'20px'}}>
                    <h3>Usuários encontrados:</h3>
                        <pre style={{
                            background: 'f5f5f5',
                            padding: '10px',
                            borderRadius: '5px',
                            overflow: 'auto'
                        }}>
                            {JSON.stringify(users, null, 2)}
                        </pre>
                    </div>
                )

            }

            {users.length == 0 && status.includes('CONECTADO') && (
                <p style={{color: 'yellow' , marginTop: '20px'}}>
                    Conexão funcionando, mas tabela users está vazia
                </p>
            )}
        </div>

    );
}
