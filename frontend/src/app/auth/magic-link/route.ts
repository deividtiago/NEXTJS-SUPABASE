// app/api/auth/magic-link/route.ts - VERSÃO CORRIGIDA
import { getSupabaseAdminClient } from '@/supabase-utils/adminClient';
import { NextResponse } from 'next/server';
import nodemailer from 'nodemailer';

export async function POST(request: Request) {
  console.log('\n📧 ========================================');
  console.log('MAGIC LINK - generateLink (Controle Total)');
  console.log('========================================\n');

  try {
    // 🔥 LER O BODY COMO JSON
    const body = await request.json();
    console.log('🔍 BODY RECEBIDO:', JSON.stringify(body, null, 2)); // 🔥 DEBUG
    
    const email = body.email;
    const type: 'magiclink' | 'recovery' = body.type || 'magiclink'; // 🔥 LER O TYPE
    
    console.log(`📧 Email: ${email}`);
    console.log(`📝 Type: ${type}`); // 🔥 DEVE MOSTRAR "recovery"
    
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return NextResponse.json(
        { error: 'Email é obrigatório e deve ser válido' },
        { status: 400 }
      );
    }

    // Gerar link com admin client
    const supabaseAdmin = getSupabaseAdminClient();
    
    console.log(`🔗 Gerando link de ${type} com generateLink...`);
    
    // 🔥 USAR O TYPE VARIÁVEL
    const { data: linkData, error: errorLink } = await supabaseAdmin.auth.admin.generateLink({
      email,
      type // 🔥 NÃO "magiclink" hardcoded!
    });

    if (errorLink) {
      console.error('❌ Erro ao gerar link:', errorLink);
      return NextResponse.json(
        { error: errorLink.message },
        { status: 500 }
      );
    }

    console.log('✅ Link gerado:', linkData);

    // IMPORTANTE: generateLink retorna properties.hashed_token
    const { hashed_token } = linkData.properties;
    
    // Construir link para a rota de verificação customizada
    const verifyUrl = `${process.env.NEXT_PUBLIC_SITE_URL || 'http://localhost:3000'}/auth/verify`;
    const constructedLink = `${verifyUrl}?token_hash=${hashed_token}&type=${type}`; // 🔥 USAR ${type}
    
    console.log('🔗 Link construído:', constructedLink);
    console.log('📤 Enviando email via Brevo SMTP...');

    // Configurar transporter
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST!,
      port: parseInt(process.env.SMTP_PORT!),
      secure: false,
      auth: {
        user: process.env.SMTP_USER!,
        pass: process.env.SMTP_PASS!,
      },
    });

    // 🔥 CUSTOMIZAR CONTEÚDO BASEADO NO TYPE
    const isRecovery = type === 'recovery';
    const subject = isRecovery 
      ? '🔐 Recuperação de Senha - Task Manager' 
      : 'Seu Magic Link - Task Manager';
    
    const title = isRecovery ? '🔐 Recuperar Senha' : '🎯 Task Manager';
    const greeting = isRecovery 
      ? 'Você solicitou a recuperação de senha.' 
      : 'Você solicitou acesso à sua conta.';
    
    const buttonText = isRecovery 
      ? '🔐 Redefinir minha senha' 
      : '🔓 Acessar minha conta';

    // Enviar email
    const info = await transporter.sendMail({
      from: `"Gerenciador de Tarefas" <deividtiagoooo@gmail.com>`,
      to: email,
      subject,
      html: `
        <!DOCTYPE html>
        <html>
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
          </head>
          <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
            <table role="presentation" style="width: 100%; border-collapse: collapse;">
              <tr>
                <td align="center" style="padding: 40px 0;">
                  <table role="presentation" style="width: 600px; max-width: 100%; border-collapse: collapse; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <tr>
                      <td style="padding: 40px 40px 20px 40px; text-align: center; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 8px 8px 0 0;">
                        <h1 style="margin: 0; color: #ffffff; font-size: 32px;">${title}</h1>
                      </td>
                    </tr>
                    
                    <tr>
                      <td style="padding: 40px; color: #333333; line-height: 1.6;">
                        <h2 style="margin: 0 0 20px 0; color: #4F46E5; font-size: 24px;">Olá! 👋</h2>
                        
                        <p style="margin: 0 0 20px 0; font-size: 16px;">
                          ${greeting} Clique no botão abaixo para continuar:
                        </p>
                        
                        <table role="presentation" style="margin: 30px auto;">
                          <tr>
                            <td style="border-radius: 6px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                              <a href="${constructedLink}" 
                                 target="_blank"
                                 style="display: inline-block; 
                                        padding: 16px 48px; 
                                        color: #ffffff; 
                                        text-decoration: none; 
                                        font-weight: bold;
                                        font-size: 18px;">
                                ${buttonText}
                              </a>
                            </td>
                          </tr>
                        </table>
                        
                        <div style="margin: 30px 0; padding: 20px; background-color: #f8f9fa; border-left: 4px solid #4F46E5; border-radius: 4px;">
                          <p style="margin: 0; color: #666666; font-size: 14px;">
                            ⏱️ Este link expira em <strong>1 hora</strong> e só pode ser usado uma vez.
                          </p>
                        </div>
                        
                        <p style="margin: 20px 0 0 0; color: #666666; font-size: 14px;">
                          Se você não solicitou este email, pode ignorá-lo com segurança.
                        </p>
                      </td>
                    </tr>
                    
                    <tr>
                      <td style="padding: 30px 40px; border-top: 1px solid #eeeeee; background-color: #f8f9fa;">
                        <p style="margin: 0 0 10px 0; color: #999999; font-size: 12px;">
                          Se o botão não funcionar, copie e cole este link:
                        </p>
                        <p style="margin: 0; color: #4F46E5; font-size: 12px; word-break: break-all;">
                          ${constructedLink}
                        </p>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
          </body>
        </html>
      `,
      text: `
Olá!

${greeting}

Clique no link abaixo para continuar:
${constructedLink}

Este link expira em 1 hora e só pode ser usado uma vez.

Se você não solicitou este email, pode ignorá-lo com segurança.
      `.trim()
    });

    console.log('✅ Email enviado!');
    console.log('   Message ID:', info.messageId);
    
    return NextResponse.json({ 
      success: true, 
      message: isRecovery 
        ? 'Link de recuperação enviado! Verifique seu email.' 
        : 'Magic link enviado! Verifique seu email.',
      redirect: '/magic-thanks'
    });

  } catch (error: any) {
    console.error('💥 Erro:', error.message);
    return NextResponse.json(
      { error: 'Erro ao enviar magic link' },
      { status: 500 }
    );
  }
}