// api/contato.js
// Função serverless da Vercel. Recebe o POST do formulário, valida, filtra spam
// e grava no Supabase usando a service_role key (nunca exposta ao navegador).
import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY // NUNCA a anon key aqui — só no servidor
);

// Rate limit simples em memória (por instância). Para produção séria,
// trocar por Upstash Redis (grátis) se o volume de spam justificar.
const tentativasPorIp = new Map();
const JANELA_MS = 60_000; // 1 minuto
const MAX_TENTATIVAS = 5;

function limitado(ip) {
  const agora = Date.now();
  const registro = tentativasPorIp.get(ip) || [];
  const recentes = registro.filter((t) => agora - t < JANELA_MS);
  recentes.push(agora);
  tentativasPorIp.set(ip, recentes);
  return recentes.length > MAX_TENTATIVAS;
}

function validarEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function sanitizar(str, max = 2000) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, max);
}

export default async function handler(req, res) {
  // Cabeçalhos de segurança básicos
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');

  if (req.method !== 'POST') {
    return res.status(405).json({ erro: 'Método não permitido' });
  }

  const ip =
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.socket?.remoteAddress ||
    'desconhecido';

  if (limitado(ip)) {
    return res.status(429).json({ erro: 'Muitas tentativas. Aguarde um minuto.' });
  }

  const body = req.body || {};

  // Honeypot: campo invisível que só bots preenchem. Se vier preenchido, finge sucesso.
  if (body.website) {
    return res.status(200).json({ ok: true });
  }

  const nome = sanitizar(body.nome, 200);
  const email = sanitizar(body.email, 200);
  const whatsapp = sanitizar(body.whatsapp, 30);
  const empresa = sanitizar(body.empresa, 200);
  const servico = sanitizar(body.servico, 50);
  const mensagem = sanitizar(body.mensagem, 3000);
  const autorizacao = body.autorizacao === true;

  if (!nome || !email || !validarEmail(email)) {
    return res.status(400).json({ erro: 'Nome e email válidos são obrigatórios' });
  }

  if (!autorizacao) {
    return res.status(400).json({ erro: 'É necessário confirmar a autorização' });
  }

  const ipHash = crypto.createHash('sha256').update(ip).digest('hex');

  const { error } = await supabase.from('leads').insert({
    nome,
    email,
    whatsapp,
    empresa,
    servico,
    mensagem,
    autorizacao,
    ip_hash: ipHash,
    user_agent: sanitizar(req.headers['user-agent'] || '', 300),
  });

  // Alerta por email (não bloqueia a resposta ao usuário se falhar)
  if (process.env.RESEND_API_KEY && process.env.ALERTA_EMAIL_PARA) {
    try {
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: 'STARKER Security <onboarding@resend.dev>',
          to: [process.env.ALERTA_EMAIL_PARA],
          subject: `Novo lead: ${nome} (${servico || 'sem serviço definido'})`,
          text:
            `Nome: ${nome}\n` +
            `Email: ${email}\n` +
            `WhatsApp: ${whatsapp}\n` +
            `Empresa: ${empresa}\n` +
            `Serviço: ${servico}\n` +
            `Mensagem: ${mensagem}`,
        }),
      });
    } catch (emailError) {
      console.error('Erro ao enviar alerta de email:', emailError.message);
      // não retorna erro pro usuário — o lead já foi salvo no banco
    }
  }

  if (error) {
    console.error('Erro ao gravar lead:', error.message);
    return res.status(500).json({ erro: 'Erro interno ao salvar' });
  }

  return res.status(200).json({ ok: true });
}
