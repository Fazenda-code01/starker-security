// api/contato.js
// Função serverless da Vercel. Recebe o POST do formulário, valida (incluindo
// Turnstile anti-bot), filtra spam e grava no Supabase usando a service_role key
// (nunca exposta ao navegador).
//
// Dependências novas necessárias (já devem estar no package.json):
//   @upstash/redis
//   @upstash/ratelimit
//
// Variáveis de ambiente novas necessárias (Vercel > Settings > Environment Variables):
//   UPSTASH_REDIS_REST_URL
//   UPSTASH_REDIS_REST_TOKEN
// (crie um banco gratuito em https://console.upstash.com — plano free é suficiente)

import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import { Redis } from '@upstash/redis';
import { Ratelimit } from '@upstash/ratelimit';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY // NUNCA a anon key aqui — só no servidor
);

// Rate limit real e persistente entre instâncias serverless (ao contrário de um Map em memória).
// 5 tentativas por IP a cada 60 segundos.
const ratelimit = new Ratelimit({
  redis: new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN,
  }),
  limiter: Ratelimit.slidingWindow(5, '60 s'),
  analytics: true,
  prefix: 'ratelimit:contato',
});

function validarEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function sanitizar(str, max = 2000) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, max);
}

// Escapa HTML para evitar XSS armazenado caso esses dados sejam exibidos
// depois em um painel admin, email em HTML, etc.
function escaparHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Validação simples de telefone/WhatsApp
function validarWhatsapp(str) {
  if (!str) return true; // campo opcional
  return /^[\d\s()+-]{8,20}$/.test(str);
}

// Valida o token do Turnstile direto com a API da Cloudflare
async function validarTurnstile(token, ip) {
  if (!token) return false;

  try {
    const resposta = await fetch(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          secret: process.env.TURNSTILE_SECRET_KEY,
          response: token,
          remoteip: ip,
        }),
      }
    );
    const data = await resposta.json();
    return data.success === true;
  } catch (err) {
    console.error('Erro ao validar Turnstile:', err.message);
    return false; // em caso de dúvida, bloqueia
  }
}

export default async function handler(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

  if (req.method !== 'POST') {
    return res.status(405).json({ erro: 'Método não permitido' });
  }

  try {
    const ip =
      req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
      req.socket?.remoteAddress ||
      'desconhecido';

    const { success } = await ratelimit.limit(ip);
    if (!success) {
      return res.status(429).json({ erro: 'Muitas tentativas. Aguarde um minuto.' });
    }

    const body = req.body || {};

    if (JSON.stringify(body).length > 20_000) {
      return res.status(413).json({ erro: 'Requisição muito grande' });
    }

    if (body.website) {
      return res.status(200).json({ ok: true });
    }

    const turnstileOk = await validarTurnstile(body.turnstileToken, ip);
    if (!turnstileOk) {
      return res.status(403).json({ erro: 'Verificação de segurança falhou' });
    }

    const nome = escaparHtml(sanitizar(body.nome, 200));
    const email = sanitizar(body.email, 200);
    const whatsapp = sanitizar(body.whatsapp, 30);
    const empresa = escaparHtml(sanitizar(body.empresa, 200));
    const servico = escaparHtml(sanitizar(body.servico, 50));
    const mensagem = escaparHtml(sanitizar(body.mensagem, 3000));
    const autorizacao = body.autorizacao === true;

    if (!nome || !email || !validarEmail(email)) {
      return res.status(400).json({ erro: 'Nome e email válidos são obrigatórios' });
    }

    if (!validarWhatsapp(whatsapp)) {
      return res.status(400).json({ erro: 'WhatsApp em formato inválido' });
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

    if (error) {
      console.error('Erro ao gravar lead:', error.message);
      return res.status(500).json({ erro: 'Erro interno ao salvar' });
    }

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
      }
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('Erro inesperado em /api/contato:', err);
    return res.status(500).json({ erro: 'Erro interno' });
  }
}
