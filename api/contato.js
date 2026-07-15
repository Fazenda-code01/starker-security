import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import { Redis } from '@upstash/redis';
import { Ratelimit } from '@upstash/ratelimit';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

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

function escaparHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function validarWhatsapp(str) {
  if (!str) return true;
  return /^[\d\s()+-]{8,20}$/.test(str);
}

async function notificarWhatsapp(nome, servico, whatsapp) {
  if (!process.env.CALLMEBOT_PHONE || !process.env.CALLMEBOT_APIKEY) {
    return;
  }

  try {
    const meuNumero = process.env.CALLMEBOT_PHONE;
    const apiKey = process.env.CALLMEBOT_APIKEY;
    const texto = `Novo lead: ${nome} - ${servico || 'sem serviço definido'} - ${whatsapp || 'sem whatsapp'}`;
    const url = `https://api.callmebot.com/whatsapp.php?phone=${encodeURIComponent(meuNumero)}&text=${encodeURIComponent(texto)}&apikey=${encodeURIComponent(apiKey)}`;

    const resp = await fetch(url, { method: 'GET' });

    if (!resp.ok) {
      console.error(`Erro ao enviar alerta de WhatsApp: status ${resp.status}`);
    }
  } catch (whatsappError) {
    console.error('Erro ao enviar alerta de WhatsApp:', whatsappError.message);
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

    await notificarWhatsapp(nome, servico, whatsapp);

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('Erro inesperado em /api/contato:', err);
    return res.status(500).json({ erro: 'Erro interno' });
  }
}
