-- Rode isso no SQL Editor do Supabase (Project > SQL Editor > New query)

create table if not exists leads (
  id uuid primary key default gen_random_uuid(),
  nome text not null,
  email text not null,
  whatsapp text,
  empresa text,
  servico text,
  mensagem text,
  autorizacao boolean not null default false,
  ip_hash text,
  user_agent text,
  criado_em timestamptz not null default now()
);

-- Índice para consultar por data rapidamente no painel
create index if not exists leads_criado_em_idx on leads (criado_em desc);

-- Row Level Security: bloqueia leitura/escrita direta do público.
-- Só a service_role key (usada pela função serverless) pode inserir.
alter table leads enable row level security;

-- Nenhuma policy = ninguém acessa via API pública do Supabase (anon key).
-- Isso é proposital: só o backend (com service_role key, que fica só no servidor) grava aqui.
