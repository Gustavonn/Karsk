# K.A.R.S.K. backend

Backend opcional para hospedar o arquivo HTML com contas compartilhadas, permissões e dados persistentes.

Usa [Turso](https://turso.tech) (SQLite compatível, hospedado, com camada gratuita que não expira e não pausa por inatividade) como banco de dados. Se as variáveis do Turso não forem definidas, ele cai automaticamente para um arquivo SQLite local — bom para testar no seu computador, mas não serve pra produção num serviço com disco não-persistente (como o plano grátis do Render).

## Requisitos

- Node.js 20+
- npm

## Desenvolvimento local (sem Turso, banco em arquivo)

1. Copie `.env.example` para `.env`.
2. Troque `KARSK_ADMIN_PASSWORD` por uma senha com pelo menos 10 caracteres.
3. Execute `npm install`.
4. Execute `npm start`.
5. Sirva `karsk_ai.html` por HTTP, por exemplo com `npx serve . -l 5500`.
6. Abra `http://localhost:5500/karsk_ai.html?api=http://localhost:8787/api`.

## Banco de dados gratuito com Turso (recomendado para produção)

1. Crie uma conta grátis em [turso.tech](https://turso.tech) (sem cartão de crédito).
2. No painel, crie um banco novo (qualquer nome, ex: `karsk`).
3. Na página do banco, copie a **Database URL** (algo como `libsql://karsk-seuusuario.turso.io`).
4. Ainda na página do banco, crie um **token de autenticação** (Create Token) e copie o valor.
5. Cole os dois no `.env` (ou nas variáveis de ambiente do seu host):
   ```
   TURSO_DATABASE_URL=libsql://karsk-seuusuario.turso.io
   TURSO_AUTH_TOKEN=o-token-que-voce-copiou
   ```
6. Rode `npm start` normalmente — as tabelas são criadas automaticamente no Turso no primeiro boot.

O plano grátis do Turso inclui 5 GB de armazenamento e não expira nem pausa por inatividade — suficiente para contas, distritos editados e o resto dos dados do KARSK por muito tempo.

## Produção

Hospede o backend em qualquer serviço que rode Node (Render, Railway, Fly.io etc.), aponte para o seu banco Turso (passo acima) e defina `WEB_ORIGIN` para a origem real de onde o `karsk_ai.html` é servido. Coloque um proxy HTTPS na frente se o host não fizer isso automaticamente. Não publique o `.env`.

Com o banco no Turso, o servidor em si pode rodar tranquilamente no plano **grátis** de um host como o Render — ele "dorme" depois de alguns minutos sem uso e demora cerca de 1 minuto para acordar na próxima visita, mas nenhum dado é perdido nesse processo, porque os dados vivem no Turso, não no disco do servidor.

O primeiro administrador é criado no primeiro boot usando `KARSK_ADMIN_USERNAME` e `KARSK_ADMIN_PASSWORD`. Se a senha não estiver definida (ou for a padrão do exemplo), nenhuma conta administrativa é criada automaticamente.

## API

- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `GET/POST /api/users` (admin)
- `PUT/DELETE /api/users/:username` (admin)
- `GET/PUT/DELETE /api/storage/shared/:key` (admin para escrita)
- `GET/PUT/DELETE /api/storage/personal/:key` (isolado por usuário)
- `GET /api/live/snapshot`, `GET /api/live/stream` (eventos em tempo real via SSE)
- `PUT /api/live/presence`, `POST /api/live/events` (admin), `POST /api/live/transmissions` (admin), `POST /api/live/states` (admin)
