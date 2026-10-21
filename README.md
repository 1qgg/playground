# Quest Game Playground

Painel independente para testar a 1Q API, iniciar jogos e registrar callbacks HTTP.

## Deploy no Coolify

1. Conecte o repositório `1qgg/playground`.
2. Selecione build pack **Dockerfile**.
3. Configure a porta interna `3000` e associe um domínio HTTPS.
4. Opcionalmente configure `CALLBACK_TOKEN` e `MAX_CALLBACK_EVENTS`.
5. Abra o domínio e preencha URL base da API, Operator Key e Operator Secret.

## Recursos

- Interface web para consultar `GET /api/v1/games`.
- Tentativa de lançamento por `POST /api/v1/launches`.
- Assinatura HMAC-SHA256 gerada no backend para não expor o segredo no JavaScript.
- Receptor financeiro de demonstração em `POST /callbacks/1q`, com validação HMAC e histórico na interface.
- Endpoint de saúde `/health`.

## Atenção

- O receptor `/callbacks/1q` valida a assinatura HMAC usando `CALLBACK_SECRET` e implementa uma carteira demonstrativa em memória para testes. Não use para dinheiro real; carteira, idempotência e histórico não são persistentes.
- A 1Q envia `X-1Q-Key` automaticamente. Não configure `CALLBACK_KEY`; a assinatura é validada com o segredo de callback, não com o Operator Secret da API.
- O contrato oficial do callback está em [`docs/OPERATOR-INTEGRATION.md`](https://github.com/1qgg/1q/blob/release/oneq-production-commercial-ac5aca9/docs/OPERATOR-INTEGRATION.md), seção Financial callback configuration.
- Os nomes dos parâmetros de catálogo e lançamento podem precisar de ajuste ao contrato atual da API. Examine a resposta JSON no painel para depurar.
- Mantenha o playground privado ou atrás de autenticação no proxy/SSO do Coolify. O backend assina chamadas usando as credenciais fornecidas pelo browser, então não exponha o serviço publicamente sem proteção.
- O projeto não altera nem implanta a API principal.
