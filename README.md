# Game Playground

Painel público para testar a 1Q API, iniciar jogos e visualizar callbacks financeiros de demonstração.

## Deploy no Coolify

1. Conecte o repositório `1qgg/playground`.
2. Selecione build pack **Dockerfile**.
3. Configure a porta interna `3000` e associe um domínio HTTPS.
4. Configure `API_BASE_URL` se a API não estiver em `https://api.1q.gg`.
5. Opcionalmente configure `MAX_CALLBACK_EVENTS` e `CALLBACK_DEFAULT_BALANCE`.
6. Faça deploy e abra o domínio.

## Recursos

- Operator Key, Operator Secret, Callback Secret e padrões do jogador salvos no navegador via localStorage.
- URL base da API definida no servidor, não editável pela interface.
- Catálogo em cartões, com resposta JSON original recolhida por padrão.
- Criação de lançamento, consulta de estado e tentativa de abrir o jogo em iframe; opção de nova aba se o provedor bloquear incorporação.
- Receptor financeiro de demonstração em `POST /callbacks/1q`, com validação HMAC e configurações separadas por `X-1Q-Key`.
- Histórico de callbacks formatado e acesso recolhido ao payload/resposta originais.

## Segurança e limitações

- O Callback Secret é salvo no navegador para edição, e também no backend para que o servidor possa validar callbacks recebidos enquanto o navegador estiver fechado. A configuração do backend é separada por Operator Key.
- A carteira, idempotência, nonces e histórico são mantidos em memória; reiniciar o processo perde esses dados. Não use para dinheiro real.
- O backend restringe o proxy a `API_BASE_URL` e caminhos `/api/v1/`; configure a URL confiável antes de expor o serviço.
- Este é um playground de demonstração pública, não um painel de administração autenticado. O operador deve usar credenciais de teste com privilégios mínimos. Para uso amplo em produção, adicione limites de requisição, proteção contra abuso e monitoramento.
- O contrato oficial está em [OPERATOR-INTEGRATION.md](https://github.com/1qgg/1q/blob/release/oneq-production-commercial-ac5aca9/docs/OPERATOR-INTEGRATION.md), seção de callback financeiro.
- Não há alteração nem implantação da API principal neste repositório.
