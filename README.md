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
- Receptor de diagnóstico em `/callbacks` e `/callbacks/:provider`.
- Histórico dos callbacks disponível pela interface.
- Endpoint de saúde `/health`.

## Atenção

- O receptor de callbacks é **genérico para diagnóstico**: responde HTTP 200 e guarda método, cabeçalhos filtrados e payload em memória. Não implementa lógica de carteira, apostas, ganhos, estornos, validação de assinatura específica do provedor ou idempotência.
- Os eventos ficam em memória e são apagados ao reiniciar o container.
- O formato canônico HMAC e os nomes exatos dos cabeçalhos devem ser conferidos com o middleware/contrato atual da 1Q API antes de considerar os testes conclusivos.
- Os nomes dos parâmetros de catálogo e lançamento podem precisar de ajuste ao contrato atual da API. Examine a resposta JSON no painel para depurar.
- Mantenha o playground privado ou atrás de autenticação no proxy/SSO do Coolify. O backend assina chamadas usando as credenciais fornecidas pelo browser, então não exponha o serviço publicamente sem proteção.
- Se `CALLBACK_TOKEN` estiver configurado, os emissores devem enviar o cabeçalho `X-Callback-Token` com o mesmo valor.
- O projeto não altera nem implanta a API principal.
