<p align="center">
  <img src="docs/assets/mimo.png" alt="Mascote do Mimo" width="140" height="170">
  <img src="docs/assets/mimo-wordmark.svg" alt="mimo" width="190" height="170">
</p>
<p align="center"><strong>Agente local para Android</strong></p>
<p align="center">Um companheiro para explorar sites, acompanhar verificações e aprender com evidências no Android.</p>
<p align="center"><a href="LICENSE">MIT</a> · Android 8+ · Python · Java · JavaScript</p>

Mimo combina um agente local com uma interface para celular: converse, informe o endereço de um site autorizado e acompanhe as páginas visitadas, ferramentas utilizadas e observações encontradas. O mascote animado explica a atividade em linguagem simples e mostra, em balões de fala, o que foi observado ou guardado na memória.

## O que ele faz

- **Conversa e links:** envie uma mensagem e, quando necessário, uma URL para análise.
- **Mapeamento de sites:** percorre links descobertos na mesma origem, incluindo sitemaps e rotas encontradas com JavaScript, com fila persistente e limites configuráveis.
- **Verificações de segurança:** observa cabeçalhos, HTTPS, cookies, conteúdo misto, formulários e mensagens de erro. Separa observações reproduzidas, limitações e itens não testados.
- **Atividade em tempo real:** apresenta ações, ferramentas e resultados públicos de cada etapa.
- **Documentação:** organiza cobertura, evidências, recomendações e exportação do relatório.
- **Memória por site:** compara execuções concluídas, identifica novas rotas e reconhece observações recorrentes. Os balões do mascote acompanham esses fatos.

O aprendizado é uma memória local de observações, sem retreinamento dos pesos do modelo. A interface apresenta resumos das ações e evidências; não expõe raciocínio interno privado do modelo.

## Ver a interface no computador

Requisitos: Node.js 22+, npm e Python 3.12+.

```bash
npm ci --prefix frontend
npm run build --prefix frontend
python3 -m http.server 4173 --bind 127.0.0.1 --directory frontend/dist
```

Abra **http://127.0.0.1:4173**. No navegador comum, a interface usa uma demonstração identificada como tal. A comunicação com o agente real depende da ponte nativa do aplicativo Android.

## Executar no Android

O aplicativo usa WebView e serviços locais no Termux. O modelo GGUF, o runtime de inferência, o SDK Android e as credenciais são preparados separadamente.

Consulte o **[guia de instalação e compilação](docs/INSTALACAO.md)** para gerar uma credencial própria, preparar o backend e compilar o APK.

## Estrutura

```text
backend/          Agente Python, navegação, verificações, memória e testes
frontend/src/     Interface, mascote, conversa e documentação
frontend/dist/    Interface compilada para prévia e WebView
frontend/android/ Aplicativo Java e script de compilação
scripts/          Preparação local e instalação da metodologia
tests/           Verificações da interface
docs/            Guia de instalação e logo
```

## Cobertura e limites

A análise percorre os endereços descobertos dentro do escopo e dos limites configurados. Páginas sem links, áreas autenticadas, bloqueios do servidor, falhas de JavaScript e limites de tempo podem deixar cobertura incompleta. O relatório diferencia páginas analisadas, pendentes, bloqueadas e falhas.

Ausência de alertas não comprova que um site está seguro. As verificações de configuração não substituem uma avaliação completa de autorização, regras de negócio e vulnerabilidades exploráveis. Use somente em sistemas próprios ou com autorização. O mapeamento não envia formulários automaticamente.

## Privacidade

Este repositório contém código, recursos visuais e testes com dados fictícios. Credenciais, conversas, memórias, relatórios reais, capturas do aparelho, modelos, chaves de assinatura e APKs da instalação pessoal ficam fora da publicação.

Ao executar o agente, os dados gerados ficam na instalação local. Relatórios e evidências podem conter informações do site analisado; revise-os antes de compartilhar. O script de preparação gera um token exclusivo, e o `.gitignore` exclui os principais arquivos privados. O APK compilado incorpora esse token e deve ser tratado como artefato privado.

## Verificações de desenvolvimento

```bash
npm run check --prefix frontend
npm run build --prefix frontend
node tests/test-documentation.mjs
node tests/test-learning-ui.mjs
python3 scripts/install_methodology.py
python3 -m pip install -r backend/requirements.txt
cd backend
python3 -m unittest test_security test_autonomy test_public_api test_learning \
  test_qa.Tests.test_02_public_scope_and_dns \
  test_qa.Tests.test_03_budget_resume \
  test_qa.Tests.test_05_session_redaction \
  test_qa.Tests.test_08_cancel_keeps_pending_queue
```

A integração contínua executa essa seleção portátil. Outros testes no diretório `backend` dependem do aparelho, do navegador ou de ferramentas preparadas no ambiente local.

## Autoria

Criado por [Invasor_ZIM (@glaudsonvilela)](https://github.com/glaudsonvilela).

## Licença e dependências

O código do projeto é distribuído sob a **[licença MIT](LICENSE)**. A licença não altera os termos das dependências, ferramentas e modelos externos.

A metodologia utiliza [web-pentest-sample, da Strobes Security](https://github.com/strobes-security/web-pentest-sample), fixado no commit `101c3fd96e2ffda27886973dea7089b93bc79756`. O instalador verifica a integridade do arquivo baixado e preserva a licença MIT upstream. O aplicativo também utiliza jsoup e esbuild, com suas respectivas licenças.
