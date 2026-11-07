# Instalação e compilação

O repositório publica os fontes. A instalação completa requer preparar o runtime no Android; abrir a prévia web não instala o agente nem o modelo.

## 1. Interface

Na raiz do repositório, com Node.js 22+:

```bash
npm ci --prefix frontend
npm run check --prefix frontend
npm run build --prefix frontend
```

## 2. Configuração privada

Com Python 3.12+:

```bash
python3 scripts/init_local.py
python3 scripts/install_methodology.py
python3 -m pip install -r backend/requirements.txt
```

O primeiro comando cria `backend/token` com permissões restritas e copia `qa-settings.example.json` para `qa-settings.json`. Uma credencial existente é preservada. Os dois arquivos gerados são ignorados pelo Git. O segundo comando instala a metodologia pública verificada por SHA256 em `backend/skills/web-pentest`, também ignorada pelo Git.

Revise `qa-settings.json` para ajustar orçamento, limites e verificações. O exemplo usa o navegador Android WebView. O modo de laboratório deve ser configurado apenas para ambientes de teste próprios.

## 3. Backend no Termux

Prepare uma instalação do Termux com Python, suporte a `cryptography`, `flock` e os comandos de wake lock. A instalação de dependências nativas pode exigir o compilador e as bibliotecas de desenvolvimento do Termux.

Copie o conteúdo de `backend/`, incluindo a configuração privada e a metodologia instalada, para `~/poco-agent` no Termux. Essa pasta é o caminho esperado pelo aplicativo.

Prepare separadamente:

- `models/Huihui-POCO-4B-Q4_0.gguf`: arquivo de modelo compatível com o nome esperado pelo agente; verifique seus termos antes de obtê-lo ou redistribuí-lo.
- `runtime/llama-server`: executável de inferência compatível com Android/ARM64, acompanhado das bibliotecas necessárias no mesmo diretório.
- Ferramentas opcionais solicitadas pelo agente: consulte `phone-tools-lock.json`. A compatibilidade dos binários depende do ambiente Android.

No Termux, permita comandos externos em `~/.termux/termux.properties` com `allow-external-apps=true`. Conceda ao aplicativo a permissão de executar comandos no Termux, quando solicitada. Marque `~/poco-agent/start.sh` como executável. Para iniciar manualmente:

```bash
cd ~/poco-agent
chmod +x start.sh
./start.sh
```

Os serviços usam loopback: agente na porta `8766`, inferência na `8080` e ferramenta nativa na `8767`. A ferramenta nativa e o processamento JavaScript dependem do aplicativo Android aberto. Esses endereços locais não são links públicos compartilháveis.

## 4. Compilar o APK

No computador, prepare JDK 17+, Android SDK Platform 35, Build Tools 35.0.0 e o JAR jsoup 1.24.1 obtido da distribuição oficial. A compilação utiliza o mesmo `backend/token` que será copiado ao Termux.

```bash
export ANDROID_SDK_ROOT=/caminho/para/android-sdk
export JSOUP_JAR=/caminho/para/jsoup-1.24.1.jar
python3 frontend/android/build.py
```

O resultado sem assinatura fica em `build/android/POCO-Mimo-unsigned.apk`. Para instalar no Android, assine-o com sua própria chave. O script também pode assinar quando as variáveis `MIMO_KEYSTORE`, `MIMO_KEY_ALIAS` e `MIMO_KEYSTORE_PASSWORD` estiverem definidas. Forneça a senha por uma forma privada de entrada; evite salvá-la no histórico do shell.

Para SDKs com outra organização, configure `MIMO_BUILD_TOOLS` e `MIMO_ANDROID_JAR`. `MIMO_TOKEN_FILE` permite selecionar outro arquivo de credencial local. O script gera `WebConfig.java` somente no diretório ignorado de compilação.

**Não publique o APK gerado:** ele incorpora a credencial da instalação. Também não publique a chave de assinatura. Uma chave diferente não consegue atualizar um aplicativo já instalado e assinado por outra chave.

## 5. Conferir no aparelho

Depois de instalar o APK assinado e iniciar o Termux, abra o Mimo, confira a conexão local e execute uma análise em um site de teste autorizado. Verifique a cobertura, os balões de observação e a exportação na aba Documentação. Uma segunda análise concluída da mesma origem deve recuperar a memória anterior.

Os testes automatizados portáteis não substituem essa checagem de integração no aparelho. Para a prévia no computador, siga os comandos do README; os eventos apresentados ali são demonstrativos.
