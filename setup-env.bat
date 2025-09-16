@echo off
REM === Configuração de ambiente do Motoboy App ===

REM 🔐 Chave secreta (gera cookies/sessões). Troque se quiser.
setx SECRET_KEY "n4g9-Zys5TY8QuHlXhpYRLDh6b5dW_dIfKuK_kg2x4DGs1BSFkradrzl22uOqUyB"

REM 🔢 Hash do PIN (esse é do 4321)
setx PIN_HASH "$2b$12$IzXluTS6gniyOTrbYy5gZep3BGPvEjBXeKMjrtO.Ujz9R.sAf6LjW"

REM 📄 Planilha (ajusta todo mês)
setx PLANILHA_CAMINHO "\\pastas\dfs\Controles\SOLICITACAO MOTOBOY\SETEMBRO 2025 - SOLICITACAO MOTOBOY.xlsx"

REM ⏱️ Cache em segundos
setx CACHE_SEGUNDOS "45"

REM 🗓️ Data fixa (deixa vazio pra usar hoje)
setx DATA_FIXA ""

REM 🍪 Cookie “secure”: TEM que ser false em HTTP local
setx SESSION_COOKIE_SECURE "false"

echo Ambiente configurado! Feche este terminal e abra um novo antes de rodar.
pause
