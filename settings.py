# settings.py
import os
import secrets

def env_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return str(val).strip().lower() in ("1", "true", "yes", "y", "on")

def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default

# 🔐 Chave de sessão/cookies
# Em DEV, se não tiver SECRET_KEY, gera uma temporária só pra não quebrar.
# EM PRODUÇÃO: defina SECRET_KEY por variável de ambiente!
SECRET_KEY = os.getenv("SECRET_KEY") or ("dev-" + secrets.token_hex(16))

# 🔢 PIN (bcrypt hash)
# Mantém esse hash como fallback (é do PIN "4321"). Em produção, prefira via env.
PIN_HASH = os.getenv("PIN_HASH", "$2b$12$IzXluTS6gniyOTrbYy5gZep3BGPvEjBXeKMjrtO.Ujz9R.sAf6LjW")

# 📄 Caminho da planilha: use env pra trocar por mês sem editar código
PLANILHA_CAMINHO = os.getenv(
    "PLANILHA_CAMINHO",
    r"\\pastas\dfs\Controles\SOLICITACAO MOTOBOY\SETEMBRO 2025 - SOLICITACAO MOTOBOY.xlsx"
)

# ⏱️ Cache de leitura da planilha (segundos)
CACHE_SEGUNDOS = env_int("CACHE_SEGUNDOS", 45)

# 🗓️ (opcional) Fixar data (formato YYYY-MM-DD). Vazio = hoje.
DATA_FIXA = os.getenv("DATA_FIXA", "").strip()

# 🍪 Cookie “secure”: tem que ser FALSE em HTTP local. TRUE só com HTTPS/Túnel.
SESSION_COOKIE_SECURE_ENV = env_bool("SESSION_COOKIE_SECURE", False)
