import os, secrets, time, bcrypt, json, hashlib
from flask import Flask, render_template, request, redirect, jsonify, url_for, session
from datetime import datetime, date, timedelta

STATUS_FILE = os.path.join(os.path.dirname(__file__), "status.json")

from settings import (
    PLANILHA_CAMINHO, PIN_HASH, CACHE_SEGUNDOS, DATA_FIXA, SECRET_KEY
)
from extractor import extract_all

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# ---------- CSRF ----------
def issue_csrf():
    tok = secrets.token_urlsafe(16)
    session["csrf"] = tok
    return tok

def check_csrf(tok: str) -> bool:
    return bool(tok) and tok == session.get("csrf")

# ---------- Sessão / Cookies ----------
app.secret_key = SECRET_KEY or secrets.token_hex(32)
SESSION_COOKIE_SECURE_ENV = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE_ENV,   # True somente em HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

# ---------- Rate-limit / brute force ----------
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "60 per hour"])

FAILED, MAX_ERR, BAN_MIN = {}, 5, 15  # 5 erros => 15 min bloqueio
def is_blocked(ip):
    rec = FAILED.get(ip)
    return bool(rec and rec[1] > time.time())

def register_fail(ip):
    n, _until = FAILED.get(ip, (0, 0))
    n += 1
    FAILED[ip] = (n, time.time() + BAN_MIN*60) if n >= MAX_ERR else (n, 0)

@app.before_request
def deny_if_banned():
    if request.endpoint == 'login' and is_blocked(get_remote_address()):
        return ("Muitas tentativas. Tente mais tarde.", 429)

# ---------- Headers de segurança ----------
@app.after_request
def security_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; frame-ancestors 'none'"
    )
    # Evita cache de páginas com dados pessoais
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    # Ativar HSTS só se tiver HTTPS de verdade:
    # resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp

# ---------- Cache do Excel ----------
_cache = {"ts": 0, "df": None}

def get_today():
    if DATA_FIXA:
        try:
            y, m, d = map(int, DATA_FIXA.split("-"))
            return date(y, m, d)
        except Exception:
            pass
    return date.today()

def load_df():
    now = time.time()
    if _cache["df"] is None or (now - _cache["ts"]) > CACHE_SEGUNDOS:
        _cache["df"] = extract_all(PLANILHA_CAMINHO)
        _cache["ts"] = now
    return _cache["df"]

def _load_status():
    if not os.path.exists(STATUS_FILE): return {}
    with open(STATUS_FILE, "r", encoding="utf-8") as f:
        try: return json.load(f)
        except: return {}

import tempfile, shutil

def _save_status(data):
    tmpdir = os.path.dirname(STATUS_FILE) or "."
    fd, tmp = tempfile.mkstemp(prefix="status_", suffix=".json", dir=tmpdir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        # troca atômica
        os.replace(tmp, STATUS_FILE)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except:
            pass


def item_id(it):
    def norm(x):
        s = str(x or "").strip().lower()
        s = " ".join(s.split())  # colapsa espaços
        return s
    base = "|".join([
        norm(it.get('Empresa')),
        norm(it.get('Documento')),
        norm(it.get('PegarCom')),
        norm(it.get('Solicitante')),
    ])
    return hashlib.sha1(base.encode("utf-8")).hexdigest()

# ---------- Render do dia ----------
def render_for_day(dia: date):
    df = load_df()
    dados = {'Manhã': [], 'Tarde': []}

    if df is not None and not df.empty:
        dsel = df[df['Data'] == dia]
        dados = {
            'Manhã': dsel[dsel['Período'] == 'Manhã'].to_dict('records'),
            'Tarde': dsel[dsel['Período'] == 'Tarde'].to_dict('records')
        }

    st = _load_status()
    d_iso = dia.strftime("%Y-%m-%d")
    today_status = st.get(d_iso, {})

    # marca estado base (feito / carregado)
    def mark(items):
        out = []
        for it in items:
            iid = item_id(it)
            it = dict(it)
            it["__id"] = iid
            it["__done"] = bool(today_status.get(iid, {}).get("done", False))
            it["__carregado"] = False
            it["__dias_atraso"] = 0
            out.append(it)
        return out

    dados['Manhã'] = mark(dados['Manhã'])
    dados['Tarde'] = mark(dados['Tarde'])

    # esconde os que foram reagendados PARA OUTRO DIA
    def _not_deferred_today(it):
        entry = st.get(d_iso, {}).get(it["__id"], {})
        to = entry.get("defer_to")
        return (not to) or (to == d_iso)

    dados['Manhã'] = [it for it in dados['Manhã'] if _not_deferred_today(it)]
    dados['Tarde'] = [it for it in dados['Tarde'] if _not_deferred_today(it)]

    # Conjuntos para evitar duplicatas ao injetar itens
    add_manha_ids = {it["__id"] for it in dados['Manhã']}
    add_tarde_ids = {it["__id"] for it in dados['Tarde']}

    N_DIAS = 7  # janela para atraso/reagendamento

    # ---------- Backlog (somente HOJE) ----------
    if dia == get_today() and df is not None and not df.empty:
        for k in range(1, N_DIAS + 1):
            dia_prev = dia - timedelta(days=k)
            p_iso = dia_prev.strftime("%Y-%m-%d")

            dprev = df[df['Data'] == dia_prev]
            if dprev.empty: 
                continue

            prev_m = dprev[dprev['Período'] == 'Manhã'].to_dict('records')
            prev_t = dprev[dprev['Período'] == 'Tarde'].to_dict('records')

            def carry_multi(src_list, dst_list, dst_ids):
                for src in src_list:
                    iid = item_id(src)

                    # já concluído em qualquer dia do intervalo? pula
                    done_algum_dia = any(
                        st.get((dia - timedelta(days=j)).strftime("%Y-%m-%d"), {}).get(iid, {}).get("done")
                        for j in range(0, k+1)
                    )
                    if done_algum_dia:
                        continue

                    # foi reagendado para OUTRO dia? pula
                    defer_to = st.get(p_iso, {}).get(iid, {}).get("defer_to")
                    if defer_to and defer_to != d_iso:
                        continue

                    if iid in dst_ids:
                        continue

                    it = dict(src)
                    it["__id"] = iid
                    it["__done"] = False
                    it["__carregado"] = True
                    it["__dias_atraso"] = k
                    dst_list.append(it)
                    dst_ids.add(iid)

            carry_multi(prev_m, dados['Manhã'], add_manha_ids)
            carry_multi(prev_t, dados['Tarde'], add_tarde_ids)

    # ---------- Reagendados explícitos (sempre traz pro dia-alvo) ----------
    for k in range(1, N_DIAS + 1):
        dia_prev = dia - timedelta(days=k)
        p_iso = dia_prev.strftime("%Y-%m-%d")
        prev_map = st.get(p_iso, {})

        for iid, entry in prev_map.items():
            if entry.get("defer_to") == d_iso and not entry.get("done", False):
                if iid in add_manha_ids or iid in add_tarde_ids:
                    continue
                src = entry.get("payload")
                if not src and df is not None and not df.empty:
                    dprev_all = df[df['Data'] == dia_prev].to_dict('records')
                    src = next((it for it in dprev_all if item_id(it) == iid), None)
                if not src:
                    continue
                it = dict(src)
                it["__id"] = iid
                it["__done"] = False
                it["__carregado"] = True
                it["__dias_atraso"] = k
                destino = 'Manhã' if str(src.get('Período')) == 'Manhã' else 'Tarde'
                dados[destino].append(it)
                if destino == 'Manhã': add_manha_ids.add(iid)
                else: add_tarde_ids.add(iid)

    # Counters finais
    counters = {
        'total': len(dados['Manhã']) + len(dados['Tarde']),
        'manha': len(dados['Manhã']),
        'tarde': len(dados['Tarde'])
    }

    return render_template(
        'rota.html',
        data_fmt=dia.strftime("%d/%m/%Y"),
        data_iso=d_iso,
        dados=dados,
        counters=counters
    )

# ---------- Rotas ----------
@app.route('/login', methods=['GET','POST'])
@limiter.limit("8 per minute")
def login():
    if request.method == 'POST':
        if not check_csrf(request.form.get("_csrf")):
            return render_template('login.html', error='Sessão expirada. Tente novamente.', csrf=issue_csrf())

        ip = get_remote_address()
        pin = (request.form.get('pin') or '').encode()
        ok = bool(PIN_HASH) and bcrypt.checkpw(pin, PIN_HASH.encode())

        if ok:
            session.clear()
            session['auth'] = True
            session.permanent = True
            FAILED.pop(ip, None)
            return redirect(url_for('rota_hoje'))
        else:
            register_fail(ip)
            return render_template('login.html', error='PIN inválido.', csrf=issue_csrf())

    return render_template('login.html', csrf=issue_csrf())

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

def ensure_auth():
    return session.get('auth', False)

@app.route('/')
def home():
    return redirect(url_for('rota_hoje'))

@app.route('/moto/hoje')
def rota_hoje():
    if not ensure_auth(): return redirect(url_for('login'))
    return render_for_day(get_today())

@app.route('/moto/amanha')
def rota_amanha():
    if not ensure_auth(): return redirect(url_for('login'))
    return render_for_day(get_today() + timedelta(days=1))

@app.route('/moto/ontem')
def rota_ontem():
    if not ensure_auth(): return redirect(url_for('login'))
    return render_for_day(get_today() - timedelta(days=1))

@app.route('/moto/<yyyymmdd>')
def rota_por_data(yyyymmdd):
    if not ensure_auth(): return redirect(url_for('login'))
    try:
        d = datetime.strptime(yyyymmdd, '%Y-%m-%d').date()
    except Exception:
        return redirect(url_for('rota_hoje'))
    return render_for_day(d)

@app.post("/moto/check")
def moto_check():
    if not ensure_auth(): return jsonify({"ok": False, "err": "unauth"}), 401
    data = request.get_json() or {}
    d_iso = data.get("date")      # "YYYY-MM-DD"
    iid   = data.get("id")        # item_id()
    done  = bool(data.get("done"))

    if not d_iso or not iid:
        return jsonify({"ok": False, "err": "invalid"}), 400

    st = _load_status()
    st.setdefault(d_iso, {})
    st[d_iso][iid] = {"done": done}
    _save_status(st)
    return jsonify({"ok": True})

@app.post("/moto/reschedule")
def moto_reschedule():
    if not ensure_auth():
        return jsonify({"ok": False, "err": "unauth"}), 401

    data = request.get_json() or {}
    from_iso = data.get("from")    # ex: "2025-09-11"
    to_iso   = data.get("to")      # ex: "2025-09-12"
    iid      = data.get("id")      # item_id()

    if not (from_iso and to_iso and iid):
        return jsonify({"ok": False, "err": "invalid"}), 400

    try:
        from_date = datetime.strptime(from_iso, "%Y-%m-%d").date()
        _to_date  = datetime.strptime(to_iso,   "%Y-%m-%d").date()
    except Exception:
        return jsonify({"ok": False, "err": "bad_date"}), 400

    # Snapshot do item (pra aparecer no dia reagendado mesmo que não exista no Excel daquele dia)
    payload = None
    df = load_df()
    if df is not None and not df.empty:
        dsel = df[df["Data"] == from_date].to_dict("records")
        for it in dsel:
            if item_id(it) == iid:
                payload = it
                break

    st = _load_status()
    st.setdefault(from_iso, {})
    entry = st[from_iso].get(iid, {})
    entry["defer_to"] = to_iso
    if payload:
        entry["payload"] = payload  # guarda Empresa/Documento/Período/etc.
    st[from_iso][iid] = entry
    _save_status(st)
    return jsonify({"ok": True})

if __name__ == '__main__':
    # Produção: prefira waitress -> python -m waitress --listen=0.0.0.0:5055 app:app
    app.run(host='0.0.0.0', port=5055)
