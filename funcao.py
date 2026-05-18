import jwt, uuid, secrets, os
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import request, jsonify, current_app
from flask_bcrypt import check_password_hash
from flask_mail import Message


# ── Senha forte ───────────────────────────────────────────────────────────────
def verificar_senha(senha):
    mai = min = num = esp = False
    for c in senha:
        if c.isupper(): mai = True
        elif c.islower(): min = True
        elif c.isdigit(): num = True
        else: esp = True
    return mai and min and num and esp


# ── JWT ───────────────────────────────────────────────────────────────────────
def gerar_token(id_usuario, is_admin=False):
    jti = str(uuid.uuid4())
    payload = {
        'sub': id_usuario,
        'admin': is_admin,
        'jti': jti,
        'exp': datetime.now(timezone.utc) + timedelta(minutes=current_app.config['JWT_MINUTOS'])
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256'), jti


def token_requerido(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        from main import con
        header = request.headers.get('Authorization', '')
        if not header.startswith('Bearer '):
            return jsonify({'error': 'Token não fornecido!'}), 401
        token = header.split(' ')[1]
        try:
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido!'}), 401

        cur = con.cursor()
        cur.execute("SELECT 1 FROM TOKENS_BLACKLIST WHERE JTI = ?", (payload['jti'],))
        invalido = cur.fetchone()
        cur.close()
        if invalido:
            return jsonify({'error': 'Sessão encerrada. Faça login novamente!'}), 401

        request.uid   = payload['sub']
        request.admin = payload.get('admin', False)
        return f(*args, **kwargs)
    return decorated


def admin_requerido(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not getattr(request, 'admin', False):
            return jsonify({'error': 'Acesso restrito ao administrador!'}), 403
        return f(*args, **kwargs)
    return decorated


# ── Foto ──────────────────────────────────────────────────────────────────────
def salvar_foto(arquivo):
    if not arquivo:
        return None
    ext = arquivo.filename.rsplit('.', 1)[-1].lower()
    if ext not in current_app.config['EXTENSOES_PERMITIDAS']:
        return None
    nome = f"{uuid.uuid4().hex}.{ext}"
    arquivo.save(os.path.join(current_app.config['UPLOAD_FOLDER'], nome))
    return nome


# ── Histórico de senhas ───────────────────────────────────────────────────────
def senha_ja_usada(con, id_usuario, nova_senha):
    cur = con.cursor()
    cur.execute("""
        SELECT SENHA_HASH FROM HISTORICO_SENHAS
        WHERE ID_USUARIO = ? ORDER BY DT DESC ROWS 3
    """, (id_usuario,))
    rows = cur.fetchall()
    cur.close()
    return any(check_password_hash(r[0], nova_senha) for r in rows)


def salvar_historico(con, id_usuario, senha_hash):
    cur = con.cursor()
    cur.execute("INSERT INTO HISTORICO_SENHAS (ID_USUARIO, SENHA_HASH) VALUES (?, ?)", (id_usuario, senha_hash))
    con.commit()
    cur.close()


# ── E-mail ────────────────────────────────────────────────────────────────────
def enviar_confirmacao(mail, email, nome, token):
    link = f"http://localhost:5000/confirmar_email/{token}"
    mail.send(Message(
        subject='Confirme seu e-mail',
        recipients=[email],
        html=f"<h3>Olá {nome}!</h3><p>Clique para confirmar: <a href='{link}'>{link}</a></p><p>Expira em 24h.</p>"
    ))


def enviar_recuperacao(mail, email, nome, token):
    link = f"http://localhost:5000/redefinir_senha/{token}"
    mail.send(Message(
        subject='Recuperação de senha',
        recipients=[email],
        html=f"<h3>Olá {nome}!</h3><p>Clique para redefinir: <a href='{link}'>{link}</a></p><p>Expira em 1h.</p>"
    ))