import smtplib
from email.mime.text import MIMEText

import jwt, uuid, secrets, os
# from datetime import datetime, timezone, timedelta
import datetime
from functools import wraps
from flask import request, jsonify, current_app
from flask_bcrypt import check_password_hash
from flask_mail import Message

from main import app


# ── Senha forte ───────────────────────────────────────────────────────────────
def verificar_senha(senha):
    mai = min = num = esp = False
    for c in senha:
        if c.isupper(): mai = True
        elif c.islower(): min = True
        elif c.isdigit(): num = True
        else: esp = True
    return mai and min and num and esp
    #retorna se é verdadeiro ou falso

def gerar_token(id_usuario):
    payload = {'id_usuario': id_usuario,
               'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1)
               }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

    return token

    # # ── JWT ───────────────────────────────────────────────────────────────────────
# def gerar_token(id_usuario, is_admin=False, pyjwt=None):
#
#     expira = datetime.now(timezone.utc) + timedelta(
#         minutes=app.config['JWT_MINUTOS']
#     )
#
#     payload = {
#         'id_usuario': id_usuario,
#         'is_admin': is_admin,
#         'exp': expira
#     }
#
#     token = pyjwt.encode(
#         payload,
#         app.config['SECRET_KEY'],
#         algorithm='HS256'
#     )
#
#     return token, expira

    return token, expira
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

def enviando_email(destinatario, assunto, mensagem):
    user = 'alicia.buzeli1105@gmail.com'
    senha = 'aofb rqjv bucc hhoa'

    msg = MIMEText(mensagem)
    msg['From'] = user
    msg['To'] = destinatario
    msg['Subject'] = assunto

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(user, senha)
    server.send_message(msg)
    server.quit()

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


def enviar_boas_vindas_vendedor(mail, email, nome, usuario, senha_temp, token):
    link = f"http://localhost:5000/redefinir_senha/{token}"
    mail.send(Message(
        subject='Bem-vindo(a)! Seus dados de acesso',
        recipients=[email],
        html=f"""
        <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;border:1px solid #e0e0e0;border-radius:8px;padding:32px">
            <h2 style="color:#2c3e50">Olá, {nome}! 👋</h2>
            <p>Sua conta foi criada pelo administrador. Aqui estão seus dados de acesso:</p>
            <table style="background:#f4f6f8;border-radius:6px;padding:16px;width:100%;margin:16px 0">
                <tr><td style="padding:4px 8px;color:#555">Usuário:</td><td style="padding:4px 8px;font-weight:bold">{usuario}</td></tr>
                <tr><td style="padding:4px 8px;color:#555">Senha temporária:</td><td style="padding:4px 8px;font-weight:bold;color:#e74c3c">{senha_temp}</td></tr>
            </table>
            <p>⚠️ <strong>Por segurança, você deve redefinir sua senha no primeiro acesso.</strong></p>
            <p style="text-align:center;margin:24px 0">
                <a href="{link}" style="background:#2c3e50;color:#fff;padding:12px 28px;border-radius:6px;text-decoration:none;font-size:15px">
                    Redefinir minha senha
                </a>
            </p>
            <p style="color:#999;font-size:12px">O link expira em 24 horas. Se não foi você, ignore este e-mail.</p>
        </div>
        """
    ))