import jwt as pyjwt
import requests
import secrets
from datetime import datetime, timezone, timedelta
from flask import request, jsonify, send_from_directory
from flask_bcrypt import generate_password_hash, check_password_hash

from main import app, con, mail
from funcao import (
    verificar_senha, gerar_token, token_requerido, admin_requerido,
    salvar_foto, senha_ja_usada, salvar_historico,
    enviar_confirmacao, enviar_recuperacao, enviar_boas_vindas_vendedor
)

# ══════════════════════════════════════════════════════════════
#  USUÁRIOS
# ══════════════════════════════════════════════════════════════

@app.route('/criar_usuarios', methods=['POST'])
def criar_usuarios():
    nome    = request.form.get('nome', '').strip()
    email   = request.form.get('email', '').strip()
    usuario = request.form.get('usuario', '').strip()
    senha   = request.form.get('senha', '').strip()

    if not nome:
        return jsonify({'error': 'Nome é obrigatório!'}), 400
    if not email:
        return jsonify({'error': 'E-mail é obrigatório!'}), 400
    if not verificar_senha(senha):
        return jsonify({'error': 'Senha precisa ter maiúscula, minúscula, número e caractere especial!'}), 400

    try:
        cur = con.cursor()

        cur.execute("SELECT 1 FROM USUARIOS WHERE USUARIO = ?", (usuario,))
        if cur.fetchone():
            cur.close()
            return jsonify({'error': 'Usuário já cadastrado!'}), 400

        cur.execute("SELECT 1 FROM USUARIOS WHERE EMAIL = ?", (email,))
        if cur.fetchone():
            cur.close()
            return jsonify({'error': 'E-mail já cadastrado!'}), 400

        foto       = salvar_foto(request.files.get('foto'))
        senha_hash = generate_password_hash(senha).decode('utf-8')
        token_conf = secrets.token_urlsafe(48)

        cur.execute("""
            INSERT INTO USUARIOS (NOME, EMAIL, USUARIO, SENHA, FOTO, TOKEN_EMAIL)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (nome, email, usuario, senha_hash, foto, token_conf))
        con.commit()

        cur.execute("SELECT MAX(ID_USUARIO) FROM USUARIOS")
        id_novo = cur.fetchone()[0]
        cur.close()

        salvar_historico(con, id_novo, senha_hash)

        try:
            enviar_confirmacao(mail, email, nome, token_conf)
        except Exception as e:
            app.logger.warning(f"E-mail não enviado: {e}")

        return jsonify({'mensagem': 'Usuário criado! Confirme seu e-mail para ativar a conta.'}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/confirmar_email/<token>', methods=['GET'])
def confirmar_email(token):
    cur = con.cursor()
    cur.execute("SELECT ID_USUARIO FROM USUARIOS WHERE TOKEN_EMAIL = ?", (token,))
    row = cur.fetchone()
    if not row:
        cur.close()
        return jsonify({'error': 'Token inválido!'}), 400
    cur.execute("UPDATE USUARIOS SET EMAIL_CONFIRMADO=1, TOKEN_EMAIL=NULL WHERE ID_USUARIO=?", (row[0],))
    con.commit()
    cur.close()
    return jsonify({'mensagem': 'E-mail confirmado! Você já pode fazer login.'}), 200


@app.route('/login', methods=['POST'])
def login():
    data    = request.get_json()
    usuario = data.get('usuario', '').strip()
    senha   = data.get('senha', '').strip()

    try:
        cur = con.cursor()
        cur.execute("""
            SELECT ID_USUARIO, SENHA, EMAIL_CONFIRMADO, BLOQUEADO, TENTATIVAS, IS_ADMIN, PRIMEIRO_ACESSO
            FROM USUARIOS WHERE USUARIO = ?
        """, (usuario,))
        row = cur.fetchone()

        if not row:
            cur.close()
            return jsonify({'error': 'Usuário não encontrado!'}), 404

        id_u, senha_hash, confirmado, bloqueado, tentativas, is_admin, primeiro_acesso = row

        if bloqueado:
            cur.close()
            return jsonify({'error': 'Conta bloqueada! Fale com o administrador.'}), 403

        if not confirmado:
            cur.close()
            return jsonify({'error': 'Confirme seu e-mail antes de entrar!'}), 403

        if not check_password_hash(senha_hash, senha):
            novas = tentativas + 1
            if novas >= 3:
                cur.execute("UPDATE USUARIOS SET TENTATIVAS=?, BLOQUEADO=1 WHERE ID_USUARIO=?", (novas, id_u))
                con.commit()
                cur.close()
                return jsonify({'error': 'Senha incorreta! Conta bloqueada.'}), 403
            cur.execute("UPDATE USUARIOS SET TENTATIVAS=? WHERE ID_USUARIO=?", (novas, id_u))
            con.commit()
            cur.close()
            return jsonify({'error': f'Senha incorreta! Tentativas restantes: {3 - novas}.'}), 401

        cur.execute("UPDATE USUARIOS SET TENTATIVAS=0 WHERE ID_USUARIO=?", (id_u,))
        con.commit()
        cur.close()

        # Vendedor no primeiro acesso deve redefinir a senha antes de continuar
        if primeiro_acesso:
            return jsonify({
                'error': 'Primeiro acesso detectado. Redefina sua senha para continuar.',
                'primeiro_acesso': True
            }), 403

        token, _ = gerar_token(id_u, bool(is_admin))
        return jsonify({'mensagem': 'Login realizado!', 'token': token}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/logout', methods=['POST'])
@token_requerido
def logout():
    header  = request.headers.get('Authorization', '').split(' ')[1]
    payload = pyjwt.decode(header, app.config['SECRET_KEY'], algorithms=['HS256'])
    exp     = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)

    cur = con.cursor()
    cur.execute("INSERT INTO TOKENS_BLACKLIST (JTI, EXPIRA_EM) VALUES (?, ?)", (payload['jti'], exp))
    con.commit()
    cur.close()
    return jsonify({'mensagem': 'Logout realizado com sucesso!'}), 200


@app.route('/usuarios', methods=['GET'])
@token_requerido
def listar_usuarios():
    cur = con.cursor()
    cur.execute("""
        SELECT ID_USUARIO, NOME, EMAIL, USUARIO, FOTO, EMAIL_CONFIRMADO, BLOQUEADO, IS_ADMIN
        FROM USUARIOS ORDER BY NOME
    """)
    rows = cur.fetchall()
    cur.close()
    return jsonify({'usuarios': [
        {'id': r[0], 'nome': r[1], 'email': r[2], 'usuario': r[3], 'foto': r[4],
         'confirmado': bool(r[5]), 'bloqueado': bool(r[6]), 'admin': bool(r[7])}
        for r in rows
    ]}), 200


@app.route('/buscar_usuarios', methods=['GET'])
@token_requerido
def buscar_usuarios():
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify({'error': 'Informe o parâmetro ?q='}), 400
    cur = con.cursor()
    cur.execute("""
        SELECT ID_USUARIO, NOME, EMAIL, USUARIO, FOTO
        FROM USUARIOS
        WHERE LOWER(NOME) CONTAINING LOWER(?)
           OR LOWER(USUARIO) CONTAINING LOWER(?)
           OR LOWER(EMAIL) CONTAINING LOWER(?)
        ORDER BY NOME
    """, (q, q, q))
    rows = cur.fetchall()
    cur.close()
    return jsonify({'usuarios': [
        {'id': r[0], 'nome': r[1], 'email': r[2], 'usuario': r[3], 'foto': r[4]}
        for r in rows
    ]}), 200


@app.route('/editar_usuarios/<int:id>', methods=['PUT'])
@token_requerido
def editar_usuarios(id):
    cur = con.cursor()
    cur.execute("SELECT NOME, USUARIO, EMAIL, FOTO FROM USUARIOS WHERE ID_USUARIO=?", (id,))
    row = cur.fetchone()
    if not row:
        cur.close()
        return jsonify({'error': 'Usuário não encontrado!'}), 404

    nome    = request.form.get('nome',    row[0]).strip()
    usuario = request.form.get('usuario', row[1]).strip()
    email   = request.form.get('email',   row[2]).strip()
    senha   = request.form.get('senha',   '').strip()

    if not nome:
        cur.close()
        return jsonify({'error': 'Nome é obrigatório!'}), 400

    cur.execute("SELECT 1 FROM USUARIOS WHERE EMAIL=? AND ID_USUARIO<>?", (email, id))
    if cur.fetchone():
        cur.close()
        return jsonify({'error': 'E-mail já está em uso!'}), 400

    cur.execute("SELECT 1 FROM USUARIOS WHERE USUARIO=? AND ID_USUARIO<>?", (usuario, id))
    if cur.fetchone():
        cur.close()
        return jsonify({'error': 'Nome de usuário já em uso!'}), 400

    foto = salvar_foto(request.files.get('foto')) or row[3]

    if senha:
        if not verificar_senha(senha):
            cur.close()
            return jsonify({'error': 'Senha precisa ter maiúscula, minúscula, número e caractere especial!'}), 400
        if senha_ja_usada(con, id, senha):
            cur.close()
            return jsonify({'error': 'Não é permitido reutilizar as últimas 3 senhas!'}), 400
        senha_hash = generate_password_hash(senha).decode('utf-8')
        salvar_historico(con, id, senha_hash)
        cur.execute("""
            UPDATE USUARIOS SET NOME=?, USUARIO=?, EMAIL=?, SENHA=?, FOTO=? WHERE ID_USUARIO=?
        """, (nome, usuario, email, senha_hash, foto, id))
    else:
        cur.execute("""
            UPDATE USUARIOS SET NOME=?, USUARIO=?, EMAIL=?, FOTO=? WHERE ID_USUARIO=?
        """, (nome, usuario, email, foto, id))

    con.commit()
    cur.close()
    return jsonify({'mensagem': 'Usuário atualizado!'}), 200


@app.route('/deletar_usuarios/<int:id>', methods=['DELETE'])
@token_requerido
def deletar_usuarios(id):
    cur = con.cursor()
    cur.execute("SELECT 1 FROM USUARIOS WHERE ID_USUARIO=?", (id,))
    if not cur.fetchone():
        cur.close()
        return jsonify({'error': 'Usuário não encontrado!'}), 404
    cur.execute("DELETE FROM USUARIOS WHERE ID_USUARIO=?", (id,))
    con.commit()
    cur.close()
    return jsonify({'mensagem': 'Usuário deletado!', 'id': id}), 200


@app.route('/desbloquear_usuario/<int:id>', methods=['PATCH'])
@token_requerido
@admin_requerido
def desbloquear_usuario(id):
    cur = con.cursor()
    cur.execute("SELECT 1 FROM USUARIOS WHERE ID_USUARIO=?", (id,))
    if not cur.fetchone():
        cur.close()
        return jsonify({'error': 'Usuário não encontrado!'}), 404
    cur.execute("UPDATE USUARIOS SET BLOQUEADO=0, TENTATIVAS=0 WHERE ID_USUARIO=?", (id,))
    con.commit()
    cur.close()
    return jsonify({'mensagem': 'Usuário desbloqueado!'}), 200


# ── Cadastro de vendedor pelo ADM ─────────────────────────────────────────────
@app.route('/criar_vendedor', methods=['POST'])
@token_requerido
@admin_requerido
def criar_vendedor():
    nome    = request.form.get('nome', '').strip()
    email   = request.form.get('email', '').strip()
    usuario = request.form.get('usuario', '').strip()

    if not nome:
        return jsonify({'error': 'Nome é obrigatório!'}), 400
    if not email:
        return jsonify({'error': 'E-mail é obrigatório!'}), 400
    if not usuario:
        return jsonify({'error': 'Usuário é obrigatório!'}), 400

    try:
        cur = con.cursor()

        cur.execute("SELECT 1 FROM USUARIOS WHERE USUARIO = ?", (usuario,))
        if cur.fetchone():
            cur.close()
            return jsonify({'error': 'Nome de usuário já cadastrado!'}), 400

        cur.execute("SELECT 1 FROM USUARIOS WHERE EMAIL = ?", (email,))
        if cur.fetchone():
            cur.close()
            return jsonify({'error': 'E-mail já cadastrado!'}), 400

        # Gera senha temporária no formato: Xxxx9999@  (atende todos os critérios)
        senha_temp  = secrets.token_urlsafe(10)
        # Garante que atende os critérios: acrescenta prefixo e sufixo fixos
        senha_temp  = f"V{senha_temp[:6]}1@"

        senha_hash  = generate_password_hash(senha_temp).decode('utf-8')
        foto        = salvar_foto(request.files.get('foto'))

        # Token de redefinição obrigatória (expira em 24h)
        token_redef = secrets.token_urlsafe(48)
        expira      = datetime.now(timezone.utc) + timedelta(hours=24)

        cur.execute("""
            INSERT INTO USUARIOS
                (NOME, EMAIL, USUARIO, SENHA, FOTO, EMAIL_CONFIRMADO, PRIMEIRO_ACESSO)
            VALUES (?, ?, ?, ?, ?, 1, 1)
        """, (nome, email, usuario, senha_hash, foto))
        con.commit()

        cur.execute("SELECT MAX(ID_USUARIO) FROM USUARIOS")
        id_novo = cur.fetchone()[0]

        # Salva token de redefinição obrigatória
        cur.execute("""
            INSERT INTO TOKENS_RECUPERACAO (ID_USUARIO, TOKEN, EXPIRA_EM)
            VALUES (?, ?, ?)
        """, (id_novo, token_redef, expira))
        con.commit()
        cur.close()

        salvar_historico(con, id_novo, senha_hash)

        try:
            enviar_boas_vindas_vendedor(mail, email, nome, usuario, senha_temp, token_redef)
        except Exception as e:
            app.logger.warning(f"E-mail de boas-vindas não enviado: {e}")

        return jsonify({
            'mensagem': f'Vendedor {nome} cadastrado! E-mail enviado para {email}.',
            'id': id_novo
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/recuperar_senha', methods=['POST'])
def recuperar_senha():
    email = request.get_json().get('email', '').strip()
    cur = con.cursor()
    cur.execute("SELECT ID_USUARIO, NOME FROM USUARIOS WHERE EMAIL=?", (email,))
    row = cur.fetchone()
    if row:
        token  = secrets.token_urlsafe(48)
        expira = datetime.now(timezone.utc) + timedelta(hours=1)
        cur.execute("INSERT INTO TOKENS_RECUPERACAO (ID_USUARIO, TOKEN, EXPIRA_EM) VALUES (?,?,?)",
                    (row[0], token, expira))
        con.commit()
        try:
            enviar_recuperacao(mail, email, row[1], token)
        except Exception as e:
            app.logger.warning(f"E-mail não enviado: {e}")
    cur.close()
    return jsonify({'mensagem': 'Se o e-mail existir, você receberá as instruções.'}), 200


@app.route('/redefinir_senha/<token>', methods=['POST'])
def redefinir_senha(token):
    senha = request.get_json().get('senha', '').strip()

    if not verificar_senha(senha):
        return jsonify({'error': 'Senha precisa ter maiúscula, minúscula, número e caractere especial!'}), 400

    cur = con.cursor()
    cur.execute("SELECT ID_USUARIO, EXPIRA_EM, USADO FROM TOKENS_RECUPERACAO WHERE TOKEN=?", (token,))
    row = cur.fetchone()

    if not row:
        cur.close()
        return jsonify({'error': 'Token inválido!'}), 400
    if row[2]:
        cur.close()
        return jsonify({'error': 'Token já utilizado!'}), 400
    if datetime.now(timezone.utc) > row[1].replace(tzinfo=timezone.utc):
        cur.close()
        return jsonify({'error': 'Token expirado!'}), 400

    id_u = row[0]
    if senha_ja_usada(con, id_u, senha):
        cur.close()
        return jsonify({'error': 'Não é permitido reutilizar as últimas 3 senhas!'}), 400

    senha_hash = generate_password_hash(senha).decode('utf-8')
    salvar_historico(con, id_u, senha_hash)
    cur.execute("UPDATE USUARIOS SET SENHA=?, PRIMEIRO_ACESSO=0 WHERE ID_USUARIO=?", (senha_hash, id_u))
    cur.execute("UPDATE TOKENS_RECUPERACAO SET USADO=1 WHERE TOKEN=?", (token,))
    con.commit()
    cur.close()
    return jsonify({'mensagem': 'Senha redefinida com sucesso!'}), 200


@app.route('/uploads/<nome>', methods=['GET'])
def servir_foto(nome):
    return send_from_directory(app.config['UPLOAD_FOLDER'], nome)


# ══════════════════════════════════════════════════════════════
#  TAREFAS + TRELLO
# ══════════════════════════════════════════════════════════════

def criar_card_trello(titulo, descricao, prazo, prioridade):
    key   = app.config.get('TRELLO_KEY', '')
    token = app.config.get('TRELLO_TOKEN', '')
    board = app.config.get('TRELLO_BOARD', '')
    if not all([key, token, board]):
        return None
    r = requests.get(f"https://api.trello.com/1/boards/{board}/lists",
                     params={'key': key, 'token': token, 'fields': 'id'})
    if r.status_code != 200 or not r.json():
        return None
    lista_id = r.json()[0]['id']
    cores = {'baixa': 'green', 'media': 'yellow', 'alta': 'orange', 'urgente': 'red'}
    r = requests.post("https://api.trello.com/1/cards", params={
        'key': key, 'token': token, 'idList': lista_id,
        'name': titulo,
        'desc': f"Prioridade: {prioridade.upper()}\n\n{descricao or ''}",
        'due': prazo
    })
    return r.json().get('id') if r.status_code == 200 else None


@app.route('/tarefas', methods=['POST'])
@token_requerido
def criar_tarefa():
    data       = request.get_json()
    titulo     = data.get('titulo', '').strip()
    descricao  = data.get('descricao', '').strip()
    responsavel= data.get('responsavel')
    prazo      = data.get('prazo')
    prioridade = data.get('prioridade', 'media').lower()

    if not titulo:
        return jsonify({'error': 'Título é obrigatório!'}), 400
    if prioridade not in ('baixa', 'media', 'alta', 'urgente'):
        return jsonify({'error': 'Prioridade: baixa, media, alta ou urgente'}), 400

    trello_id = criar_card_trello(titulo, descricao, prazo, prioridade)

    cur = con.cursor()
    cur.execute("""
        INSERT INTO TAREFAS (TITULO, DESCRICAO, RESPONSAVEL, PRAZO, PRIORIDADE, TRELLO_ID)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (titulo, descricao or None, responsavel, prazo, prioridade, trello_id))
    con.commit()
    cur.execute("SELECT MAX(ID_TAREFA) FROM TAREFAS")
    id_t = cur.fetchone()[0]
    cur.close()

    return jsonify({
        'mensagem': 'Tarefa criada!',
        'tarefa': {'id': id_t, 'titulo': titulo, 'prioridade': prioridade,
                   'prazo': prazo, 'trello_id': trello_id}
    }), 201


@app.route('/tarefas', methods=['GET'])
@token_requerido
def listar_tarefas():
    cur = con.cursor()
    cur.execute("""
        SELECT t.ID_TAREFA, t.TITULO, t.DESCRICAO, t.PRAZO, t.PRIORIDADE,
               t.STATUS, t.TRELLO_ID, u.NOME, t.DT_CRIACAO
        FROM TAREFAS t
        LEFT JOIN USUARIOS u ON t.RESPONSAVEL = u.ID_USUARIO
        ORDER BY t.DT_CRIACAO DESC
    """)
    rows = cur.fetchall()
    cur.close()
    return jsonify({'tarefas': [
        {'id': r[0], 'titulo': r[1], 'descricao': r[2],
         'prazo': str(r[3]) if r[3] else None, 'prioridade': r[4],
         'status': r[5], 'trello_id': r[6], 'responsavel': r[7],
         'criado_em': str(r[8])}
        for r in rows
    ]}), 200