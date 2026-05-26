import random

import jwt
import jwt as pyjwt
import requests
import secrets
from datetime import datetime, timezone, timedelta
from flask import request, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from main import app, con, mail
from funcao import (
    verificar_senha, gerar_token, decodificar_token, enviando_email
)

# ══════════════════════════════════════════════════════════════
#  USUÁRIOS
# ══════════════════════════════════════════════════════════════

from flask import request, jsonify, current_app, render_template
from werkzeug.security import generate_password_hash
import random
import os
import threading


@app.route('/cadastro_vendedor', methods=['POST'])
def cadastro_vendedor():
    cur = con.cursor()

    try:
        nome = request.form.get('nome').strip()
        email = request.form.get('email').strip()
        cpf = request.form.get('cpf', '').strip()
        senha = request.form.get('senha', '').strip()
        telefone = request.form.get('telefone', '').strip()
        confirmar_senha = request.form.get('confirmar_senha').strip()
        imagem = request.files.get('imagem')

        if not nome or not email or not senha or not confirmar_senha:
            return jsonify({"error": "Preencha todos os campos obrigatórios"}), 400

        if senha != confirmar_senha:
            return jsonify({"error": "As senhas não coincidem"}), 400

        if len(senha) < 8:
            return jsonify({"error": "A senha deve ter pelo menos 8 caracteres"}), 400

        tem_maiuscula = False
        tem_minuscula = False
        tem_numero = False
        tem_especial = False

        especiais = "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~"

        for c in senha:
            if c.isupper():
                tem_maiuscula = True
            elif c.islower():
                tem_minuscula = True
            elif c.isdigit():
                tem_numero = True
            elif c in especiais:
                tem_especial = True

        if not tem_maiuscula:
            return jsonify({"error": "A senha precisa ter uma letra maiúscula"}), 400

        if not tem_minuscula:
            return jsonify({"error": "A senha precisa ter uma letra minúscula"}), 400

        if not tem_numero:
            return jsonify({"error": "A senha precisa ter um número"}), 400

        if not tem_especial:
            return jsonify({"error": "A senha precisa ter um caractere especial"}), 400

        cur.execute("SELECT 1 FROM USUARIO WHERE EMAIL = ?", (email,))

        if cur.fetchone():
            return jsonify({"error": "Email já cadastrado"}), 400

        codigo = random.randint(100000, 999999)
        senha_hash = generate_password_hash(senha)

        cur.execute("""
            INSERT INTO USUARIO
            (
                EMAIL,
                CPF,
                NOME,
                TELEFONE,
                SENHA,
                TIPO,
                CODIGO,
                SITUACAO,
                CONFIRMAR_SENHA
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            email,
            cpf,
            nome,
            telefone,
            senha_hash,
            1,
            codigo,
            0,
            confirmar_senha
        ))

        con.commit()

        cur.execute(
            "SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = ?",
            (email,)
        )

        resultado = cur.fetchone()

        if not resultado:
            return jsonify({"error": "Erro ao buscar usuário cadastrado"}), 500

        id_usuario = resultado[0]

        if imagem:
            nome_imagem = f"{id_usuario}.jpg"

            pasta = os.path.join(
                current_app.config['UPLOAD_FOLDER'],
                "Fotos"
            )

            os.makedirs(pasta, exist_ok=True)

            caminho_imagem = os.path.join(pasta, nome_imagem)

            imagem.save(caminho_imagem)

        try:
            assunto = 'Confirmação de Email'

            mensagem = f"""
Olá, {nome}!

Seu código de confirmação é:

{codigo}

Se você não realizou este cadastro, ignore este email.
"""

            thread = threading.Thread(
                target=enviando_email,
                args=(email, assunto, mensagem)
            )

            thread.start()

        except Exception as e:
            print(f"Erro ao enviar email: {e}")

        return jsonify({
            "mensagem": "Vendedor cadastrado com sucesso!",
            "id_usuario": id_usuario
        }), 200

    except Exception as e:
        con.rollback()
        print(f"Houve um erro: {e}")
        return jsonify({"error": str(e)}), 500

    finally:
        cur.close()
@app.route('/confirmar_email', methods=['POST'])
def confirmar_email():
    cur = con.cursor()

    try:
        data = request.get_json(silent=True)

        if not data:
            return jsonify({
                "error": "Envie os dados em JSON no Body -> raw -> JSON"
            }), 400

        email = data.get('email')
        codigo = data.get('codigo')

        if not email or not codigo:
            return jsonify({
                'error': 'Email e código são obrigatórios.'
            }), 400

        codigo = str(codigo).strip()

        cur.execute("""
            SELECT id_usuario, codigo
            FROM usuario
            WHERE email = ?
        """, (email,))

        usuario = cur.fetchone()

        if not usuario:
            return jsonify({
                'error': 'Usuário não encontrado.'
            }), 404

        id_usuario = usuario[0]
        codigo_banco = str(usuario[1]).strip()

        if codigo != codigo_banco:
            return jsonify({
                'error': 'Código inválido.'
            }), 400

        cur.execute("""
            UPDATE usuario
            SET situacao = 1,
                codigo = NULL
            WHERE id_usuario = ?
        """, (id_usuario,))

        con.commit()

        return jsonify({
            'message': 'Email validado com sucesso.'
        }), 200

    except Exception as e:
        con.rollback()
        print(f"Erro ao validar email: {e}")
        return jsonify({
            'error': str(e)
        }), 500

    finally:
        cur.close()

@app.route('/login', methods=['POST'])
def login():
    print(app.config.get('SECRET_KEY'))
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "error": "Envie email e senha em JSON"
            }), 400

        print('1')
        email = data.get('email', '').strip()
        senha = data.get('senha', '').strip()
        print("2")

        if not email or not senha:
            return jsonify({
                "error": "Email e senha são obrigatórios"
            }), 400

        print('3')
        cur = con.cursor()

        cur.execute("""
            SELECT ID_USUARIO, SENHA, SITUACAO, TENTATIVAS, BLOQUEADO
            FROM USUARIO
            WHERE EMAIL = ?
        """, (email,))

        usuario = cur.fetchone()
        print('4')

        if not usuario:
            cur.close()
            return jsonify({'error': 'Usuário não encontrado!'}), 404
        print('5')

        id_u = usuario[0]
        senha_hash = usuario[1]
        confirmado = usuario[2]
        tentativas = int(usuario[3] or 0)
        bloqueado = usuario[4]

        print('6')

        if bloqueado:
            cur.close()
            return jsonify({
                'error': 'Conta bloqueada! Fale com o administrador.'
            }), 403
        print('7')

        if not confirmado:
            cur.close()
            return jsonify({
                'error': 'Confirme seu e-mail antes de entrar!'
            }), 403
        print('8')

        if not check_password_hash(senha_hash, senha):
            novas = tentativas + 1
            print('9')

            if novas >= 3:
                cur.execute("""
                    UPDATE USUARIO
                    SET TENTATIVAS = ?, BLOQUEADO = 1
                    WHERE ID_USUARIO = ?
                """, (novas, id_u))
                print('10')

                con.commit()
                cur.close()
                print('11')

                return jsonify({
                    'error': 'Senha incorreta! Conta bloqueada.'
                }), 403
            print('12')

            cur.execute("""
                UPDATE USUARIO
                SET TENTATIVAS = ?
                WHERE ID_USUARIO = ?
            """, (novas, id_u))
            print('13')

            con.commit()
            cur.close()


            return jsonify({
                'error': f'Senha incorreta! Tentativas restantes: {3 - novas}.'
            }), 401

        print('14')
        cur.execute("""
            UPDATE USUARIO
            SET TENTATIVAS = 0
            WHERE ID_USUARIO = ?
        """, (id_u,))
        print('15')

        con.commit()
        cur.close()

        token = gerar_token(id_u)
        print(token)

        return jsonify({
            'mensagem': 'Login realizado!',
            'token': token
        }), 200

    except Exception as e:
        print(f"Erro no login: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/cadastro_cliente', methods=['POST'])
def cadastro_cliente():
    cur = con.cursor()

    try:
        data = request.get_json()
        nome = data.get('nome', '').strip()
        print(nome)
        endereco = data.get('endereco', '').strip()
        print(endereco)
        cpf = data.get('cpf', '').strip()
        print(cpf)
        telefone = data.get('telefone', '').strip()
        print(telefone)
        email = data.get('email', '').strip()


        if not nome or not endereco or not cpf or not telefone or not email:
            return jsonify({"error": "Preencha todos os campos obrigatórios"}), 400

        cur.execute("SELECT 1 FROM USUARIO WHERE CPF = ?", (cpf,))

        if cur.fetchone():
            return jsonify({"error": "CNPJ já cadastrado"}), 400

        cur.execute("""
            INSERT INTO USUARIO
            (ENDERECO,
             CPF,
             NOME,
             TELEFONE,
             EMAIL,
             TIPO)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            endereco,
            cpf,
            nome,
            telefone,
            email,
            2
        ))

        con.commit()

        cur.execute(
            "SELECT ID_USUARIO FROM USUARIO WHERE CPF = ?",
            (cpf,)
        )

        resultado = cur.fetchone()

        if not resultado:
            return jsonify({"error": "Erro ao buscar usuário cadastrado"}), 500

        id_usuario = resultado[0]


        return jsonify({
            "mensagem": "Cliente cadastrado com sucesso!",
            "id_usuario": id_usuario
        }), 200

    except Exception as e:
        con.rollback() #passa tudo, se der erro volta tudo
        print(f"Houve um erro: {e}")
        return jsonify({"error": str(e)}), 500

    finally:
        cur.close()

@app.route('/esqueci_senha', methods=['POST'])
def esqueci_senha():
    cur = con.cursor()
    try:
        data = request.get_json()

        email = data.get('email', '').strip()
        codigo = data.get('codigo', '').strip()
        nova_senha = data.get('nova_senha', '').strip()

        if not email:
            return  jsonify({'error': 'Email é obrigatório'}), 400

        if not codigo and not nova_senha:
            cur.execute("""
                SELECT id_usuario
                FROM USUARIO
                WHERE EMAIL = ?
            """, (email,))
            if not cur.fetchone():
                return jsonify({'error' : 'Usuário não encontrado'}), 404

            codigo = f"{secrets.randbelow(1000000):06d}"

            cur.execute("""
                        UPDATE USUARIO
                        SET CODIGO = ?
                        WHERE EMAIL = ?
            """, (codigo, email))
            con.commit()

            threading.Thread(
                target=enviando_email,
                args=(email, "Recuperação de senha", f"Código: {codigo}"),
                daemon=True
            ).start()

            return jsonify({"mensagem": "Código enviado com sucesso!"}), 200

        if codigo and nova_senha:
            cur.execute("""
                SELECT ID_USUARIO, SENHA, SENHA_UM, SENHA_DOIS, SENHA_TRES, CODIGO
                FROM USUARIO
                WHERE EMAIL = ?
            """, (email,))
            usuario = cur.fetchone()

            if not usuario:
                return jsonify({'error': 'Usuário não encontrado'}), 404

            id_usuario = usuario[0]
            senha_atual = usuario[1]
            senha_um = usuario[2]
            senha_dois = usuario[3]
            senha_tres = usuario[4]
            codigo_banco = usuario[5]

            if str(codigo_banco) != str(codigo):
                return jsonify({'error': 'Código inválido'}), 400

            if not verificar_senha(nova_senha):
                return jsonify({"error": "A senha não segue nossos padrões de segurança"}), 400

            historico = [senha_atual, senha_um, senha_dois, senha_tres]
            for senha_hash in historico:
                if not senha_hash:
                    continue
                try:
                    if check_password_hash(senha_hash, nova_senha):
                        return jsonify({"error": "Não é permitido reutilizar as últimas 3 senhas"}), 400
                except ValueError:
                    continue

            nova_hash = generate_password_hash(nova_senha)

            cur.execute("""
                UPDATE usuario
                SET senha      = ?,
                    senha_um   = ?,
                    senha_dois = ?,
                    senha_tres = ?,
                    codigo     = NULL
                WHERE id_usuario = ?
            """, (
                nova_hash,
                nova_hash,
                senha_um,
                senha_dois,
                id_usuario
            ))
            con.commit()

            return jsonify({"mensagem": "Senha redefinida com sucesso"}), 200

        return jsonify({'error': 'Dados inválidos'}), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    finally:
        cur.close()

@app.route('/editar_usuario/<id_usuario>', methods=['PUT'])
def editar_usuario(id_usuario):
    token = request.cookies.get('access_token')

    if not token:
        return jsonify({"error" : "Token de autentificação necessário"}), 401

    try:
        payload = decodificar_token(token)
        id_usuario = payload['id_usuario']
        tipo = payload['tipo']

        if id_usuario != id and tipo != 0:
            return  jsonify({"error": "Você não pode editar outro usuário, apenas Administradores"}), 401

    except jwt.ExpiredSignatureError: #token expirado
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError: #token invalido
        return jsonify({"error": "Token invalid"}), 401

    cur = con.cursor()
    try:
        cur.execute("""
            SELECT 1 
            FROM USUARIO
            WHERE ID_USUARIO = ?
        """, (id_usuario,))
        if not cur.fetchone():
            return jsonify({"error": "Usuário não encontrado"}), 404

        nome = request.form.get('nome')
        email = request.form.get('email')

        if not nome or not email:
            return jsonify({"error": "Nome e email são obrigatórios"}), 400

        email = request.form.get('email').strip()
        senha = request.form.get('senha')
        cpf = request.form.get('cpf')
        telefone = request.form.get('telefone')
        nome = request.form.get('nome')
        confirmar_senha = request.form.get('confirmar_senha')
        imagem = request.files.get('imagem')

        cur.execute("""
            SELECT 1
            FROM USUARIO
            WHERE EMAIL = ? AND ID_USUARIO = ?
        """, (email, id_usuario))
        if cur.fetchone():
            return jsonify({"error": "Email já cadastrado"}), 400

        if not confirmar_senha(senha):
            return jsonify({"error": "Senha incorreta"}), 400

        senha_hash = generate_password_hash(senha).decode('utf-8')

        cur.execute("""
            UPDATE USUARIO 
            SET NOME = ?,
                EMAIL = ?,
                TELEFONE = ?,
                CPF = ?,
                SENHA = ?,
                CONFIRMAR_SENHA = ?
            WHERE ID_USUARIO = ?
        """, (nome, email, telefone, cpf, senha, id_usuario))
        con.commit()

        if imagem:
            nome_imagem = f"{id}.jpg"

