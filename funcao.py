from flask_bcrypt import generate_password_hash, check_password_hash
from flask import request, current_app, render_template

# Importar o con da main
from db import conexao

# Bibliotecas para envio de e-mail
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Bibliotecas para token
import jwt
import datetime

# Função para verificar existente
def verificar_existente(tipo, id_usuario = None):
    # Por padrão, o id_usuario é none (quando não passamos na hora de chamar a função)

    # Cria conexão com o banco
    con = conexao()
    cur = con.cursor()
    try:

        # Verifica CPF/CNPJ
        if tipo == 1:
            # Se estiver editando um usuário (ignora o próprio id)
            if id_usuario:
                cur.execute("""SELECT 1
                               FROM USUARIO
                               WHERE CPF = ? AND ID_USUARIO != ?""", (id_usuario))
            else:
                # Verifica se já existe
                cur.execute("""SELECT 1
                           FROM USUARIOS
                           WHERE CPF = ?""", (id_usuario, ))

        # Verifica e-mail
        elif tipo == 2:
            # Se estiver editando (ignora o próprio id)
            if id_usuario:
                cur.execute("""SELECT 1
                               FROM USUARIOS
                               WHERE EMAIL = ? AND ID_USUARIO != ?""", (id_usuario, ))
            else:
                # Verifica se já existe
                cur.execute("""SELECT 1
                           FROM USUARIOS
                           WHERE EMAIL = ?""", (id_usuario, ))

        # Se não encontrou, pode usar
        if not cur.fetchone():
            return True
        return False

    except Exception as e:
        return False
    finally:
        cur.close()
        con.close()


# Verifica se as senhas são iguais
def senha_correspondente(senha, confirmar_senha):
    try:
        if senha == confirmar_senha:
            return True
        return False
    except Exception as e:
        return False


# Verifica se a senha é forte
def senha_forte(senha):
    try:
        # Verifica tamanho mínimo
        if len(senha) < 8:
            return False

        # Critérios da senha
        criterios = {
            "maiuscula": False,
            "minuscula": False,
            "numero": False,
            "especial": False
        }

        # Percorre cada caractere
        for s in senha:
            if s.isupper():
                criterios["maiuscula"] = True
            elif s.islower():
                criterios["minuscula"] = True
            elif s.isdigit():
                criterios["numero"] = True
            elif s.isalnum() is False:
                criterios["especial"] = True

        # Verifica se todos os critérios foram atendidos
        if criterios["maiuscula"] == True and criterios["minuscula"] == True and criterios["numero"] == True and criterios["especial"] == True:
            return True

        return False

    except Exception as e:
        return False


# Verifica se a senha já foi usada antes
def senha_antiga(id_usuario, nova_senha):
    # Cria conexão
    con = conexao()
    cursor = con.cursor()
    try:
        # Busca senha atual
        cursor.execute('SELECT senha FROM usuario WHERE id_usuario = ?', (id_usuario, ))
        senha_atual_hash = cursor.fetchone()[0]

        # Busca últimas senhas usadas
        cursor.execute('SELECT FIRST 2 SENHA_HASH FROM HISTORICO_SENHA WHERE id_usuario = ?',
                   (id_usuario,))
        ultimas_senhas = cursor.fetchall()

        # Busca a senha mais antiga do histórico
        cursor.execute(
            'SELECT FIRST 1 ID_HISTORICO_SENHA FROM HISTORICO_SENHA WHERE id_usuario = ?',
            (id_usuario,))
        tem_senha = cursor.fetchone()

        if tem_senha:
            senha_mais_antiga = tem_senha[0]

        # Verifica se a nova senha já foi usada
        for u in ultimas_senhas:
            senha_anterior = u[0]
            if check_password_hash(senha_anterior, nova_senha):
                return False

        # Verifica com a senha atual
        if check_password_hash(senha_atual_hash, nova_senha):
            return False

        # Data da alteração
        data_alteracao = datetime.datetime.utcnow()

        # Salva senha atual no histórico
        cursor.execute("INSERT INTO HISTORICO_SENHA(id_usuario, SENHA_HASH, data_Alteracao) VALUES(?, ?, ?)",
                       (id_usuario, senha_atual_hash, data_alteracao))

        # Remove códigos de recuperação antigos
        cursor.execute('DELETE FROM RECUPERACAO_SENHA WHERE id_usuario = ?', (id_usuario,))

        # Mantém apenas as últimas 2 senhas no histórico
        if ultimas_senhas:
            if len(ultimas_senhas) == 2:
                cursor.execute(""" DELETE FROM HISTORICO_SENHA
                                   WHERE ID_HISTORICO_SENHA = ?""",
                               (senha_mais_antiga,))

        con.commit()

        return True

    except Exception as e:
        print(e)
        return False


# Função para enviar e-mail
def enviando_email(destinatario, assunto, html):
    # Dados do remetente
    user = 'nananenem732@gmail.com'
    senha = 'jxwf uxid qaga hhah'

    # Monta mensagem
    msg = MIMEText(html, 'html')
    msg['From'] = user
    msg['To'] = destinatario
    msg['Subject'] = assunto

    try:
        # Conecta no servidor SMTP
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)

        # Faz login
        server.login(user, senha)

        # Envia e-mail
        server.sendmail(user, [destinatario], msg.as_string())
    finally:
        server.quit()


# Gera token de autenticação
def gerar_token(tipo, id_usuario, tempo):
    # Dados do token
    payload = { 'tipo': tipo,
                'id_usuario': id_usuario,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=tempo)
               }

    # Chave secreta
    senha_secreta = current_app.config['SECRET_KEY']

    # Cria token
    token = jwt.encode(payload, senha_secreta, algorithm='HS256')

    return token


# Decodifica token
def decodificar_token():
    try:
        # Pega token do cookie
        token = request.cookies.get("acess_token")

        # Verifica se existe
        if not token:
            return False

        # Chave secreta
        senha_secreta = current_app.config['SECRET_KEY']

        # Decodifica token
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])

        return {'tipo': payload['tipo'], 'id_usuario': payload['id_usuario']}

    # Token expirado
    except jwt.ExpiredSignatureError:
        return False

    # Token inválido
    except jwt.InvalidTokenError:
        return False
