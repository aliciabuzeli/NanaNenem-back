@app.route('/criar_usuarios', methods=['POST'])
def criar_usuarios():
    dados = request.get_json()

    nome = dados.get('nome')
    usuario = dados.get('usuario')
    senha = dados.get('senha')

    try:
        cursor = con.cursor()
        cursor.execute("select 1 from usuarios where usuario = ?", (usuario,))
        if cursor.fetchone():
            return jsonify({"error": "Usuário já cadastrado!"}), 400
        if verificar_senha(senha) == False:
            return jsonify({"error": "Senha deve conter letra maiúscula, letra minúscula, número e caractere especial!"}), 400

        senha_hash = generate_password_hash(senha).decode('utf-8')

        cursor.execute("""INSERT INTO usuarios (nome, usuario, senha) VALUES(?, ?, ?)""", (nome, usuario, senha_hash))
        con.commit()
        return jsonify({
            'mensagem': 'Usuario criado com sucesso!',
            'usuarios': {
                'nome': nome,
                'usuario': usuario,
                'senha': senha_hash
            }
        }), 201

    except Exception as e:
        return jsonify(mensagem=f'Erro ao inserir no banco de dados: {e}'), 500
    finally:
        cursor.close()


@app.route('/editar_usuarios/<int:id>', methods=['PUT'])
def editar_usuarios(id):

    cursor = con.cursor()
    cursor.execute("SELECT id_usuario, nome, usuario, senha FROM usuarios WHERE id_usuario = ?", (id,))
    tem_usuario = cursor.fetchone()
    if not tem_usuario:
        cursor.close()
        return jsonify({"error": "Usuario não encontrado!"}), 404

    data = request.get_json()
    nome = data.get('nome')
    usuario = data.get('usuario')
    senha = data.get('senha')

    if verificar_senha(senha) == False:
        return jsonify(
            {"error": "Senha deve conter letra maiúscula, letra minúscula, número e caractere especial!"}), 400

    senha_hash = generate_password_hash(senha).decode('utf-8')

    cursor.execute("UPDATE usuarios SET nome = ?, usuario = ?, senha = ? WHERE id_usuario = ?", (nome, usuario, senha_hash, id))
    con.commit()
    cursor.close()

    return jsonify({"mensagem": "Usuario atualizado com sucesso!",
                    'usuarios': {
                        'id_usuario': id,
                        'nome': nome,
                        'usuario': usuario,
                        'senha': senha_hash
                               }
                    })


@app.route('/deletar_usuarios/<int:id>', methods=['DELETE'])
def deletar_usuarios(id):
    cursor = con.cursor()
    cursor.execute("SELECT 1 FROM usuarios WHERE id_usuario = ?", (id,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Usuario não encontrado!"}), 404

    cursor.execute("DELETE FROM usuarios WHERE id_usuario = ?", (id,))
    con.commit()
    cursor.close()

    return jsonify(
        {"mensagem": "Usuario deletado com sucesso!",
         'id_usuario': id}

    )


app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    usuario = data.get('usuario')
    senha = data.get('senha')

    try:
        cursor = con.cursor()
        cursor.execute("SELECT senha FROM usuarios WHERE usuario = ?", (usuario,))
        resultado = cursor.fetchone()
        if not resultado:
            return jsonify({"error": "Usuário não encontrado!"}), 404

        senha_hash = resultado[0]
        if not check_password_hash(senha_hash, senha):
            return jsonify({"error": "Senha incorreta!"}), 401

        return jsonify({"mensagem": "Login bem-sucedido!"})

    except Exception as e:
        return jsonify(mensagem=f'Erro ao consultar Banco de dados: {e}'), 500
    finally:
        cursor.close()

