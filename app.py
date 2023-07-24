from flask import Flask, jsonify, request
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors import CORS  # Importe a classe CORS

app = Flask(__name__)
CORS(app)
app.config['JWT_SECRET_KEY'] = 'seu_jwt_secret_key_aqui'  # Altere isso para uma chave secreta segura em produção
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
revogados = set()
# Simulando um banco de dados temporário em memória (para fins de demonstração)
usuarios = []
filmes = []
# Função auxiliar para encontrar um usuário pelo nome de usuário
def encontrar_usuario_por_nome(nome):
    for usuario in usuarios:
        if usuario['nome'] == nome:
            return usuario
    return None

# Função auxiliar para encontrar um filme pelo nome
def encontrar_filme_por_nome(nome):
    for filme in filmes:
        if filme['nome'] == nome:
            return filme
    return None


@app.route('/')
def home():
    return jsonify({"message": "Olá, Mundo!"}), 200
# Rota para registrar um novo usuário
@app.route('/cadastro', methods=['POST'])
def cadastrar_usuario():
    dados_usuario = request.json
    nome = dados_usuario['nome']
    senha = dados_usuario['senha']

    if encontrar_usuario_por_nome(nome):
        return jsonify({"message": "Nome de usuário já está em uso."}), 400

    senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')
    novo_usuario = {"nome": nome, "senha": senha_hash}
    usuarios.append(novo_usuario)

    return jsonify({"message": "Usuário registrado com sucesso."}), 201

# Rota para fazer login e obter um token JWT
@app.route('/login', methods=['POST'])
def login():
    dados_usuario = request.json
    nome = dados_usuario['nome']
    senha = dados_usuario['senha']

    usuario = encontrar_usuario_por_nome(nome)
    if not usuario or not bcrypt.check_password_hash(usuario['senha'], senha):
        return jsonify({"message": "Nome de usuário ou senha inválidos."}), 401

    access_token = create_access_token(identity=usuario['nome'])
    return jsonify(access_token=access_token), 200

# Rota protegida que requer autenticação com JWT
@app.route('/perfil', methods=['GET'])
@jwt_required()
def perfil():
    usuario_atual = get_jwt_identity()
    return jsonify({"message": usuario_atual}), 200

# Rota para adicionar um filme e suas informações
@app.route('/filmes', methods=['POST'])
@jwt_required()
def adicionar_filme():
    dados_filme = request.json
    nome_filme = dados_filme['nome']
    nota = dados_filme['nota']
    status = dados_filme['status']
    usuario = get_jwt_identity()  # Obtém o nome de usuário autenticado

    if encontrar_filme_por_nome(nome_filme):
        return jsonify({"message": "Filme já existe na lista."}), 400

    novo_filme = {"nome": nome_filme, "nota": nota, "status": status, "usuario": usuario}
    filmes.append(novo_filme)

    return jsonify({"message": "Filme adicionado com sucesso."}), 201

# Rota para listar todos os filmes do usuário autenticado
@app.route('/filmes', methods=['GET'])
@jwt_required()
def listar_filmes():
    usuario = get_jwt_identity()  # Obtém o nome de usuário autenticado
    filmes_usuario = [filme for filme in filmes if filme['usuario'] == usuario]
    return jsonify(filmes_usuario), 200

# Rota para atualizar informações de um filme
@app.route('/filmes/<string:nome>', methods=['PUT'])
@jwt_required()
def atualizar_filme(nome):
    filme = encontrar_filme_por_nome(nome)

    if not filme or filme['usuario'] != get_jwt_identity():
        return jsonify({"message": "Filme não encontrado ou não pertence ao usuário."}), 404

    dados_atualizados = request.json
    filme['nota'] = dados_atualizados.get('nota', filme['nota'])
    filme['status'] = dados_atualizados.get('status', filme['status'])

    return jsonify({"message": "Informações do filme atualizadas com sucesso."}), 200
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_raw_jwt()['jti']  # Obtém o 'jti' (JSON Token Identifier) do token JWT atual
    revogados.add(jti)
    return jsonify({"message": "Logout realizado com sucesso."}), 200

if __name__ == '__main__':
    app.run(debug=True)
    
