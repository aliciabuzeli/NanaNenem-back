from flask import Flask
from flask_cors import CORS
from flask_mail import Mail
import fdb, os

app = Flask(__name__)
app.config.from_pyfile('config.py')
CORS(app)
mail = Mail(app)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

try:
    con = fdb.connect(
        host=app.config['DB_HOST'],
        database=app.config['DB_NAME'],
        user=app.config['DB_USER'],
        password=app.config['DB_PASSWORD']
    )
    print("Banco conectado!")
except Exception as e:
    print(f"Erro na conexão: {e}")
    con = None

from view import *

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)