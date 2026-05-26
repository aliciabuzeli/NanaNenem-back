import os

from main import app

app.config['SECRET_KEY'] = 'minha_chave_super_secreta_123'
app.config['JWT_MINUTOS'] = 60

DEBUG = True

DB_HOST = 'localhost'
DB_NAME = r'C:\Users\Aluno\Downloads\NanaNenem-back-main (3)\NanaNenem-back-main\BANCO.FDB'

DB_USER = 'sysdba'
DB_PASSWORD = 'sysdba'

UPLOAD_FOLDER = os.path.abspath(os.path.dirname(__file__))
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER