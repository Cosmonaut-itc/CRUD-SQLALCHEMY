from flask import Flask, jsonify
from flask_db2 import DB2
import sys
from flask_cors import CORS, cross_origin
import flask_login
import secrets
import flask
from argon2 import PasswordHasher
import time

# timestamp - milesimas de segundo desde 1 de enero de 1970 
VIDA_TOKEN = 1000 * 60 * 3

# 2do - creamos un objeto de tipo flask
app = Flask(__name__)

# APLICAR CONFIG DE DB2
app.config['DB2_DATABASE'] = 'testdb'
app.config['DB2_HOSTNAME'] = 'localhost'
app.config['DB2_PORT'] = 50000
app.config['DB2_PROTOCOL'] = 'TCPIP'
app.config['DB2_USER'] = 'db2inst1'
app.config['DB2_PASSWORD'] = 'GD1OJfLGG64HV2dtwK'

db = DB2(app)

CORS(app)

app.secret_key = secrets.token_urlsafe(16)
login_manager = flask_login.LoginManager()
login_manager.init_app(app)

usuarios = {"a": {"pass": "a"}}


class Usuario(flask_login.UserMixin):
    pass

@login_manager.user_loader
def user_loader(email):
    if email not in usuarios:
        return

    usuario = Usuario()
    usuario.id = email
    return usuario


@login_manager.request_loader
def request_loader(request):
    # obtener información que nos mandan en encabezado
    key = request.headers.get('Authorization')

    if key == ":":
        return None

    if key == None:
        return None
    processed = key.split(":")

    # recibimos token de encabezado
    usuario = processed[0]
    token = processed[1]

    # verificamos que usuario exista
    cur = db.connection.cursor()

    query = "SELECT * FROM users WHERE email=?"
    params = (usuario,)

    cur.execute(query, params)
    data = cur.fetchone()
    cur.close()

    if (not data):
        return None

    # verificamos que tenga token válido
    ph = PasswordHasher()

    try:
        ph.verify(data[3], token)
    except:
        return None

        # verificamos que el token siga vigente
    timestamp_actual = time.time()

    if (data[4] + VIDA_TOKEN < timestamp_actual):
        return None

    # actualizar vigencia del token 
    cur = db.connection.cursor()
    query = 'UPDATE users SET last_date=? WHERE email=?'
    params = (timestamp_actual, usuario)
    cur.execute(query, params)
    cur.close()

    # regresamos objeto si hubo Y token valido 
    result = Usuario()
    result.id = usuario
    result.nombre = "Pruebita"
    result.apellido = "Rodriguez"
    result.rol = "ADMIN"
    return result


@app.route('/login', methods=['POST'])
def login():
    # intro al password hasher
    ph = PasswordHasher()

    # Email check
    email = flask.request.form['email']

    cur = db.connection.cursor()

    query = 'SELECT * FROM users WHERE email=?'

    params = (email,)

    cur.execute(query, params)
    data = cur.fetchone()
    cur.close()

    if data is None:
        return "USUARIO NO VALIDO", 401

    # Password check
    try:
        ph.verify(data[2], flask.request.form['pass'])
    except:
        return "PASSWORD NO VALIDO", 401

    # Token
    token = secrets.token_urlsafe(32)

    # Timestamp
    last_date = time.time()

    # Place timestamp in DB
    cur = db.connection.cursor()
    query = "UPDATE users SET token=?, last_date=? WHERE email=?"
    params = (ph.hash(token), last_date, email)
    cur.execute(query, params)
    cur.close()


    return jsonify(token=token, caducidad=VIDA_TOKEN), 200



@login_manager.unauthorized_handler
def handler():
    return 'No autorizado', 401


@app.route('/logout')
@cross_origin()
@flask_login.login_required
def logout():

    cur = db.connection.cursor()
    query = 'UPDATE users SET last_date=? WHERE email=?'
    params = (0, flask_login.current_user.id)
    cur.execute(query, params)
    cur.close()
    return 'saliste'

@app.route('/')
@cross_origin()
@flask_login.login_required
def default():
    cur = db.connection.cursor()
    cur.execute('SELECT * FROM songs;')
    songs = cur.fetchall()

    cur.close()

    song_dic = []
    for i in songs:
        current = {
            "id" : i[0],
            "name" : i[1],
            "author" : i[2]
        }
        song_dic.append(current)

    return jsonify(song_dic)

@app.route('/songDetails/<string:song_id>')
def RequestSongDetail(song_id):
    cur = db.connection.cursor()
    query = 'SELECT * FROM songs WHERE id =?'
    params = (song_id,)
    cur.execute(query, params)
    song = cur.fetchone()
    cur.close()
    return jsonify(song)