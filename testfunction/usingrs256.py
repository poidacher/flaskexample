from flask import Flask, request, jsonify, make_response
import jwt
import bcrypt
import uuid
import datetime
from functools import wraps
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretindependent'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:''@localhost/test'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(225), unique=True)
    password = db.Column(db.String(225))
    public_id = db.Column(db.String(225))
    admin = db.Column(db.Boolean)
    name = db.Column(db.String(225))


class Todos(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    text = db.Column(db.String(225))
    status = db.Column(db.Boolean)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            with open('public.key', 'r') as fh:
                 verifying_key = fh.read()
            #data = jwt.decode(token, app.config['SECRET_KEY'])
            data = jwt.decode(token, verifying_key)
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_user(current_user):
    if not current_user.admin:
        return jsonify({'message':'Tidak dapat masuk menggunakan user ini'})

    users = Users.query.all()

    output = []

    for users in users:
        user_data= {}
        user_data['public_id'] = users.public_id
        user_data['name'] = users.name
        user_data['admin'] = users.admin
        user_data['password'] = users.password
        output.append(user_data)

    return jsonify({'users': output})


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'Tidak dapat masuk menggunakan user ini'})

    user = Users.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'user tidak ditemukan'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] =  user.name
    user_data['admin'] = user.admin
    user_data['password'] = user.password

    return jsonify({'user': user_data})


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):

    if not current_user.admin:
        return jsonify({'message': 'Tidak dapat masuk menggunakan user ini'})

    data = request.get_json();

    hashed_password = bcrypt.hashpw(data['password'].encode('utf8'), bcrypt.gensalt())

    new_user = Users(public_id=str(uuid.uuid4()), name=data['name'],  password= hashed_password, admin= False)
    db.session.add(new_user);
    db.session.commit();

    return jsonify({'message': 'user baru telah ditambahkan'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message':'Tidak dapat masuk menggunakan user ini'})

    user = Users.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'user tidak ditemukan'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'user sudah diupdate menjadi admin'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message':'Tidak dapat masuk menggunakan user ini'})

    user = Users.query.filterby(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'user tidak ditemukan'})

    db.session.delete(user)
    db.sesssion.commit()

    return jsonify({'message' : 'user telah dihapus'})


@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('tidak dapat diverifikasi 1', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = Users.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('tidak dapat diverivikasi 2', 401,  {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if bcrypt.checkpw(auth.password.encode('utf8'), user.password.encode('utf8')):
        with open('private.key', 'rb') as fh:
            signing_key = fh.read()
#        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1)}, signing_key, 'RS256')

        return jsonify({'token': token.decode('UTF-8')})

    return make_response('tidak dapat diverifikasi 3', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


if __name__ == '__main__':
    app.run(debug=True)
