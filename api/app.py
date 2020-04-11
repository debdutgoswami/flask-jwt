# flask imports
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid # for public id
from  werkzeug.security import generate_password_hash, check_password_hash
# imports for PyJWT authentication
import  jwt, datetime
from functools import wraps

app = Flask(__name__)
app.config.from_pyfile('settings.py')
db = SQLAlchemy(app)


# Database ORMs
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class Article(db.Model):
    id = db.Column(db.Integer,  primary_key=True)
    text = db.Column(db.String(1200))
    user_id = db.Column(db.Integer)


# checking whether loged-in or not based on that info, data is provided
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!!'}), 401

        return  f(current_user, *args, **kwargs)

    return decorated


# User Database Route
@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message': 'Cannot Perform'})

    users = User.query.all()

    output = []
    for user in users:
        output.append({
            'public_id': user.public_id,
            'name' : user.name,
            'admin' : user.admin
        })

    return jsonify({'users': output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'Cannot Perform'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No User Found'})

    user_data = {
        'public_id': user.public_id,
        'name' : user.name,
        'admin' : user.admin
    }

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):

    if not current_user.admin:
        return jsonify({'message': 'Cannot Perform'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New User Created Sucessfully!!'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'Cannot Perform'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No User Found'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'User Has Been Promoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'Cannot Perform'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No User Found'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'User Has Been Deleted!!'})


# Articles Route
@app.route('/article', methods=['GET'])
@token_required
def get_all_articles(current_user):

    articles = Article.query.all()

    output = []
    for article in articles:
        # querying the user database by public_id to find the author of the article
        user = User.query.filter_by(id=article.user_id).first()
        output.append({
            'public_id': user.public_id,
            'text' : article.text,
            'author' : user.name
        })

    return jsonify({'articles': output})

@app.route('/article', methods=['POST'])
@token_required
def create_article(current_user):

    data = request.get_json()
    #setting user_id to current_user's public ID so we can query the user database later on for the author
    new_article = Article(text=data['text'], user_id=current_user.id)
    db.session.add(new_article)
    db.session.commit()

    return jsonify({'message' : 'Article Created!!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!!"'})
