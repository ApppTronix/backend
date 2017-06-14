from flask import Flask, jsonify
from flask_mongoengine import MongoEngine
from flask_security import MongoEngineUserDatastore, UserMixin, RoleMixin
from functools import wraps
from flask import request, Response
from oauth2client import client, crypt
import jwt
import time
import random

flow = client.flow_from_clientsecrets(
    'client_secrets.json',
    scope='profile',
    redirect_uri='http://www.example.com/oauth2callback')
flow.params['access_type'] = 'offline'         # offline access
flow.params['include_granted_scopes'] = True   # incremental auth

CLIENT_ID = "803577935837-vpfc9acmb7i274qi9u8jotg1qcddjqrb.apps.googleusercontent.com"
SIGNING_SECRET_KEY = "Heavy-Secret-untellable"


def check_auth(accessToken):
    try:
        jwt.decode(accessToken, SIGNING_SECRET_KEY)
    except jwt.ExpiredSignatureError:
        return False
    return True

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'Authorization' in request.headers:
            auth = request.headers['Authorization']
        if not check_auth(auth):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# Create app
app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'super-secret'

# MongoDB Config
app.config['MONGODB_DB'] = 'mydatabase'
app.config['MONGODB_HOST'] = 'localhost'
app.config['MONGODB_PORT'] = 27017

# Create database connection object
db = MongoEngine(app)


class Role(db.Document, RoleMixin):
    name = db.StringField(max_length=80, unique=True)
    description = db.StringField(max_length=255)

class User(db.Document, UserMixin):
    email = db.StringField(max_length=255)
    password = db.StringField(max_length=255)
    active = db.BooleanField(default=True)
    confirmed_at = db.DateTimeField()
    picture = db.StringField()
    userID = db.StringField()
    name = db.StringField(max_length=255)
    refreshSecret=db.LongField()
    courses=db.ListField(db.StringField(max_length=5))
    roles = db.ListField(db.ReferenceField(Role), default=[])

# Setup Flask-Security
user_datastore = MongoEngineUserDatastore(db, User, Role)
#security = Security(app, user_datastore)

@app.route('/timeTable', methods=['GET'])
@requires_auth
def getTimeTable():
    print('auth worked')
    return 'okay'

@app.route('/login', methods=['POST'])
def login():
    # To verify using ID Token and send access, refresh tokens

    content=request.get_json(force=True)
    token=content['idToken']
    print(token)

    try:
        idinfo = client.verify_id_token(token, CLIENT_ID)
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise crypt.AppIdentityError("Wrong issuer.")
    except crypt.AppIdentityError:
        #Invalid ID token
        return 'fail'

    print(idinfo['sub'])

    #Create refresh and access token
    refreshKey=random.getrandbits(32);
    secs=int(time.time())
    refreshToken = jwt.encode({'refreshSecret': refreshKey}, SIGNING_SECRET_KEY, algorithm='HS256')
    accessToken = jwt.encode( {'userID': idinfo['sub'],'iat':secs,'exp':secs+3000}, SIGNING_SECRET_KEY, algorithm='HS256')
    print('refreshtoken')
    print(refreshToken)
    #New User
    if not user_datastore.find_user(userID=idinfo['sub']):
        user_datastore.create_user(email=idinfo['email'], picture=idinfo['picture'], userID=idinfo['sub'], name=idinfo['name'], refreshSecret=refreshKey)
        print('new user created')
        return refreshToken
    #Existing User
    else :
        user=user_datastore.find_user(userID=idinfo['sub'])
        refreshKey=user.refreshSecret
        print(refreshKey)
        return jwt.encode({'refreshSecret': refreshKey}, SIGNING_SECRET_KEY, algorithm='HS256')



@app.route('/isServerOnline', methods=['GET'])
def isServerOnline():
    return jsonify({"result": "true"})

@app.route('/getAccessToken', methods=['POST'])
def getAccessToken():
    content = request.get_json(force=True)
    refreshToken = content['refreshToken']
    payload = jwt.decode(refreshToken, SIGNING_SECRET_KEY)
    print(payload['refreshSecret'])
    user = user_datastore.find_user(refreshSecret=payload['refreshSecret'])

    if not user:
        return "fail"
    else:
        secs = int(time.time())
        accessToken = jwt.encode({'userID': user.userID, 'iat': secs, 'exp': secs + 3000}, SIGNING_SECRET_KEY,
                                 algorithm='HS256')
        return accessToken

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6050, threaded=True)
