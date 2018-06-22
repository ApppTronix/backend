from flask import Flask, jsonify, request, redirect, url_for, Response
from flask_mongoengine import MongoEngine
from flask_pymongo import PyMongo
from flask_security import MongoEngineUserDatastore, UserMixin,RoleMixin
from models import User, Role
import errno
from functools import wraps
from pymongo import MongoClient
from pyfcm import FCMNotification
from oauth2client import client, crypt
import re

# Create app
app = Flask(__name__)


flow = client.flow_from_clientsecrets(
    'client_secrets.json',
    scope='profile',
    redirect_uri='http://www.example.com/oauth2callback')
flow.params['access_type'] = 'offline'         # offline access
flow.params['include_granted_scopes'] = True   # incremental auth

CLIENT_ID = "803577935837-vpfc9acmb7i274qi9u8jotg1qcddjqrb.apps.googleusercontent.com"
SIGNING_SECRET_KEY = "Heavy-Secret-untellable"

global payload
global  current_user

UPLOAD_FOLDER = '/root/uploads'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

dbClient = MongoClient(connect=False)
mydb = dbClient['nitkdb']
push_service = FCMNotification(api_key="AAAAuxj6N90:APA91bEFaMeZ39cJXMYPHUSzo1T3hZT4cYVZW0wbo0GFaQGHHpDbG1V6C1jWOYgmyUpdR55tGcDyEbebSZAxC0sjhEmIjouUh1GyKjTzgU3WOnsdnMP9JpbXDM7Ja5d9Obtt-koSJF40")


def check_auth(accessToken):
    try:
        global payload, current_user
        payload = jwt.decode(accessToken, SIGNING_SECRET_KEY)
        current_user = user_datastore.find_user(userID=payload['userID'])
    except jwt.ExpiredSignatureError:
        return False
    return True

def check_teacher(accessToken):
    try:
        global payload, current_user
        payload = jwt.decode(accessToken, SIGNING_SECRET_KEY)
        current_user = user_datastore.find_user(userID=payload['userID'])
        if(current_user.role is not 'teacher'):
            return False
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
            print(auth)
            if not check_auth(auth):
                return authenticate()
        else:
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def requires_teacher(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'Authorization' in request.headers:
            auth = request.headers['Authorization']
            print(auth)
            if not check_teacher(auth):
                return authenticate()
        else:
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

def make_sure_path_exists(path):
    try:
        os.makedirs(path)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise


#configFiles
app.config.from_pyfile('config.py')


# Create database connection object
db = MongoEngine(app)
mongo = PyMongo(app)


user_datastore = MongoEngineUserDatastore(db, User,Role)


from views import *      #importing views

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6050, threaded=True)