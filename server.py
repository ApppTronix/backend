from flask import Flask, jsonify
from flask_mongoengine import MongoEngine
from flask_security import MongoEngineUserDatastore, UserMixin, RoleMixin
from functools import wraps
from flask import request, Response
from oauth2client import client, crypt
from pymongo import MongoClient
import jwt
import time
import random
import pyfcm
from pyfcm import FCMNotification

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

dbClient = MongoClient('localhost', 27017)
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

# Create app
app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'super-secret'

# MongoDB Config
app.config['MONGODB_DB'] = 'nitkdb'
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
    courses=db.ListField(db.StringField())
    fcmID=db.StringField()
    collID=db.StringField()
    roles = db.ListField(db.ReferenceField(Role), default=[])

# Setup Flask-Security
user_datastore = MongoEngineUserDatastore(db, User, Role)
#security = Security(app, user_datastore)

@app.route('/timeTable', methods=['GET'])
@requires_auth
def getTimeTable():
    print('auth worked')
    current_user = user_datastore.find_user(userID=payload['userID'])
    ttcollections = mydb['timetable']

    varlist = []

    for course in current_user.courses:
        ttobject = ttcollections.find_one({"course": course})

        for period in ttobject['periods']:
            period['course']=course
            period['shortName']=ttobject['shortName']
            varlist.append(period)

    resultDict = {"results":varlist}
    print(resultDict)

    return jsonify(resultDict)

@app.route('/uploadtimeTable', methods=['POST'])
@requires_auth
def uploadTimeTable():
    content = request.get_json(force=True)

    current_user = user_datastore.find_user(userID=payload['userID'])
    ttcollections = mydb['timetable']

    courseObj = ttcollections.find_one({"course": content['course']})

    courseObj['timetable'].append(content)
    mydb.assignments.update_one({"_id": courseObj['_id']}, {"$set": courseObj})

    usersColln = mydb.user.find({"courses": ["EE243"]})
    for user in usersColln:
        result = push_service.notify_single_device(registration_id=user['fcmID'], data_message={"action": "syncDB"})
        print(result)

    return jsonify({"result": "uploadSuccessful"})

@app.route('/assignments', methods=['GET'])
@requires_auth
def getAssignments():
    print('auth worked')
    current_user = user_datastore.find_user(userID=payload['userID'])
    assignmentsColln = mydb['assignments']
    varlist = []

    for course in current_user.courses:
        assgnct = assignmentsColln.find_one({"course": course})

        for assgn in assgnct['assignments']:
            assgn['course']=course
            varlist.append(assgn)

    resultDict = {"results":varlist}
    print(resultDict)

    return jsonify(resultDict)

@app.route('/uploadAssignment', methods=['POST'])
@requires_auth
def uploadAssignment():
    content=request.get_json(force=True)

    current_user = user_datastore.find_user(userID=payload['userID'])
    assignmentsColln = mydb['assignments']

    courseObj = assignmentsColln.find_one({"course": content['course']})
    content.pop('course')
    courseObj['assignments'].append(content)
    mydb.assignments.update_one({"_id":courseObj['_id']},{"$set":courseObj})

    usersColln = mydb.user.find({"courses":["EE243"]})
    for user in usersColln:
        result = push_service.notify_single_device(registration_id=user['fcmID'], data_message={"action":"syncDB"})
        print(result)

    return jsonify({"result":"uploadSuccessful"})

@app.route('/editAssignment', methods=['POST'])
@requires_auth
def editAssignment():
    content=request.get_json(force=True)

    current_user = user_datastore.find_user(userID=payload['userID'])
    assgnColln = mydb['assignments']
    print(content)
    courseObj = assgnColln.find_one({"course": content['course']})
    content.pop('course')
    index=-1
    for test in courseObj['tests']:
        index += 1
        if test["title"] == content["title"]:
            courseObj['tests'][index]=content
            mydb.assignments.update_one({"_id": courseObj['_id']}, {"$set": courseObj})
            usersColln = mydb.user.find({"courses": ["EE243"]})
            for user in usersColln:
                result = push_service.notify_single_device(registration_id=user['fcmID'],
                                                           data_message={"action": "syncDB"})
                print(result)

            return jsonify({"result": "editSuccessful"})

@app.route('/deleteAssignment', methods=['POST'])
@requires_auth
def deleteAssignment():
    content=request.get_json(force=True)

    current_user = user_datastore.find_user(userID=payload['userID'])
    assignmentsColln = mydb['assignments']
    print(content)
    courseObj = assignmentsColln.find_one({"course": content['course']})
    content.pop('course')
    index=-1

    for assgn in courseObj['tests']:
        index += 1
        if assgn["title"] == content["title"]:
            del courseObj['assignments'][index]
            mydb.assignments.update_one({"_id": courseObj['_id']}, {"$set": courseObj})
            usersColln = mydb.user.find({"courses": ["EE243"]})
            for user in usersColln:
                result = push_service.notify_single_device(registration_id=user['fcmID'],
                                                           data_message={"action": "syncDB"})
                print(result)
            return jsonify({"result": "deleteSuccessful"})
    return jsonify({"result":"fail"})

@app.route('/tests', methods=['GET'])
@requires_auth
def getTests():
    print('auth worked')
    current_user = user_datastore.find_user(userID=payload['userID'])
    testsColln = mydb['tests']
    varlist = []

    for course in current_user.courses:
        testct = testsColln.find_one({"course": course})

        for test in testct['tests']:
            test['course']=course
            varlist.append(test)

    resultDict = {"results":varlist}
    print(resultDict)

    return jsonify(resultDict)

@app.route('/uploadTest', methods=['POST'])
@requires_auth
def uploadTest():
    content=request.get_json(force=True)

    current_user = user_datastore.find_user(userID=payload['userID'])
    testsColln = mydb['tests']
    print(content)
    courseObj = testsColln.find_one({"course": content['course']})
    content.pop('course')
    courseObj['tests'].append(content)
    mydb.tests.update_one({"_id":courseObj['_id']},{"$set":courseObj})

    usersColln = mydb.user.find({"courses":["EE243"]})
    for user in usersColln:
        result = push_service.notify_single_device(registration_id=user['fcmID'], data_message={"action":"syncDB"})
        print(result)

    return jsonify({"result":"uploadSuccessful"})

@app.route('/editTest', methods=['POST'])
@requires_auth
def editTest():
    content=request.get_json(force=True)

    current_user = user_datastore.find_user(userID=payload['userID'])
    testsColln = mydb['tests']
    print(content)
    courseObj = testsColln.find_one({"course": content['course']})
    content.pop('course')
    index=-1
    for test in courseObj['tests']:
        index += 1
        if test["title"] == content["title"]:
            courseObj['tests'][index]=content
            mydb.tests.update_one({"_id": courseObj['_id']}, {"$set": courseObj})
            usersColln = mydb.user.find({"courses": ["EE243"]})
            for user in usersColln:
                result = push_service.notify_single_device(registration_id=user['fcmID'],
                                                           data_message={"action": "syncDB"})
                print(result)

            return jsonify({"result": "editSuccessful"})

@app.route('/deleteTest', methods=['POST'])
@requires_auth
def deleteTest():
    content=request.get_json(force=True)

    current_user = user_datastore.find_user(userID=payload['userID'])
    testsColln = mydb['tests']
    print(content)
    courseObj = testsColln.find_one({"course": content['course']})
    content.pop('course')
    index=-1
    for test in courseObj['tests']:
        index += 1
        if test["title"] == content["title"]:
            del courseObj['tests'][index]
            mydb.tests.update_one({"_id": courseObj['_id']}, {"$set": courseObj})
            usersColln = mydb.user.find({"courses": ["EE243"]})
            for user in usersColln:
                result = push_service.notify_single_device(registration_id=user['fcmID'], data_message={"action": "syncDB"})
                print(result)
            return jsonify({"result": "deleteSuccessful"})


    return jsonify({"result":"fail"})

@app.route('/coursesWithAttendance', methods=['GET'])
@requires_auth
def getCoursesWithAttendance():
    current_user = user_datastore.find_user(userID=payload['userID'])
    attendanceColln = mydb['attendance']
    varlist = []

    for course in current_user.courses:
        attd = attendanceColln.find_one({"course": course})

        var={}
        totalSessions = 0
        print(totalSessions)
        presentSessions=0

        for att in attd['attendance']:

            totalSessions+=1
            if current_user.collID in att['studentsPresent']:
                presentSessions+=1

        var['course']=course
        var['attendancePercentage']=str(presentSessions/totalSessions*100)

        var['courseDesc']='Digitl Elec'
        varlist.append(var)

    resultDict = {"results": varlist}
    print(resultDict)

    return jsonify(resultDict)


@app.route('/attendance', methods=['GET'])
@requires_auth
def getAttendance():

    current_user = user_datastore.find_user(userID=payload['userID'])
    attendanceColln = mydb['attendance']
    varlist = []

    for course in current_user.courses:
        attd = attendanceColln.find_one({"course": course})

        for att in attd['attendance']:
            var={}
            var['date']=att['date']
            var['course']=course
            var['time']=att['date']

            if current_user.userID in att['studentsPresent']:
                var['presence'] = "P"
            else:
                var['presence'] = "A"

            varlist.append(var)

    resultDict = {"results":varlist}
    print(resultDict)

    return jsonify(resultDict)

@app.route('/updateFCM', methods=['POST'])
@requires_auth
def updateFCM():
    # To verify using ID Token and send access, refresh tokens

    content=request.get_json(force=True)
    token=content['fcmId']
    current_user['fcmID'] = token
    print(token)

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
    refreshKey=random.getrandbits(32)
    refreshToken = jwt.encode({'refreshSecret': refreshKey}, SIGNING_SECRET_KEY, algorithm='HS256')

    print('refreshtoken')
    print(refreshToken)
    #New User
    if not user_datastore.find_user(userID=idinfo['sub']):
        user_datastore.create_user(email=idinfo['email'], picture=idinfo['picture'], userID=idinfo['sub'], collID='15EE244', name=idinfo['name'], refreshSecret=refreshKey, fcmID=content['fcmID'], courses=['EE243'])
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
    print(content)
    refreshToken = content['refreshToken']
    payload = jwt.decode(refreshToken, SIGNING_SECRET_KEY)
    print(payload['refreshSecret'])
    user = user_datastore.find_user(refreshSecret=payload['refreshSecret'])

    if not user:
        print("fail")
        return "fail"
    else:
        secs = int(time.time())
        accessToken = jwt.encode({'userID': user.userID, 'iat': secs, 'exp': secs + 3000}, SIGNING_SECRET_KEY,
                                 algorithm='HS256')
        return accessToken

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6050, threaded=True)