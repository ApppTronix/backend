from app import app
import jwt
import time
import random
import os
import datetime
from werkzeug.utils import secure_filename
from flask import send_from_directory
import flask
from config import *
from flask import Flask, jsonify, request, redirect, url_for, Response
from models import *
import errno
from functools import wraps
from pyfcm import FCMNotification
from oauth2client import client, crypt
from pymongo import MongoClient


dbClient = MongoClient(connect=False)
db = dbClient['nitkdb']
push_service = FCMNotification(api_key="AAAAuxj6N90:APA91bEFaMeZ39cJXMYPHUSzo1T3hZT4cYVZW0wbo0GFaQGHHpDbG1V6C1jWOYgmyUpdR55tGcDyEbebSZAxC0sjhEmIjouUh1GyKjTzgU3WOnsdnMP9JpbXDM7Ja5d9Obtt-koSJF40")

flow = client.flow_from_clientsecrets(
    'client_secrets.json',
    scope='profile',
    redirect_uri='http://www.example.com/oauth2callback')
flow.params['access_type'] = 'offline'         # offline access
flow.params['include_granted_scopes'] = True   # incremental auth


def check_auth(accessToken):
    try:
        global payload, current_user
        payload = jwt.decode(accessToken, SIGNING_SECRET_KEY)
        current_user = User.objects.get(email=payload['email'])
    except jwt.ExpiredSignatureError:
        return False
    return True

def check_teacher(accessToken):
    try:
        global payload, current_user
        payload = jwt.decode(accessToken, SIGNING_SECRET_KEY)
        current_user = User.objects.get(email=payload['email'])
        if current_user.role != 'teacher':
            print(current_user.role)
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

@app.route('/uploadCourse', methods=['POST'])
@requires_auth
def uploadCourse():
    current_user = User.objects.get(email=payload['email'])
    content=request.get_json(force=True)

    courseColln = db['course']
    courseColln.insert_one(content)
    ttcollections = db['timetable']
    ttcollections .insert_one(content)

    acollections = db['assignments']
    acollections .insert_one(content)

    tcollections = db['tests']
    tcollections .insert_one(content)

    return jsonify({"result":"success"})

@app.route('/login/<roleName>', methods=['POST'])
def login(roleName):
    # To verify using ID Token and send access, refresh tokens
    if roleName not in ['teacher','student']:
        return 'bad url'
    content=request.get_json(force=True)
    token=content['idToken']

    try:
        idinfo = client.verify_id_token(token, CLIENT_ID)
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise crypt.AppIdentityError("Wrong issuer.")
    except crypt.AppIdentityError:
        #Invalid ID token
        return 'fail'
    print(idinfo)

    #Create refresh and access token
    refreshKey=random.getrandbits(32)
    refreshToken = jwt.encode({'refreshSecret': refreshKey, 'email':email}, SIGNING_SECRET_KEY, algorithm='HS256')

    #New User
    if not User.objects(email=idinfo['email']):
        if roleName in ['student']:
            print(idinfo['hd'])
            if idinfo['hd'] in ["nitk.edu.in"]:
                collID = idinfo['email'][:7]
                user = User(email=idinfo['email'], picture=idinfo['picture'], userID=idinfo['sub'],
                                           collID=collID, name=idinfo['name'], refreshSecret=refreshKey,
                                           fcmID=content['fcmID'], role="student")
                user.save()
                print('new user created')
                return refreshToken
            else:
                return 'fail. please login with email provided by nitk'
        else:
            print('new user cannot be created')
            return 'fail. approach admin to create teacher acc'
    #Existing User
    else :
        user=User.objects.get(email=idinfo['email'])

        if 'refreshSecret' not in user:
            refreshKey=random.getrandbits(32)
            User.delete_user(user)
            user = User(email=idinfo['email'], picture=idinfo['picture'], userID=idinfo['sub'],
                                       name=idinfo['name'], refreshSecret=refreshKey, role="teacher")
            user.save()
        else:
            refreshKey=user.refreshSecret

        print('existing user')
        return jwt.encode({'refreshSecret': refreshKey, 'email':email}, SIGNING_SECRET_KEY, algorithm='HS256')


@app.route('/loginEmail/<roleName>', methods=['POST'])
def loginEmail(roleName):
    content = request.get_json(force=True)
    refreshKey = random.getrandbits(32)

    print(content)
    print(User.objects.get(email=content['email']))
    if User.objects.get(email=content['email']):
        print('success')
        user = User.objects.get(email=content['email'], password=content['password'])
    else:
        return 'fail'

    refreshKey = random.getrandbits(32)
    user.refreshSecret = refreshKey
    user.save()
    refreshToken = jwt.encode({'refreshSecret': refreshKey, 'email': user.email}, SIGNING_SECRET_KEY ,algorithm='HS256')
    return refreshToken

@app.route('/schedule', methods=['GET'])
@requires_auth
def getTimeTable():
    print('auth worked')
    current_user = User.objects.get(email=payload['email'])
    ttcollections = db['timetable']

    varlist = []

    for course in current_user.courses:
        ttobject = ttcollections.find_one({"course": course})

        if ttobject is not None:
            for period in ttobject['periods']:
                period['course'] = course
                period['shortName'] = ttobject['shortName']
                varlist.append(period)

    resultDict = {"results":varlist}
    print(resultDict)

    return jsonify(resultDict)

@app.route('/uploadSchedule', methods=['POST'])
@requires_teacher
def uploadTimeTable():
    content = request.get_json(force=True)

    ttcollections = db['timetable']

    courseObj = ttcollections.find_one({"course": content['course']})

    if 'periods' not in courseObj:
        courseObj['periods']=[]

    course=content.pop('course')
    courseObj['periods'].append(content)
    db.timetable.update_one({"_id": courseObj['_id']}, {"$set": courseObj})

    content['course']=course
    sendfcm(course, "newSchedule", content)

    return jsonify({"result": "uploadSuccessful"})

@app.route('/assignments', methods=['GET'])
@requires_auth
def getAssignments():
    print('auth worked')
    current_user = User.objects.get(email=payload['email'])
    assignmentsColln = db['assignments']
    varlist = []

    for course in current_user.courses:
        assgnct = assignmentsColln.find_one({"course": course})

        if assgnct is not None:
            for assgn in assgnct['assignments']:
                assgn['course'] = course
                varlist.append(assgn)

    resultDict = {"results":varlist}
    print(resultDict)

    return jsonify(resultDict)

@app.route('/uploadAssignment', methods=['POST'])
@requires_teacher
def uploadAssignment():
    content=request.get_json(force=True)

    current_user = User.objects.get(email=payload['email'])
    assignmentsColln = db['assignments']

    courseObj = assignmentsColln.find_one({"course": content['course']})
    course=content.pop('course')

    if 'assignments' not in courseObj:
        courseObj['assignments']=[]


    courseObj['assignments'].append(content)
    db.assignments.update_one({"_id":courseObj['_id']},{"$set":courseObj})

    sendfcm(course, "newAssignment", content)

    return jsonify({"result":"uploadSuccessful"})

@app.route('/editAssignment', methods=['POST'])
@requires_teacher
def editAssignment():
    content=request.get_json(force=True)

    current_user = User.objects.get(userID=payload['userID'])
    assgnColln = db['assignments']
    print(content)
    courseObj = assgnColln.find_one({"course": content['course']})
    course=content.pop('course')
    index=-1
    for test in courseObj['tests']:
        index += 1
        if test["title"] == content["title"]:
            courseObj['tests'][index]=content
            db.assignments.update_one({"_id": courseObj['_id']}, {"$set": courseObj})

            content['course'] = course

            sendfcm(course, "editAssignment", content)

            return jsonify({"result": "editSuccessful"})
    return jsonify({"result": "assignment not found"})

@app.route('/tests', methods=['GET'])
@requires_auth
def getTests():
    print('auth worked')
    current_user = User.objects.get(email=payload['email'])
    testsColln = db['tests']
    varlist = []

    for course in current_user.courses:
        testct = testsColln.find_one({"course": course})

        if testct is not None:
            for test in testct['tests']:
                test['course'] = course
                varlist.append(test)

    resultDict = {"results":varlist}
    print(resultDict)

    return jsonify(resultDict)

@app.route('/uploadTest', methods=['POST'])
@requires_teacher
def uploadTest():
    content=request.get_json(force=True)

    global current_user
    testsColln = db['tests']
    print(content)
    courseObj = testsColln.find_one({"course": content['course']})
    course=content.pop('course')
    index = -1
    flag=False

    if 'tests' not in courseObj:
        courseObj['tests']=[]

    for test in courseObj['tests']:
        index += 1
        if test["title"] == content["title"]: flag = True

    if(flag):
        return jsonify({"result": "testTitleExists"})

    courseObj['tests'].append(content)
    db.tests.update_one({"_id":courseObj['_id']},{"$set":courseObj})

    content['course']=course
    sendfcm(course, "newTest", content)

    return jsonify({"result":"uploadSuccessful"})

@app.route('/editSchedule', methods=['POST'])
@requires_teacher
def editSchedule():
    content = request.get_json(force=True)

    ttcollections = db['timetable']

    courseObj = ttcollections.find_one({"course": content['course']})

    course = content.pop('course')
    index = -1

    for schedule in courseObj['periods']:
        index += 1
        if schedule["date"] == content["date"] & schedule["time"] == content["time"]:
            courseObj['periods'][index]=content
            db.timetable.update_one({"_id": courseObj['_id']}, {"$set": courseObj})

            content['course'] = course
            sendfcm(course, "editSchedule", content)
            return jsonify({"result": "editSuccessful"})

    return jsonify({"result": "fail"})
@app.route('/editTest', methods=['POST'])
@requires_teacher
def editTest():
    content=request.get_json(force=True)

    testsColln = db['tests']
    print(content)
    courseObj = testsColln.find_one({"course": content['course']})
    course = content.pop('course')
    index=-1
    for test in courseObj['tests']:
        index += 1
        if test["title"] == content["title"]:
            courseObj['tests'][index]=content
            db.tests.update_one({"_id": courseObj['_id']}, {"$set": courseObj})

            # Send a message to devices subscribed to this course topic.
            content['course']=course
            sendfcm(course, "editTest", content)
            return jsonify({"result": "editSuccessful"})

    return jsonify({"result": "test not found"})

@app.route('/deleteAssignment', methods=['POST'])
@requires_teacher
def deleteAssignment():
    content=request.get_json(force=True)


    global current_user
    assignmentsColln = db['assignments']
    print(content)
    courseObj = assignmentsColln.find_one({"course": content['course']})
    course=content.pop('course')
    index=-1

    for assgn in courseObj['assignments']:
        index += 1
        if assgn["title"] == content["title"]:
            del courseObj['assignments'][index]
            db.assignments.update_one({"_id": courseObj['_id']}, {"$set": courseObj})
            content['course'] = course
            sendfcm(course, "deleteAssignment", content)
            return jsonify({"result": "deleteSuccessful"})

    return jsonify({"result": "delete failed. Assignment does not exist"})

@app.route('/deleteTest', methods=['POST'])
@requires_teacher
def deleteTest():
    content=request.get_json(force=True)

    global current_user
    testsColln = db['tests']
    print(content)
    courseObj = testsColln.find_one({"course": content['course']})
    course=content.pop('course')
    index=-1

    for test in courseObj['tests']:
        index += 1
        if test["title"] == content["title"]:
            del courseObj['tests'][index]
            db.tests.update_one({"_id": courseObj['_id']}, {"$set": courseObj})

            content['course'] = course
            sendfcm(course,"deleteTest",content)
            return jsonify({"result": "deleteSuccessful"})

    return jsonify({"result":"delete failed. Test does not exist"})

@app.route('/deleteSchedule', methods=['POST'])
@requires_teacher
def deleteSchedule():
    content = request.get_json(force=True)

    ttcollections = db['timetable']

    courseObj = ttcollections.find_one({"course": content['course']})

    course = content.pop('course')
    index = -1

    for schedule in courseObj['periods']:
        index += 1
        if (schedule["date"] == content["date"])&(schedule["time"] == content["time"]):
            del courseObj['periods'][index]
            db.timetable.update_one({"_id": courseObj['_id']}, {"$set": courseObj})

            content['course'] = course
            sendfcm(course,"deleteSchedule",content)
            return jsonify({"result": "deleteSuccessful"})

    return jsonify({"result":"delete failed. Scheduled class does not exist"})

def sendfcm(course,msg, content):
    result = push_service.notify_topic_subscribers(topic_name=course,data_message={"title":msg, "content":content})
    print(result)



@app.route('/uploadFile/<path:course>/<path:filename>', methods=['POST'])
@requires_auth
def uploadFile(filename, course):
    current_user = User.objects.get(email=payload['email'])
    print(filename)
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        directory = app.config['UPLOAD_FOLDER']+"/"+course
        if not os.path.exists(directory):
            os.makedirs(directory)
        file.save(os.path.join(app.config['UPLOAD_FOLDER']+"/"+course, filename))
        sendfcm(course, "newResource", filename)
        return jsonify({"result": "uploadSuccess"})
    return jsonify({"result": "uploadFailed"})

@app.route('/uploadAttendanceImage/<path:course>/<path:filename>', methods=['POST'])
@requires_auth
def uploadAttendanceImage(filename, course):
    current_user = User.objects.get(email=payload['email'])
    print(filename)
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        directory = app.config['IMAGE_UPLOAD_FOLDER']+"/"+course
        if not os.path.exists(directory):
            print("creating directory")
            os.makedirs(directory)
        file.save(os.path.join(app.config['IMAGE_UPLOAD_FOLDER']+"/"+course, filename))
        return jsonify({"result": "uploadSuccess"})
    return jsonify({"result": "uploadFailed"})


@app.route('/uploads/<course>/<filename>')
@requires_auth
def uploaded_file(course,filename):
    print(course+filename)
    return send_from_directory(app.config['UPLOAD_FOLDER']+"/"+course,
                               filename)

@app.route('/resources', methods=['GET'])
@requires_auth
def getResources():
    current_user = User.objects.get(email=payload['email'])
    item = []

    courseColln = db['course']
    varlist = []

    for course in current_user.courses:
        if os.path.exists(app.config['UPLOAD_FOLDER']+'/'+course):
            resource = os.listdir(app.config['UPLOAD_FOLDER']+'/'+course)            #path
            item.append({"courseCode": course, "resources": resource})
    print(item)
    return jsonify({"result": item})

@app.route('/uploadFaceImages', methods=['POST'])
@requires_auth
def uploadFaceImages():
    global current_user
    uploaded_files = flask.request.files.getlist("file[]")
    i=0
    print(uploaded_files)
    for file in uploaded_files:
        i+=1
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            directory = app.config['FACES_FOLDER']+"/"+current_user.collID
            if not os.path.exists(directory):
                print("creating directory")
                os.makedirs(directory)
            file.save(os.path.join(app.config['FACES_FOLDER']+"/"+current_user.collID,current_user.collID+"_000"+str(i)))

    return jsonify({"result": "success"})


@app.route('/courses', methods=['GET'])
@requires_auth
def getCourses():
    current_user = User.objects.get(email=payload['email'])
    courseColln = db['course']
    varlist = []

    for course in current_user.courses:
        var = courseColln.find_one({"name": course})
        var.pop('_id')
        varlist.append(var)

    resultDict = {"results": varlist}
    print(resultDict)

    return jsonify(resultDict)


@app.route('/enrollCourse', methods=['POST'])
@requires_auth
def enrollCourses():
    content = request.get_json(force=True)
    current_user = User.objects.get(email=payload['email'])
    courseColln = db['course']

    var = courseColln.find_one({"course": content['name']})
    if var is None:
        return jsonify({"result":"course doesnt exist"})
    else:
        current_user.courses.append(content['name'])
        var.regIDs.append(current_user.collID)
        db.course.update_one({"_id": var['_id']}, {"$set": var})
        return jsonify({"result":"course enrolled"})


@app.route('/getAvailableCourses', methods=['GET'])
@requires_auth
def availableCourses():

    current_user = User.objects.get(userID=payload['userID'])
    semester=findSemester(current_user.collId)
    courseColln = db['course']

    varlist = []
    for course in courseColln :
        if semester in course['sem']:
            varlist.append(course)

    return jsonify({"result":varlist})

def findSemester(a):
    now=datetime.datetime.now()
    year=now.year
    month=now.month
    stdyear=a[:2]
    tmp=year[3:4]-stdyear

    if(month==1):
        sem = 2 * tmp
    elif (month>6 & month<12):
        sem=1+2*tmp
    else :
        sem=2*tmp

    return sem


@app.route('/uploadAttendance', methods=['POST'])
@requires_teacher
def putAttendance():
    print("Upload Attendance")
    content = request.get_json(force=True)
    print(content)
    print("Upload Attendance")
    ttcollections = db['timetable']

    courseObj = ttcollections.find_one({"course": content['course']})

    course = content.pop('course')

    if 'periods' not in courseObj:
        courseObj['periods']=[]

    i=0
    for schedule in courseObj['periods']:
        if (schedule['date'] == content['date'])&(schedule['time'] == content['time']):
            print("found schedule, updating attendance")
            courseObj['periods'][i]['presentIDs']=content['presentIDs']
            db.timetable.update_one({"_id": courseObj['_id']}, {"$set": courseObj})
            sendfcm(course, "updateAttendance", content)
            return jsonify({"result": "uploadSuccessful"})
        else:
            i+=1
    return jsonify({"result": "uploadFailed"})

@app.route('/updateFCM', methods=['POST'])
@requires_auth
def updateFCM():
    # To verify using ID Token and send access, refresh tokens

    content=request.get_json(force=True)
    token=content['fcmId']
    current_user['fcmID'] = token
    print(token)

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
    user = User.objects.get(email=payload['email'], refreshSecret= payload['refreshSecret'])

    if not user:
        print("fail")
        return "fail"
    else:
        secs = int(time.time())
        accessToken = jwt.encode({'email': user.email, 'iat': secs, 'exp': secs + 600}, SIGNING_SECRET_KEY,
                                 algorithm='HS256')
        return accessToken

