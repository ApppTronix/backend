from flask import Flask
from flask_mongoengine import MongoEngine

# Create app
app = Flask(__name__)

#configFiles
app.config.from_pyfile('config.py')

# Create database connection object
db = MongoEngine(app)

from views import *

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6050, threaded=True)