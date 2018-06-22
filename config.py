DEBUG = True
SECRET_KEY = 'super-secret'

SECURITY_PASSWORD_HASH = 'pbkdf2_sha512'
SECURITY_TRACKABLE = True
SECURITY_PASSWORD_SALT = 'something_super_secret_change_in_production'

# MongoDB Config
MONGODB_DB = 'nitkdb'
MONGODB_HOST = 'localhost'
MONGODB_PORT = 27017
UPLOAD_FOLDER = UPLOAD_FOLDER