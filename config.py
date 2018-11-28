DEBUG = True
SECRET_KEY = 'super-secret'

SECURITY_PASSWORD_HASH = 'pbkdf2_sha512'
SECURITY_TRACKABLE = True
SECURITY_PASSWORD_SALT = 'something_super_secret_change_in_production'

# MongoDB Config
MONGODB_DB = 'nitkdb'
MONGODB_HOST = 'localhost'
MONGODB_PORT = 27017

CLIENT_ID = "803577935837-vpfc9acmb7i274qi9u8jotg1qcddjqrb.apps.googleusercontent.com"
SIGNING_SECRET_KEY = "Heavy-Secret-untellable"

UPLOAD_FOLDER = '/root/uploads'
IMAGE_UPLOAD_FOLDER = '/root/imageuploads'
#UPLOAD_FOLDER = 'C:\\'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])