from server import db
from flask_security import UserMixin,RoleMixin

class Role(db.Document, RoleMixin):
    name = db.StringField(max_length=255)

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
    role=db.StringField()
    roles = db.ListField(db.ReferenceField(Role), default=[])
