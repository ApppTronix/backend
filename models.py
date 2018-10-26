from app import db
from flask_mongoengine import BaseQuerySet


class User(db.Document):
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
    meta = { 'collection': 'user', 'queryset_class': BaseQuerySet}
