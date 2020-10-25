from datetime import datetime

from db import db


class Song(db.DynamicEmbeddedDocument):
    upvote_users = db.ListField(db.StringField())


    def to_json(self):
        res = super(Song, self).to_json(self)
        import json
        obj = json.loads(res)
        obj.upvote_users = 3
        return json.dumps(obj)


class Session(db.DynamicDocument):
    name = db.StringField(required=True)
    password = db.StringField()
    created_on = db.DateTimeField(default=datetime.utcnow)
    songs = db.ListField(db.EmbeddedDocumentField('Song'))
    messages = db.ListField(db.StringField())


class User(db.Document):
    username = db.StringField()
    auth_token = db.StringField()
    socket_id = db.StringField()
    session = db.ReferenceField('Session')
