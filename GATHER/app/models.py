
from app.database import db

class User(db.Model):
    __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(length=16))
    email = db.Column(db.String(length=32))
    password = db.Column(db.String(length=32))
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return str(self.username)


class AuthToken(db.Model):
    __tablename__ = "auth_tokens"

    user_id = db.Column(db.Integer, db.ForeignKey(User.user_id), primary_key=True)
    token = db.Column(db.String(length=256))
    expiry = db.Column(db.DateTime)

    def __repr__(self):
        return str("[user_id: "+str(self.user_id)+" auth_token: "+self.token+"]")

class BlackList(db.Model):
    token = token = db.Column(db.String(length=256), primary_key=True)

    def __repr__(self):
        return str(self.token)    
