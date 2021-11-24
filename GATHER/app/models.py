
from threading import Event
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



class RegistrationSports(db.Model):
    __tablename__ = 'RegistrationSports'
    sports_id= db.Column(db.Integer, primary_key=True)
    user_id= db.Column(db.Integer)
    event_name= db.Column(db.String(length=800))
    event_id= db.Column(db.Integer)

    def __repr__(self):
        return str("[sports_id: "+str(self.sports_id)+ " user_id: "+self.user_id+"]")


class Payments(db.Model):
    __tablename__ = 'Payments'
    payment_id= db.Column(db.Integer, primary_key=True)
    user_id=db.Column(db.Integer)
    sports_id= db.Column(db.Integer)
    payment_amount= db.Column(db.Integer)
    payment_withdrwal_status= db.Column(db.Boolean, default=False)

    def __repr__(self):
        return str("[user_id: "+str(self.payment_id)+"]")


class Message(db.Model):
    __tablename__ = 'Message'
    message_id= db.Column(db.Integer,  primary_key=True)
    admin_id= db.Column(db.Integer)
    user_id=db.Column(db.Integer)
    message= db.Column(db.String(length=800))

    def __repr__(self):
        return str("[message_id: "+str(self.message_id)+"]")
class CreateEvent(db.Model):
    __tablename__="create_event"
    event_id=db.Column(db.Integer,  primary_key=True)
    event_name=db.Column(db.String(length=800))
    amount=db.Column(db.Integer)
    
    def __repr__(self):
        return str("[event_id: "+str(self.event_id)+"event_name"+str(self.event_name)+"]")

class CreateEventRate(db.Model):
    __tablename__="create_Event_rating"
    event_id= db.Column(db.Integer, db.ForeignKey(CreateEvent.event_id), primary_key=True)
    rating=db.Column(db.Float)

    def __repr__(self):
        return str("[rating_id: "+str(self.event_id)+"rating"+str(self.rating)+"]")

class CreateUserRate(db.Model):
    __tablename__="create_user_rating"
    user_id= db.Column(db.Integer, db.ForeignKey(User.user_id), primary_key=True)
    rating=db.Column(db.Float)

    def __repr__(self):
        return str("[rating_id: "+str(self.user_id)+"rating"+str(self.rating)+"]")
