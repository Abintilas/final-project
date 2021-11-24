from flask import request, jsonify
from flask_restful import Api, Resource
from passlib.context import CryptContext 
import jwt
import datetime
from app.config import app
from app.models import  User, AuthToken, Message, RegistrationSports, Payments, CreateEvent, CreateEventRate, CreateUserRate
from app.database import db





api = Api(app)



pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto") 


class RegisterEndpoint(Resource):
    def get(self):
        return "allowed methods: [POST]"

    def post(self):
        try:       
            username = request.json.get("username").strip()
            email = request.json.get("email").strip()
            password = request.json.get("password").strip()

        except Exception as e:
            print(str(e))
            return "failed to retrieve credentials"

        check_validation=unique_username_email(username,email)
        if check_validation[0]==False:
            return check_validation[1]
        new_user = User()
        new_user.username = username
        new_user.email = email
        new_user.password = pwd_context.hash(password)
        db.session.add(new_user)
        db.session.commit()

        jwt_token = generate_jwt_token({"user_id": new_user.user_id})
    
        return jsonify(create_auth_response(jwt_token, 201))

class LoginEndpoint(Resource):
    def get(self):
        return "allowed methods: [POST]"

    def post(self):
        try:
             
            email = request.json.get("email").strip()
            user=User.query.filter_by(email=email).first()
            password=pwd_context.verify(request.json.get("password").strip(),user.password) 
        except Exception as e:
            print(str(e))

            return "user credentials not found"

        if password:
            user = User.query.filter_by(email=email).first()
        else: 
            user= None
            return "Wrong Credential"
        if user is not None:
            jwt_token = generate_jwt_token({"user_id": user.user_id})

            
            new_token = AuthToken()
            token_available=AuthToken.query.filter_by(user_id=user.user_id)
            if token_available:
                AuthToken.query.filter_by(user_id=user.user_id).delete()
            new_token.user_id = user.user_id
            new_token.token = jwt_token
            new_token.expiry = datetime.datetime.utcnow() +datetime.timedelta(minutes=30) 
            db.session.add(new_token)
            db.session.commit()

            return jsonify(create_auth_response(jwt_token, 200))
        else:
            return "invalid login credentials"

class LogoutEndpoint(Resource):
    def get(self):
        sent_token = request.headers.get("Authorization").split(" ")[1]   
        print(sent_token)     
        valid_token = AuthToken.query.filter_by(token=f"{sent_token}").first()
        if valid_token:        
            if datetime.datetime.utcnow() > valid_token.expiry:
                AuthToken.query.filter_by(token=f"{sent_token}").delete()
                db.session.commit() 
                return "you logout sucessfully!"            
            else:               
                AuthToken.query.filter_by(token=f"{sent_token}").delete()
                db.session.commit() 
                return "you logout sucessfully!" 
        else:
            return "invalid authentication token"  
           
    def post(self):
        return "allowed methods: [gets]"

class ProfileEndpoint(Resource):
    def get(self):
        sent_token = request.headers.get("Authorization").split(" ")[1]
        print(sent_token)        
        valid_token = AuthToken.query.filter_by(token=f"{sent_token}").first()
        if valid_token:        
            if datetime.datetime.utcnow() > valid_token.expiry:
                user=AuthToken.query.filter_by(token=f"{sent_token}").first()
                if user is not None:
                    jwt_token = generate_jwt_token({"user_id": user.user_id})
                    new_token = AuthToken()
                    AuthToken.query.filter_by(token=f"{sent_token}").delete()
                    new_token.user_id = user.user_id
                    new_token.token = jwt_token
                    new_token.expiry = datetime.datetime.utcnow() +datetime.timedelta(minutes=30) 
                    db.session.add(new_token)
                    db.session.commit()
                    response=create_auth_response(jwt_token, 200)
                    response["message"] = "your token is updated"  
                    return jsonify(response)             
            else:               
                user = User.query.filter_by(user_id=valid_token.user_id).first()
                return jsonify({"username": user.username, "email": user.email, "isAdmin": user.is_admin})
        else:
            return "invalid authentication token"

    def post(self):
        return "allowed methods: [GET]"






class PostMessageEndPoint(Resource):
    def get(self):
        return "allowed post method"
    def post(self):
        sent_token=request.headers.get("Authorization").split(" ")[1]
        valid_token = AuthToken.query.filter_by(token=f"{sent_token}").first()
        if valid_token: 
            if datetime.datetime.utcnow() > valid_token.expiry:
                return "token expired,,,please login in again"
            else:
                user=User.query.filter_by(user_id=valid_token.user_id).first()
                if user.is_admin:
                    new_message=Message()
                    new_message.admin_id=valid_token.user_id
                    new_message.user_id=request.json.get("user_id")
                    new_message.message=request.json.get("message")
                    db.session.add(new_message)
                    db.session.commit()
                    return "your message get to user! Thank you for time"
                else:
                    return "Sorry! you are not admin"
        else:
            return "invalid authentication token"

class GetMessageEndpoint(Resource):
    def get(self):
        sent_token = request.headers.get("Authorization").split(" ")[1]          
        valid_token = AuthToken.query.filter_by(token=f"{sent_token}").first()
        if valid_token:       
            if datetime.datetime.utcnow() > valid_token.expiry:
                return "token expired,,,please login in again"
            else:      
                try:          
                    message=Message.filter_by(user_id=valid_token.user_id).first()
                    return jsonify({"message": message.message})
                except:
                    return "No messgae for you"
        else:
            return "invalid authentication token"

    def post(self):
        return "allowed methods: [GET]"
class GetAllEventEndPoint(Resource):
    def get(self):
        event_list=CreateEvent.query.all()
        event_dict={"event":[]}
        for event in event_list:
            temp_event={"event_id":event.event_id, "event_name": event.event_name, "amount":event.amount }
            li=event_dict.get("event")
            li.append(temp_event)
            event_dict["event"]=li
        return jsonify(event_dict)  
    def post(self):
        return "[Get] method allowed"  

class RegisterForSportEndPoint(Resource):
    def get(self):
      return "[Post] method allowed"

    def post(self):
        sent_token=request.headers.get("Authorization").split(" ")[1]
        sent_token = request.headers.get("Authorization").split(" ")[1]          
        valid_token = AuthToken.query.filter_by(token=f"{sent_token}").first()
        if valid_token:       
            if datetime.datetime.utcnow() > valid_token.expiry:
                return "token expired,,,please login in again"
            else:      
                try:          
                    event_id_=request.json.get("event_id")
                    event=CreateEvent.query.filter_by(event_id=event_id_).first()
                    if event:
                        pass
                    else:
                        return "your event id does not exist"
    
                    register_sport= RegistrationSports()
                    user=RegistrationSports.query.filter_by(user_id=valid_token.user_id).all()

                    if user:
                        try:
                            user_event=[]
                            for register_event in user:
                                user_event.append(register_event.event_id)
                            if user_event.index(event_id_)>=0:
                                return "you are already register for "+ str(event_id_)+" event id"
                        except:
                            pass
                    register_sport.user_id=valid_token.user_id
                    register_sport.event_id=event.event_id
                    register_sport.event_name=event.event_name
                    db.session.add(register_sport)
                    db.session.commit()
                    payment=Payments()
                    payment.sports_id=register_sport.sports_id
                    payment.user_id=valid_token.user_id
                    payment.payment_amount= event.amount
                    db.session.add(payment)
                    db.session.commit()
                    return "you register succesfully! Next step is payment"
                except:
                    return "Your registration is not succesfull"
        else:
            return "invalid authentication token"
class GetPaymentStatusEndPoint(Resource):
    
    def get(self):
        sent_token = request.headers.get("Authorization").split(" ")[1]          
        valid_token = AuthToken.query.filter_by(token=f"{sent_token}").first()
        if valid_token:       
            if datetime.datetime.utcnow() > valid_token.expiry:
                return "token expired,,,please login in again"
            else:
                try:
                    user_payment=Payments.query.filter_by(user_id=valid_token.user_id).all()
                    payment_li={"payment":[]}
                    if user_payment:
                        for payment in user_payment:
                            temp_pay=payment_li.get("payment")
                            status=payment.payment_withdrwal_status
                            if status:
                                status="success"
                            else:
                                status="not success"
                            print(temp_pay)
                            temp_pay.append({"payment_id":payment.payment_id,"amount": payment.payment_amount, "payment_status": status})
                            payment_li["payment"]=temp_pay
                        return payment_li
                    return "you have to done registration first"
                except:
                   pass
                return "Error from server side"
        else:
            return "invalid authentication token"
    def post(self):
      return "[get] method allowed"


class PaymentProcess(Resource):
    def get(self):
      return "[Post] method allowed"
    def post(self):
        sent_token=request.headers.get("Authorization").split(" ")[1]         
        valid_token = AuthToken.query.filter_by(token=f"{sent_token}").first()
        if valid_token:       
            if datetime.datetime.utcnow() > valid_token.expiry:
                return "token expired,,,please login in again"
            else:
                try:
                    user_payment=Payments.query.filter_by(user_id=valid_token.user_id).all()
                    payment_id=request.json.get("payment_id")
                    if user_payment:
                        li_payment_id=[]
                        for payment in user_payment:
                            li_payment_id.append(payment.payment_id)
                        if li_payment_id.index(payment_id)>=0:
                            Payments.query.filter_by(payment_id=payment_id).update(dict(payment_withdrwal_status=True))
                            db.session.commit()
                            return "your payment is successful"
                        else:
                            return "Your payment id is wrong  "                
                    else:
                        return "you have to done registraion first"

                except:
                    return "Your payment id is wrong  " 
        else:
            return "invalid authentication token"


class CreateEventEndPoint(Resource):
    def get(self):
        return "[Post] Method Allowed"      
    def post(self):
        sent_token=request.headers.get("Authorization").split(" ")[1]
        sent_token = request.headers.get("Authorization").split(" ")[1]          
        valid_token = AuthToken.query.filter_by(token=f"{sent_token}").first()
        if valid_token:
            if datetime.datetime.utcnow() > valid_token.expiry:
                return "token expired,,,please login in again"
            else:
                user = User.query.filter_by(user_id=valid_token.user_id).first()
                try: 
                    event_id_=request.json.get("event_id")
                    event_name=request.json.get("event_name")
                    amount=request.json.get("amount")
                except:
                    return "error arise in request data create event "
                if user.is_admin:
                    event=CreateEvent()
                    valid_event = CreateEvent.query.filter_by(event_id=event_id_).first()
                    if valid_event:
                        CreateEvent.query.filter_by(event_id=event_id_).update(dict(event_name=event_name))
                        CreateEvent.query.filter_by(event_id=event_id_).update(dict(amount=amount))
                        db.session.commit()
                        return "your event updated successfully"
                    else:
                        event.event_id=event_id_
                        event.event_name=event_name
                        event.amount=amount
                        db.session.add(event)
                    
                    db.session.commit()
                    return "Your event register successful"
                else:
                    return "you are not a admin"
        return "your token credential failed."

class DeleteEventEndPoint(Resource):
    def get(self):
        return "[Post] Method Allowed"

    def post(self):
        sent_token=request.headers.get("Authorization").split(" ")[1]
        sent_token = request.headers.get("Authorization").split(" ")[1]          
        valid_token = AuthToken.query.filter_by(token=f"{sent_token}").first()
        if valid_token:
            if datetime.datetime.utcnow() > valid_token.expiry:
                return "token expired,,,please login in again"
            else:
                user = User.query.filter_by(user_id=valid_token.user_id).first()
                try: 
                    event_id_=request.json.get("event_id")
                except:
                    return "error arise in request data create event "
                if user.is_admin:
                    event=CreateEvent()
                    valid_event = CreateEvent.query.filter_by(event_id=event_id_).first()
                    if valid_event:
                        CreateEvent.query.filter_by(event_id=event_id_).delete()
                        db.session.commit()
                    else:
                       return "The event id does not exist"
                    
                    
                    return "Your event delete successfully"
                else:
                    return "you are not a admin"
        return "your token credential failed."
class GetEventRatingEndPoint(Resource):
    def get(self):
        event_list=CreateEventRate.query.all()
        event_dict={"Rate":[]}
        for event in event_list:
            temp_event={"event_id":event.event_id, "rating": event.rating}
            li=event_dict.get("Rate")
            li.append(temp_event)
            event_dict["Rate"]=li
        return jsonify(event_dict) 
    def post(self):
        return "[Get] Method allowed"
class CreateEventRateEndPoint(Resource):
    def get(self):
        return "[post] method allowed"
    def post(self):
        sent_token=request.headers.get("Authorization").split(" ")[1]
        sent_token = request.headers.get("Authorization").split(" ")[1]          
        valid_token = AuthToken.query.filter_by(token=f"{sent_token}").first()
        if valid_token:
            if datetime.datetime.utcnow() > valid_token.expiry:
                return "token expired,,,please login in again"
            else:
                user = User.query.filter_by(user_id=valid_token.user_id).first()
                try: 
                    event_id_=request.json.get("event_id")
                    rating=request.json.get("rating")
                    event=CreateEvent.query.filter_by(event_id=event_id_).first()
                    if event:
                        pass
                    else:
                        return "event does not exist"
                except:
                    return "error arise in request data "
                rate=CreateEventRate.query.filter_by(event_id=event_id_).first()
                rate_value=0
                if rate:
                    rate_value=rate.rating
                    rate_value=(rate_value+rating)/2
                    CreateEventRate.query.filter_by(event_id=event_id_).update(dict(rating=rate_value))
                    db.session.commit()
                    return "your rate successfully updated/added"
                else:
                    rate_db=CreateEventRate()
                    rate_db.event_id=event_id_
                    rate_db.rating=rating
                    db.session.add(rate_db)
                    db.session.commit()
                    return "you rate succesfully added/updated"
        return "your token credential failed."
class GetUserRatingEndPoint(Resource):
    def get(self):
        user_list=CreateUserRate.query.all()
        user_dict={"Rate":[]}
        for user in user_list:
            temp_user={"user_id":user.user_id, "rating": user.rating}
            li=user_dict.get("Rate")
            li.append(temp_user)
            user_dict["Rate"]=li
        return jsonify(user_dict) 
    def post(self):
        return "[Get] Method allowed"
class CreateUserRateEndPoint(Resource):
    def get(self):
        return "[post] method allowed"
    def post(self):
        sent_token=request.headers.get("Authorization").split(" ")[1]
        sent_token = request.headers.get("Authorization").split(" ")[1]          
        valid_token = AuthToken.query.filter_by(token=f"{sent_token}").first()
        if valid_token:
            if datetime.datetime.utcnow() > valid_token.expiry:
                return "token expired,,,please login in again"
            else:
                user = User.query.filter_by(user_id=valid_token.user_id).first()
                try: 
                    user_id_=request.json.get("user_id")
                    rating=request.json.get("rating")
                    user=User.query.filter_by(user_id=user_id_).first()
                    if user:
                        pass
                    else:
                        return "user does not exist"
                except:
                    return "error arise in request data "
                rate=CreateUserRate.query.filter_by(user_id=user_id_).first()
                rate_value=0
                if rate:
                    rate_value=rate.rating
                    rate_value=(rate_value+rating)/2
                    CreateUserRate.query.filter_by(user_id=user_id_).update(dict(rating=rate_value))
                    db.session.commit()
                    return "your rate successfully updated/added"
                else:
                    rate_db=CreateUserRate()
                    rate_db.user_id=user_id_
                    rate_db.rating=rating
                    db.session.add(rate_db)
                    db.session.commit()
                    return "you rate succesfully added/updated"
        return "your token credential failed."


api.add_resource(RegisterEndpoint, "/api/register")
api.add_resource(LoginEndpoint, "/api/login")
api.add_resource(LogoutEndpoint,'/api/logout')
api.add_resource(ProfileEndpoint, "/api/profile")
api.add_resource(PostMessageEndPoint, "/api/writemessage")
api.add_resource(GetMessageEndpoint, "/api/message")
api.add_resource(CreateEventEndPoint,"/api/createevent")
api.add_resource(GetAllEventEndPoint,"/api/getevent")
api.add_resource(DeleteEventEndPoint,"/api/deleteevent")
api.add_resource(RegisterForSportEndPoint,"/api/sportsregistration")
api.add_resource(GetPaymentStatusEndPoint,"/api/paymentstatus")
api.add_resource(PaymentProcess,"/api/paymentprocess")
api.add_resource(GetEventRatingEndPoint,"/api/eventrate")
api.add_resource(CreateEventRateEndPoint,"/api/eventratee")
api.add_resource(GetUserRatingEndPoint,"/api/userrate")
api.add_resource(CreateUserRateEndPoint,"/api/userratee")






def generate_jwt_token(payload):
    encoded = jwt.encode(payload, app.config.get("SECRET_KEY"), algorithm='HS256')
    token = encoded
    return token

def create_auth_response(token, status_code):
    response = {
        'access_token' : token,
        'token_type' : "bearer",
        'status-code': 200
    }

    return response

def unique_username_email(user_name, email_id):
    valid=User.query.filter_by(username=f"{user_name}").first()
    if valid:
        return [False, "username exist"]
    valid=User.query.filter_by(email=f"{email_id}").first()    
    if valid:
        return [False, "email exist"]
    return [True]


def create_event():
    return [
        {"Event-id": 1,"Event-Name": "BaseBall"},
        {"Event-id": 2,"Event-Name":"FootBall"},
        {"Event-id": 3,"Event-Name":"Cricket"},
        {"Event-id": 4,"Event-Name":"Swimming"},
        {"Event-id": 5,"Event-Name":"Chess"}]

def create_payment():
    return [
        {"Event-id": 1,"Amount": "$900"},
        {"Event-id": 2,"Amount":"$1000"},
        {"Event-id": 3,"Amount":"$1500"},
        {"Event-id": 4,"Amount":"$800"},
        {"Event-id": 5,"Amount":"$50"}]

if __name__ == "__main__":
    app.run(debug=True)

