from flask import Flask, request, render_template, jsonify
from flask_restful import Api, Resource

from hashlib import md5
import os
import requests
import jwt
import datetime

from app.config import app
from app.models import User, AuthToken, BlackList
from app.database import db


api = Api(app)

class ProfileEndpoint(Resource):
    def get(self):
        sent_token = request.headers.get("Authorization").split(" ")[1]
        
        black_token = BlackList.query.filter_by(token=sent_token).first()
        if black_token:
            db.session.delete(black_token)
            return "token expired,,,please login in again"
        
        valid_token = AuthToken.query.filter_by(token=f"{sent_token}").first()
        if valid_token:
            if datetime.datetime.utcnow() > valid_token.expiry:
                blacklist = BlackList()
                blacklist.token = valid_token.token
                db.session.delete(valid_token)
                db.session.commit()
                return "token expired,,,please login in again"
            else:
                user = User.query.filter_by(user_id=valid_token.user_id).first()
                return jsonify({"username": user.username, "email": user.email, "isAdmin": user.is_admin})
        else:
            return "invalid authentication token"

    def post(self):
        return "allowed methods: [GET]"


class LoginEndpoint(Resource):
    def get(self):
        return "allowed methods: [POST]"

    def post(self):
        try: 
            email = request.json.get("email").strip()
            password = md5((request.json.get("password").strip()).encode()).hexdigest()

        except Exception as e:
            print(str(e))

            return "user credentials not found"

        user = User.query.filter_by(email=email, password=password).first()
        if user is not None:
            jwt_token = generate_jwt_token({"user_id": user.user_id})

            new_token = AuthToken()
            new_token.user_id = user.user_id
            new_token.token = jwt_token
            new_token.expiry = datetime.datetime.utcnow() +datetime.timedelta(minutes=30) # change the minutes to a desirable duration
            db.session.add(new_token)
            db.session.commit()

            return create_auth_response(jwt_token, 200)
        else:
            return "invalid login credentials"


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

        new_user = User()
        new_user.username = username
        new_user.email = email
        new_user.password = md5(password.encode()).hexdigest()

        db.session.add(new_user)
        db.session.commit()

        jwt_token = generate_jwt_token({"user_id": new_user.user_id})
    
        return create_auth_response(jwt_token, 201)


api.add_resource(ProfileEndpoint, "/api/profile")
api.add_resource(LoginEndpoint, "/api/login")
api.add_resource(RegisterEndpoint, "/api/register")


def generate_jwt_token(payload):
    encoded = jwt.encode(payload, app.config.get("SECRET_KEY"), algorithm='HS256')
    token = encoded
    return token

def create_auth_response(token, status_code):
    response = jsonify(
        access_token = token,
        token_type = "bearer"
    )
    response.status_code = status_code
    return response


if __name__ == "__main__":
    app.run(debug=True)
##anyone can access , page anybody logged in can see, profile page certain people can see
