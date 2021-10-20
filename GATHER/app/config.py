import os
from flask import Flask

from app.database import db
from app.initdb import create_admin

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(basedir, "database.sqlite3")


app = Flask(__name__)

app.config['SECRET_KEY'] = '090d0a#sf808q0r0F080$e32Da'
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db.init_app(app)


if not os.path.exists(SQLALCHEMY_DATABASE_URI):
    
    db.app = app
    
    db.create_all()

    create_admin()
