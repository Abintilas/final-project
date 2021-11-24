from hashlib import md5
from passlib.context import CryptContext 
from app.database import db
from app.models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")  
def create_admin():

    
    user = User.query.filter_by(email="admin@site.net").first()

    if user is None:
        
        user = User(
            username="admin",
            password=pwd_context.hash("passwords"),
            email="admin@site.net",
            is_admin=True
        )

        
        db.session.add(user)
        db.session.commit()
        print("super user admin set successfully")

    else:
        print("super user admin already exists")


