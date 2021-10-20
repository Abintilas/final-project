from hashlib import md5

from app.database import db
from app.models import User

 
def create_admin():

    user = User.query.filter_by(email="admin@site.net").first()

    if user is None:
        
        user = User(
            username="admin",
            password=md5("password".encode()).hexdigest(),
            email="admin@site.net",
            is_admin=True
        )

        db.session.add(user)
        db.session.commit()
        print("super user admin set successfully")

    else:
        print("super user admin already exists")


