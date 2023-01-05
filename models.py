import hashlib
import json

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    config = {
        "columns": [
            {
                "title": "Example",
                "elements": [
                    {
                        "title": "Github",
                        "link": "https://github.com/ozeliurs/ozeliurs",
                        "icon": "fab fa-github"
                    },
                    {
                        "title": "Resume",
                        "link": "https://www.ozeliurs.com",
                        "icon": "fas fa-file"
                    }
                ],
            }
        ]
    }

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(128), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    homepage_config = db.Column(db.String(10240), nullable=False, default=json.dumps(config, indent=2))

    def __init__(self, username, password):
        self.username = username
        self.password = hashlib.sha3_256(password.encode()).hexdigest()

    def check_password(self, password):
        return self.password == hashlib.sha3_256(password.encode()).hexdigest()
