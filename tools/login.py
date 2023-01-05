from flask import session, redirect, abort


class LoginManager:
    def __init__(self, user_db):
        self.user_db = user_db

    def login_required(self, f):
        def wrapper(*args, **kwargs):
            if self.is_logged_in():
                return f(*args, **kwargs)
            else:
                return redirect("/login")

        wrapper.__name__ = f"Login_required_{f.__name__}"   # This is to make sure the name of the function is unique
        return wrapper

    def admin_required(self, f):
        def wrapper(*args, **kwargs):
            if self.is_logged_in() and self.get_user().admin:
                return f(*args, **kwargs)
            else:
                abort(401, "You are not an admin")

        wrapper.__name__ = f"login_required_{f.__name__}"   # This is to make sure the name of the function is unique
        return wrapper

    def login(self, username, password):
        user = self.user_db.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user'] = user.id
            session['username'] = user.username
            return True
        else:
            return False

    def logout(self):
        session.pop('user', None)
        session.pop('username', None)
        return True

    def get_user(self):
        if "user" in session:
            return self.user_db.query.filter_by(id=session['user']).first()
        else:
            return False

    def is_logged_in(self):
        return "user" in session
