import json
import werkzeug
import secrets
import string

from pathlib import Path

from flask import Flask, render_template, redirect, request, session, abort
from flask_wtf.csrf import CSRFProtect

from models import db, User
from tools import login, widgets

app = Flask(__name__)
csrf = CSRFProtect()
csrf.init_app(app)

Path("persistent").mkdir(parents=True, exist_ok=True)

secret_key = Path("persistent/secret_key.txt")

if secret_key.exists():
    app.secret_key = secret_key.read_text()
else:
    app.secret_key = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
    secret_key.write_text(app.secret_key)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///persistent/db.sqlite'
db.init_app(app)

with app.app_context():
    db.create_all()

login_manager = login.LoginManager(User)

__version__ = '0.1.7'


@app.errorhandler(werkzeug.exceptions.HTTPException)
def handle_exception(e):
    """Return an error response"""
    return render_template("error.html", code=e.code, message=e.description, name=e.name), e.code


# -------------Login----------------
@app.get('/login')
def get_login():
    return render_template('login.html')


@app.post('/login')
def post_login():
    logged_in = login_manager.login(request.form['username'], request.form['password'])
    if logged_in:
        return redirect("/")
    else:
        return render_template('login.html')


@app.get('/register')
def get_register():
    return render_template('login.html')


@app.post('/register')
def post_register():
    if "username" not in request.form or "password" not in request.form:
        abort(400, "Missing username or password")

    user = User(request.form['username'], request.form['password'])
    db.session.add(user)
    db.session.commit()
    return redirect("/")


@app.get('/logout')
@login_manager.login_required
def get_logout():
    login_manager.logout()
    return redirect("/login")


# -------------Routes----------------
@app.get('/')
@login_manager.login_required
def home():
    try:
        config = json.loads(login_manager.get_user().homepage_config)
    except json.JSONDecodeError:
        abort(500, "Invalid JSON")
        return
    return render_template('home.html', config=config)


@app.get('/edit_config')
@login_manager.login_required
def get_edit_config():
    return render_template('edit_config.html', config=User.query.filter_by(id=session['user']).first().homepage_config)


@app.post('/edit_config')
@login_manager.login_required
def post_edit_config():
    user = User.query.filter_by(id=session['user']).first()
    config = request.form['config']
    try:
        config = json.loads(config)
    except json.JSONDecodeError:
        abort(400, "Invalid JSON")
        return

    user.homepage_config = json.dumps(config, indent=2)
    db.session.commit()
    return redirect("/")


# -------------Template Functions----------------
@app.context_processor
def utility_processor():
    def render_item(config):
        return widgets.Widget(config).render()
    return dict(render_item=render_item, version=__version__)


if __name__ == '__main__':
    app.run()
