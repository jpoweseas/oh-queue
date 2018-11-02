from flask import Blueprint, abort, redirect, render_template, request, session, url_for
from flask_login import LoginManager, login_user, logout_user, current_user

from oh_queue.models import db, User

import os

auth = Blueprint('auth', __name__)
auth.config = {}

login_manager = LoginManager()

@auth.record
def record_params(setup_state):
    app = setup_state.app
    auth.course_offering = app.config.get('COURSE_OFFERING')
    auth.debug = app.config.get('DEBUG')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

def user_from_pennkey(name, pennkey, is_staff):
    """Get a User with the given pennkey, or create one."""
    user = User.query.filter_by(pennkey=pennkey).one_or_none()
    if not user:
        user = User(name=name, pennkey=pennkey, is_staff=is_staff)
    else:
        user.name = name
        user.is_staff = is_staff
    db.session.add(user)
    db.session.commit()
    return user

def refresh_user(as_staff = False):
    pennkey = os.environ.get('REMOTE_USER')
    if not pennkey:
        return False
    name = pennkey
    user = user_from_pennkey(name, pennkey, as_staff)
    login_user(user)
    return redirect(url_for('index'))

def set_user(pennkey, as_staff):
    if not auth.debug:
        abort(404)
    os.environ["REMOTE_USER"] = pennkey
    if refresh_user(as_staff=as_staff):
        return redirect(url_for('index'))
    else:
        return abort(404)

@auth.route('/set_user/<string:pennkey>')
def set_student(pennkey):
    return set_user(pennkey, False)

@auth.route('/set_staff/<string:pennkey>')
def set_staff(pennkey):
    return set_user(pennkey, True)

@auth.route('/login/')
def login():
    if refresh_user():
        return redirect(url_for('index'))
    else:
        return abort(404)

def init_app(app):
    app.register_blueprint(auth)
    login_manager.init_app(app)
