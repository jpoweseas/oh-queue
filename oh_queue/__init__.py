import logging
logging.basicConfig(level=logging.INFO)

# Flask-related stuff
from flask import Flask, request
from flask_socketio import SocketIO

from oh_queue import assets, auth
from oh_queue.models import db, TicketStatus
from raven.contrib.flask import Sentry

from flask_login import login_user, current_user

# Initialize the application
app = Flask(__name__)
app.config.from_object('config')

if not app.debug:
    sentry = Sentry(app,
                    dsn='https://58883f34f9e5457cbe973fe9cffb0ba7:92a99d56e13b447a98f7e449efbcee16@sentry.cs61a.org/4')

app.jinja_env.globals.update({
  'TicketStatus': TicketStatus,
  'assets_env': assets.assets_env,
  'course_name': app.config['COURSE_NAME']
})

db.init_app(app)
auth.init_app(app)
socketio = SocketIO(app)

# Import views
import oh_queue.views

# Caching
@app.after_request
def after_request(response):
    if request.path.startswith('/static') and not app.config.get('DEBUG'):
        cache_control = 'max-age=31556926'
    else:
        cache_control = 'no-store'
    response.headers.add('Cache-Control', cache_control)
    return response
