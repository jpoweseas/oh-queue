import datetime
import pytz

from flask import jsonify, render_template, render_template_string, request
from flask_login import current_user, login_required

from oh_queue import app, db, socketio
from oh_queue.models import Ticket, TicketStatus

def render_ticket(ticket, assist):
    template = app.jinja_env.get_template('ticket.html')
    return template.render(
        current_user=current_user,
        ticket=ticket,
        assist=assist,
    )

def return_payload(ticket):
    return {
        'id': ticket.id,
        'name': current_user.name,
        'add_date': format_datetime(ticket.created),
        'location': ticket.location,
        'assignment': ticket.assignment,
        'question': ticket.question,
        'html': render_ticket(ticket, assist=False),
        'assist_html': render_ticket(ticket, assist=True),
    }

def pending_tickets():
     return Ticket.query.filter_by(
        status=TicketStatus.pending,
    ).order_by(Ticket.created).all()

@app.route("/")
@login_required
def index():
    tickets = pending_tickets()
    return render_template('main.html', tickets=tickets, date=datetime.datetime.now())


@app.route("/assist")
@login_required
def assist():
    tickets = pending_tickets()
    return render_template('assist.html', tickets=tickets, date=datetime.datetime.now())

@app.route('/add_ticket', methods=['POST'])
def add_ticket():
    """Stores a new ticket to the persistent database, and emits it to all
    connected clients.
    """
    if not current_user.is_authenticated:
        abort(403)
    # Create a new ticket and add it to persistent storage
    ticket = Ticket(
        status=TicketStatus.pending,
        user_id=current_user.id,
        assignment=request.form['assignment'],
        question=request.form['question'],
        location=request.form['location'],
    )
    db.session.add(ticket)
    db.session.commit()

    # Emit the new ticket to all clients
    socketio.emit('add_ticket_response', return_payload(ticket))
    return jsonify(result='success')

@app.route('/resolve_ticket', methods=['POST'])
def resolve_ticket():
    if not current_user.is_authenticated:
        abort(403)
    ticket_id = request.form['id']

    ticket = Ticket.query.get(ticket_id)
    ticket.status = TicketStatus.resolved
    ticket.helper_id = current_user.id
    db.session.commit()

    socketio.emit('resolve_ticket_response', return_payload(ticket))
    return jsonify(result='success')

# Filters

db_timezone = pytz.timezone(app.config['DB_TIMEZONE'])
local_timezone = pytz.timezone(app.config['LOCAL_TIMEZONE'])

@app.template_filter('datetime')
def format_datetime(timestamp):
    tz_aware = db_timezone.localize(timestamp)
    return tz_aware.astimezone(local_timezone).strftime('%I:%M %p')
