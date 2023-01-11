
from flask import Blueprint, render_template, get_flashed_messages, request, flash, redirect, url_for, current_app, session, g
from app.db import get_db
from flask_wtf.csrf import CSRFError
from sendgrid.helpers.mail import Mail
from sendgrid import SendGridAPIClient
import os
from app.auth import login_required

bp = Blueprint('email', __name__, url_prefix='/')


@bp.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("CSRF token not found, that is suspicious")


@bp.route('/', methods=['GET'])
def index():
    return render_template('mails/index.html')


@bp.route('/see_mails', methods=['GET'])
@login_required
def see_mails():
    search = request.args.get("search")
    db, c = get_db()
    if search is None:
        try:
            c.execute(
                'SELECT e.id, e.subject, u.email, e.content, e.sent_at'
                ' FROM EMAIL e JOIN MAILER_USERS u ON e.created_by = u.id WHERE e.created_by = %s ORDER BY sent_at DESC',
                (g.user['id'],)
            )
        except Exception as e:
            flash("Something go wrong try later")

    else:
        c.execute("SELECT * FROM email WHERE content LIKE %s",
                  (f'%{search}%',))

    mails = c.fetchall()

    return render_template('mails/see_mails.html', mails=mails, session=session, result=len(mails))


@bp.route('/create', methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        email = request.form.get('email')
        subject = request.form.get('subject')
        content = request.form.get('content')
        errors = []

        if not email or not subject or not content:
            errors.append("All fields are required")

        if len(errors) == 0:
            db, c = get_db()
            send(email, subject, content)
            c.execute("INSERT INTO email (email, subject, content, created_by) VALUES(%s, %s, %s, %s)",
                      (email, subject, content, g.user['id']))
            db.commit()
            return redirect(url_for('email.see_mails'))

        else:
            flash(errors)

    return render_template('mails/create.html')


def send(to, subject, content):
    message = Mail(
            from_email=os.environ.get('FROM_EMAIL'),
            to_emails=to,
            subject=subject,
            html_content='<strong> {} </strong>'.format(content)
        )
    try:
        sg = SendGridAPIClient(api_key=os.environ.get('SENDGRID_API_KEY'))
        sg.send(message)
        flash('Email sent to {}'.format(to))
        

    except Exception as e:
        flash("Something go wrong, try later")
