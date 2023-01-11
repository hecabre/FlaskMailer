import functools
from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for, session, current_app
)
from flask_wtf.csrf import CSRFError
from werkzeug.security import check_password_hash, generate_password_hash
from .db import get_db
import os


bp = Blueprint('mailer', __name__, url_prefix='/')


@bp.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("CSRF token not found, that is suspicious")
    return render_template('')

def cleaning_inputs(input):
    special_characters = ['%', '{', '}', '<', '>', '!', '$', '(', ')', '/', '\\']
    for i in str(input):
        if i in special_characters:
            error = 'Special characters are not accepted, try again with another username'
            flash(error)

def checking_email(email):
    if not "@" in email:
        error = 'The email needs a @'
        flash(error)

@bp.route('/register', methods=['GET', 'POST'])
def register():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            password_2 = request.form['password_2']
            username = request.form['username']
            print(os.environ.get("SECRET_KEY"))
            db, c = get_db()
            error = None
            c.execute(
                'SELECT id FROM mailer_users WHERE email = %s OR username = %s', (email, username)
            )

            if not username and not email and not password and not password_2:
                error = 'All the inputs are necessary'
                
            if password != password_2:
                error = 'The passwords are not the same'

            if len(password) <= 6:
                error = 'Password must be longer than 6 characters'
                
            elif c.fetchone() is not None:
                error = 'The users already exists'
            
            cleaning_inputs(username)
            checking_email(str(email))

            if error is None:
                c.execute(
                    'INSERT INTO mailer_users (email, username, password) VALUES(%s, %s, %s)',
                    (email, username, generate_password_hash(password))
                )
                db.commit()

                return redirect(url_for('mailer.login'))

            flash(error)
        return render_template('auth/register.html')


@bp.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        cleaning_inputs(email)
        db, c = get_db()
        error = None
        c.execute(
            'select * from mailer_users where email = %s or username = %s', (email, email)
        )
        user = c.fetchone()
        if user is None:
            error = 'Email / Username / Password is incorrect'
        
        elif not check_password_hash(user['password'], password):
            error = 'Email / Username / Password is incorrect'
        
        if error is None:
            session.clear()
            session['mailer_users_id'] = user['id']
            return redirect(url_for('email.see_mails'))

        flash(error)
    return render_template('auth/login.html')


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('mailer.login'))


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('mailer_users_id')
    if user_id is None:
        g.user = None
    
    else:
        db, c = get_db()
        c.execute(
            'SELECT * FROM mailer_users WHERE ID = %s', (user_id,)
        )    
        g.user = c.fetchone()


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('mailer.login'))
        
        return view(**kwargs)

    return wrapped_view



