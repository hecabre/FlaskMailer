import os
from flask import Flask
from . import csrf

def create_app():
    app = Flask(__name__)
    app.config.from_mapping(
        FROM_EMAIL = os.environ.get('FROM_EMAIL'),
        SENDGRID_KEY = os.environ.get('SENDGRID_API_KEY'),
        DATABASE_HOST = os.environ.get('FLASK_DATABASE_HOST'),
        SECRET_KEY = os.environ.get("SECRET_KEY").encode(),
        DATABASE_PASSWORD = os.environ.get('FLASK_DATABASE_PASSWORD'),
        DATABASE_USER = os.environ.get('FLASK_DATABASE_USER'),
        DATABASE = os.environ.get('FLASK_DATABASE')
    )
    from . import db
    from . import email
    from . import auth
    app.register_blueprint(email.bp)
    app.register_blueprint(auth.bp)
    csrf.csrf.init_app(app)
    db.init_app(app)
    return app
