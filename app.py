from flask import Flask, render_template, redirect, url_for, flash
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo
from dotenv import load_dotenv
import os
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer

from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)

# -------------------- App + Config --------------------
load_dotenv()

app = Flask(__name__)
os.makedirs(app.instance_path, exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'app.db')




app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-only-change-me')

# Mail (Mailtrap by default; overridable via .env)
app.config.update(
    MAIL_SERVER=os.getenv('MAIL_SERVER', 'sandbox.smtp.mailtrap.io'),
    MAIL_PORT=int(os.getenv('MAIL_PORT', 2525)),
    MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', 'True').lower() == 'true',
    MAIL_USE_SSL=os.getenv('MAIL_USE_SSL', 'False').lower() == 'true',
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=(
        os.getenv('MAIL_DEFAULT_SENDER_NAME', 'ResumeFit'),
        os.getenv('MAIL_DEFAULT_SENDER', 'no-reply@resumefit.app'),
    ),
)
mail = Mail(app)

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Token serializer for email verification
ts = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Login manager (NOTE: defined at module level, not inside the model)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # where to send users who need to log in

# -------------------- Models --------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

    def make_verify_token(self):
        return ts.dumps(self.email, salt='email-verify')

    @staticmethod
    def email_from_token(token, max_age=3600):
        try:
            return ts.loads(token, salt='email-verify', max_age=max_age)
        except Exception:
            return None

@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))

# -------------------- Forms --------------------
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    no_email = BooleanField('Continue without email verification', default=False)

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

# -------------------- Routes --------------------
@app.route('/')
def home():
    return 'Welcome to ResumeFit! (Home page placeholder)'

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        if form.no_email.data:
            flash('Continuing without email. Nothing stored.', 'info')
            return redirect(url_for('login'))

        existing = User.query.filter_by(email=email).first()
        if existing:
            flash('That email is already registered.', 'warning')
            return redirect(url_for('login'))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        token = user.make_verify_token()
        verify_link = url_for('verify_email', token=token, _external=True)

        try:
            msg = Message(
                subject='ResumeFit - Verify your email',
                recipients=[email],
                body=(
                    f'Hi {username},\n\n'
                    f'Click to verify your email:\n{verify_link}\n\n'
                    '(This link expires in 1 hour.)'
                )
            )
            mail.send(msg)
            flash('Account created! Check your email for a verification link.', 'success')
        except Exception as e:
            flash(f'Could not send verification email: {e}', 'danger')

        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/verify/<token>')
def verify_email(token):
    email = User.email_from_token(token)
    if not email:
        flash('Verification link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('No user found for that email.', 'danger')
        return redirect(url_for('login'))

    user.is_verified = True
    db.session.commit()
    flash('Email verified! You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user or not user.check_password(form.password.data):
            flash('Invalid credentials', 'danger')
            return render_template('login.html', form=form)

        if not user.is_verified:
            flash('Please verify your email first.', 'warning')
            return render_template('login.html', form=form)

        login_user(user)
        flash('Welcome back!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return f"Hello, {current_user.username}! (protected page)"

# ---- Dev helpers ----
@app.route('/dev/test-mail')
def dev_test_mail():
    try:
        msg = Message('ResumeFit test', recipients=['anything@example.com'], body='Hello from ResumeFit via Mailtrap!')
        mail.send(msg)
        return 'Sent! Check your Mailtrap inbox.'
    except Exception as e:
        return f'Failed to send: {e}', 500

@app.route('/dev/users')
def dev_users():
    rows = User.query.all()
    return "<br>".join([f"{u.id} | {u.email} | verified={u.is_verified}" for u in rows])

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
