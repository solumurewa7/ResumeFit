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
import uuid
from werkzeug.utils import secure_filename
from flask_wtf.file import FileField, FileAllowed, FileRequired
import pdfplumber
import docx
from flask import send_from_directory, abort


# -------------------- App + Config --------------------
load_dotenv()

app = Flask(__name__)
os.makedirs(app.instance_path, exist_ok=True)




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
db_path = os.getenv('DATABASE_URL') or ('sqlite:///' + os.path.join(app.instance_path, 'app.db'))
app.config['SQLALCHEMY_DATABASE_URI'] = db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# Token serializer for email verification
ts = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Login manager (NOTE: defined at module level, not inside the model)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # where to send users who need to log in



ALLOWED_EXTS = {'pdf', 'docx'}

app.config['UPLOAD_FOLDER'] = os.path.join(app.instance_path, 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# 5 MB upload limit (optional; can also come from .env)
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 5*1024*1024))




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







class Resume(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_path = db.Column(db.String(512), nullable=False)
    resume_text = db.Column(db.Text, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)










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



class ResumeForm(FlaskForm):
    file = FileField(
        'Upload resume (PDF/DOCX)',
        validators=[FileRequired(), FileAllowed(['pdf','docx'], 'PDF or DOCX only')]
    )



# -------------------- Extractors --------------------

def _extract_pdf_text(path):
    parts = []
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            parts.append(page.extract_text() or "")
    return "\n".join(parts).strip()

def _extract_docx_text(path):
    d = docx.Document(path)
    return "\n".join(p.text for p in d.paragraphs).strip()

def extract_text(path, ext):
    ext = ext.lower()
    if ext == 'pdf':
        return _extract_pdf_text(path)
    if ext == 'docx':
        return _extract_docx_text(path)
    raise ValueError("Unsupported file type")








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
    latest = Resume.query.filter_by(user_id=current_user.id)\
                         .order_by(Resume.uploaded_at.desc()).first()
    return render_template('dashboard.html', latest=latest)







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






def _allowed(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTS




@app.route('/resume', methods=['GET','POST'])
@login_required
def resume():
    if not current_user.is_verified:
        flash('Please verify your email first.', 'warning')
        return redirect(url_for('dashboard'))

    form = ResumeForm()
    latest = Resume.query.filter_by(user_id=current_user.id).order_by(Resume.uploaded_at.desc()).first()

    if form.validate_on_submit():
        f = form.file.data
        if not _allowed(f.filename):
            flash('Only PDF or DOCX allowed.', 'danger')
            return render_template('resume.html', form=form, latest=latest)

        ext = f.filename.rsplit('.', 1)[1].lower()
        safe = secure_filename(f.filename)
        dest_name = f"{uuid.uuid4().hex}_{safe}"
        dest_path = os.path.join(app.config['UPLOAD_FOLDER'], dest_name)
        f.save(dest_path)

        try:
            text = extract_text(dest_path, ext)
            if not text.strip():
                raise ValueError("Empty text extracted")
        except Exception as e:
            os.remove(dest_path)
            flash(f'Could not read file: {e}', 'danger')
            return render_template('resume.html', form=form, latest=latest)

        rec = Resume(
            user_id=current_user.id,
            original_filename=safe,
            stored_path=dest_path,
            resume_text=text
        )
        db.session.add(rec)
        db.session.commit()
        flash('Resume uploaded and parsed successfully!', 'success')
        return redirect(url_for('resume'))

    return render_template('resume.html', form=form, latest=latest)






@app.route('/resume/view/<int:resume_id>')
@login_required
def resume_view(resume_id):
    rec = Resume.query.get_or_404(resume_id)
    if rec.user_id != current_user.id:
        abort(403)
    # serve the stored file
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        os.path.basename(rec.stored_path),
        as_attachment=False # browser will preview PDFs, download DOCX
    )















with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
