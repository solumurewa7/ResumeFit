from flask import Flask, render_template, redirect, url_for, flash
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
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
from wtforms import StringField, PasswordField, BooleanField, TextAreaField
import re
from wtforms import TextAreaField
from rapidfuzz import fuzz
import string
import json






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



class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)

    job_title = db.Column(db.String(255), nullable=True)
    company = db.Column(db.String(255), nullable=True)

    fit_percentage = db.Column(db.Float, nullable=False)
    fit_label = db.Column(db.String(20), nullable=False)

    matched_skills = db.Column(db.Text, nullable=False)  # JSON string list
    missing_skills = db.Column(db.Text, nullable=False)  # JSON string list

    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)











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

class AnalyzeForm(FlaskForm):
    job_title = StringField('Job Title')
    company = StringField('Company')
    jd_text = TextAreaField('Job Description', validators=[DataRequired()])



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








# ---------- Skills catalog & helpers ----------
TECH_SKILLS = [
    'python','java','c++','c','javascript','typescript','react','node',
    'html','css','sql','mysql','postgres','mongodb','linux','git',
    'aws','azure','gcp','docker','kubernetes','rest','api',
    'pandas','numpy','matplotlib','scikit-learn','tensorflow','pytorch',
    'oop','object oriented programming','data structures','algorithms','machine learning','deep learning',
    'cloud computing','cybersecurity','devops','agile methodologies','scrum','ci/cd','microservices','graphql','bash','shell scripting','jira','linux administration'
    ]
SOFT_SKILLS = [
    'communication','teamwork','leadership','problem solving',
    'time management','adaptability','collaboration','initiative'
]

# simple synonyms -> canonical
SYNONYMS = {
    'js': 'javascript',
    'ts': 'typescript',
    'ml': 'machine learning',
    'object-oriented programming': 'object oriented programming',
    'sql server': 'sql',
}

def _normalize(text: str) -> str:
    text = text.lower()
    text = re.sub(r'[^a-z0-9+\s]', ' ', text)  # keep + for C++
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def _apply_synonyms_to_normalized_text(t: str) -> str:
    """
    t must already be normalized (lowercase, punctuation stripped).
    Applies phrase synonyms first, then single-token synonyms.
    """
    # phrase replacements (keys with spaces)
    for k, v in SYNONYMS.items():
        k_norm = _normalize(k)
        v_norm = _normalize(v)
        if ' ' in k_norm and k_norm in t:
            t = re.sub(rf'\b{re.escape(k_norm)}\b', v_norm, t)

    # token replacements
    tokens = [SYNONYMS.get(tok, tok) for tok in t.split()]
    return " ".join(tokens)


def _canon(word: str) -> str:
    return SYNONYMS.get(word, word)

def extract_skill_hits(text: str):
    """Return a set of canonical skills found in text."""
    t = _normalize(text)
    t = _apply_synonyms_to_normalized_text(t)
    words = set(t.split())


    hits = set()
    # single-token hits
    for s in TECH_SKILLS + SOFT_SKILLS:
        s_norm = _normalize(s)
        if ' ' not in s_norm:
            if _canon(s_norm) in words:
                hits.add(_canon(s_norm))

    # multi-token phrases
    phrases = [s for s in TECH_SKILLS + SOFT_SKILLS if ' ' in s]
    for p in phrases:
        p_norm = _normalize(p)
        if p_norm in t:
            hits.add(_canon(p_norm))

    return hits

ALL_SKILLS = TECH_SKILLS + SOFT_SKILLS

def _present(skill: str, text: str, threshold: int = 80) -> bool:
    """Check if a skill is present in text using fuzzy matching."""
    skill_norm = _normalize(skill)
    text_norm = _normalize(text)
    return fuzz.partial_ratio(skill_norm, text_norm) >= threshold
 









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

    recent = Analysis.query.filter_by(user_id=current_user.id)\
                           .order_by(Analysis.created_at.desc()).limit(10).all()

    return render_template('dashboard.html', latest=latest, recent=recent)








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





@app.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze():
    form = AnalyzeForm()

    latest = Resume.query.filter_by(user_id=current_user.id)\
                         .order_by(Resume.uploaded_at.desc()).first()

    if not latest:
        flash("Upload a resume before analyzing a job.", "warning")
        return redirect(url_for('resume'))

    resume_text = latest.resume_text or ""

    if form.validate_on_submit():
        jd_text = form.jd_text.data or ""
        job_title = (form.job_title.data or "").strip() or None
        company = (form.company.data or "").strip() or None

        jd_skills = extract_skill_hits(jd_text)
        res_skills = extract_skill_hits(resume_text)

        matched_set = jd_skills & res_skills
        missing_set = jd_skills - res_skills

        matched = sorted(matched_set)
        missing = sorted(missing_set)

        total = len(jd_skills)
        if total == 0:
            flash("No recognizable skills found in the job description.", "warning")
            return redirect(url_for('analyze'))

        fit_pct = round(len(matched_set) / total * 100, 1)
        if fit_pct >= 70:
            fit_label = "Strong"
        elif fit_pct >= 40:
            fit_label = "Medium"
        else:
            fit_label = "Low"

        rec = Analysis(
            user_id=current_user.id,
            job_title=job_title,
            company=company,
            fit_percentage=fit_pct,
            fit_label=fit_label,
            matched_skills=json.dumps(matched),
            missing_skills=json.dumps(missing),
        )
        db.session.add(rec)
        db.session.commit()

        # keep last 10 analyses per user
        keep_n = 10
        old = Analysis.query.filter_by(user_id=current_user.id)\
                            .order_by(Analysis.created_at.desc())\
                            .offset(keep_n).all()
        for row in old:
            db.session.delete(row)
        db.session.commit()

        return redirect(url_for('analysis_detail', analysis_id=rec.id))

    return render_template('analyze.html', form=form, resume_present=True)




@app.route('/analysis/<int:analysis_id>')
@login_required
def analysis_detail(analysis_id):
    rec = Analysis.query.get_or_404(analysis_id)
    if rec.user_id != current_user.id:
        abort(403)

    matched = json.loads(rec.matched_skills) if rec.matched_skills else []
    missing = json.loads(rec.missing_skills) if rec.missing_skills else []
    required = sorted(set(matched) | set(missing))

    latest_resume = Resume.query.filter_by(user_id=current_user.id)\
                                .order_by(Resume.uploaded_at.desc()).first()
    resume_id = latest_resume.id if latest_resume else None

    return render_template(
        'analyze_result.html',
        job_title=rec.job_title,
        company=rec.company,
        fit_pct=rec.fit_percentage,
        fit_label=rec.fit_label,
        matched=matched,
        missing=missing,
        required=required,
        resume_id=resume_id
    )




with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
