from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
import sqlite3
import os
from datetime import datetime
import uuid
import json
from io import BytesIO
try:
    from xhtml2pdf import pisa  # optional
    _PDF_ENABLED = True
except Exception:
    pisa = None
    _PDF_ENABLED = False

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')  # Change this to a secure secret key
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_DIR', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB total per request
DATA_DIR = os.environ.get('DATA_DIR', 'data')
DRAFTS_DIR = os.environ.get('DRAFTS_DIR', 'drafts')
DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'auth.db'))
ALLOWED_STATUSES = [
    'Pending with HR-Immigration',
    'Work in Progress-Internal',
    'Work in Progress - DOL',
    'Work in Process - Recruitment',
    'Approved',
    'Denied',
]

# ------- Helper mappers for friendlier labels in submission views -------
EDU_LABELS = {
    'university': 'School/University',
    'degree': 'Degree',
    'major': 'Major Field of Study',
    'date': 'Date Conferred',
}
EDU_ORDER = ['university', 'degree', 'major', 'date']

WB_LABELS = {
    'employer': 'Employer',
    'addr1': 'Address Line 1',
    'addr2': 'Address Line 2',
    'country': 'Country',
    'state': 'State',
    'city': 'City',
    'zip': 'Zip Code',
    'title': 'Job Title',
    'start': 'Start Date',
    'fulltime': 'Full Time?',
    'end': 'End Date',
    'manager': "Manager's Name",
    'phone': 'Employer Phone',
    'duties': 'Job Duties',
    'skills': 'Skills Required',
}
WB_ORDER = ['employer','addr1','addr2','country','state','city','zip','title','start','fulltime','end','manager','phone','duties','skills']

def _friendly(name: str) -> str:
    return name.replace('_', ' ').title()

def _extract_block_entries(fields: dict, prefix: str, labels: dict, order: list):
    """Extract entries by index for fields like 'edu[1][school]' into
    [ { 'index': 1, 'items': [(Label, value), ...] }, ... ]"""
    groups = {}
    for k, v in (fields or {}).items():
        if not isinstance(k, str) or not k.startswith(f"{prefix}["):
            continue
        try:
            rest = k[len(prefix)+1:]  # after prefix[
            idx_str, remainder = rest.split(']', 1)
            idx = int(idx_str)
            # remainder expected like '[field]...' take inner name between next [ ]
            if remainder.startswith('['):
                inner = remainder[1:]
                inner = inner.split(']', 1)[0]
            else:
                inner = remainder
        except Exception:
            continue
        entry = groups.setdefault(idx, {})
        entry[inner] = v
    # transform
    result = []
    for idx in sorted(groups.keys()):
        entry = groups[idx]
        items = []
        # ordered first
        for key in order:
            if key in entry:
                items.append((labels.get(key, _friendly(key)), entry.get(key, '')))
        # remaining keys
        for key in entry.keys():
            if key not in order:
                items.append((labels.get(key, _friendly(key)), entry.get(key, '')))
        result.append({ 'index': idx, 'items': items })
    return result

import re

def _collect_draft_uploads_from_fs(user_id: str):
    """Scan uploads folder for files saved via autosave_uploads pattern
    'draft_{user}_{key}_{uuid}_{orig}'. Return dict key -> [filenames]."""
    out = {}
    try:
        uid = str(user_id)
        prefix = f"draft_{uid}_"
        pat = re.compile(rf"^draft_{re.escape(uid)}_(.+?)_[0-9a-fA-F]{{32}}_.*$")
        for name in os.listdir(app.config['UPLOAD_FOLDER']):
            if not name.startswith(prefix):
                continue
            m = pat.match(name)
            if not m:
                continue
            key = m.group(1)
            out.setdefault(key, []).append(name)
    except Exception:
        return {}
    return out

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(DRAFTS_DIR, exist_ok=True)

# ---------- Auth (sqlite3) ----------
class User(UserMixin):
    def __init__(self, id, email, name, role, password_hash):
        self.id = str(id)
        self.email = email
        self.name = name
        self.role = role
        self.password_hash = password_hash

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('applicant','hr')),
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()

init_db()

def row_to_user(row):
    if not row:
        return None
    return User(row['id'], row['email'], row['name'], row['role'], row['password_hash'])

@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return row_to_user(row)

def find_user_by_email(email):
    conn = get_db()
    row = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    return row_to_user(row)

def create_user(email, name, password, role='applicant'):
    ph = generate_password_hash(password)
    conn = get_db()
    conn.execute(
        'INSERT INTO users (email, name, password_hash, role, created_at) VALUES (?,?,?,?,?)',
        (email, name, ph, role, datetime.utcnow().isoformat() + 'Z')
    )
    conn.commit()
    row = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    return row_to_user(row)

@app.route('/')
@login_required
def index():
    # Load any existing draft for this user to hydrate form immediately
    draft_fields = {}
    is_locked = False
    lock_meta = {}
    try:
        path = os.path.join(DRAFTS_DIR, f"{current_user.id}.json")
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            draft_fields = data.get('fields', {}) or {}
            is_locked = bool(data.get('locked'))
            if is_locked:
                # pick up latest status/case from the submission file if present
                lock_meta = {
                    'case_number': data.get('case_number'),
                    'submission_id': data.get('submission_id'),
                    'status': data.get('status') or 'Pending with HR-Immigration'
                }
                try:
                    sid = lock_meta.get('submission_id')
                    if sid:
                        s_path = os.path.join(DATA_DIR, f"{sid}.json")
                        if os.path.exists(s_path):
                            with open(s_path, 'r', encoding='utf-8') as sf:
                                srec = json.load(sf)
                            lock_meta['status'] = srec.get('meta', {}).get('status', lock_meta['status'])
                            lock_meta['case_number'] = srec.get('meta', {}).get('case_number', lock_meta['case_number'])
                except Exception:
                    pass
    except Exception:
        draft_fields = {}
    # Find submissions for this applicant (to list on home)
    last_submission = None
    all_submissions = []
    try:
        latest_ts = ''
        for name in os.listdir(DATA_DIR):
            if not name.endswith('.json'):
                continue
            p = os.path.join(DATA_DIR, name)
            with open(p, 'r', encoding='utf-8') as f:
                rec = json.load(f)
            u = (rec.get('user') or {}).get('id')
            if str(u) != str(current_user.id):
                continue
            meta = rec.get('meta', {}) or {}
            ts = meta.get('submitted_at') or ''
            all_submissions.append({
                'id': rec.get('id'),
                'case_number': meta.get('case_number') or '',
                'status': meta.get('status') or 'Pending with HR-Immigration',
                'submitted_at': ts,
            })
            if ts > latest_ts:
                latest_ts = ts
                last_submission = {
                    'id': rec.get('id'),
                    'case_number': meta.get('case_number') or '',
                    'status': meta.get('status') or 'Pending with HR-Immigration',
                    'submitted_at': ts,
                }
        # Sort all submissions descending by submitted_at
        all_submissions.sort(key=lambda r: r.get('submitted_at') or '', reverse=True)
    except Exception:
        last_submission = None
        all_submissions = []
    return render_template('index.html', draft_fields=draft_fields, is_locked=is_locked, lock_meta=lock_meta, last_submission=last_submission, all_submissions=all_submissions)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        name = (request.form.get('name') or '').strip()
        password = request.form.get('password')
        role = 'applicant'
        access_code = (request.form.get('access_code') or '').strip()
        # Optional HR access code via env var HR_ACCESS_CODE
        if access_code and access_code == os.environ.get('HR_ACCESS_CODE', ''):
            role = 'hr'
        if not email or not name or not password:
            flash('All fields are required.', 'error')
            return render_template('login.html', mode='register')
        if find_user_by_email(email):
            flash('Email already registered.', 'error')
            return render_template('login.html', mode='register')
        user = create_user(email, name, password, role)
        login_user(user)
        flash('Registration successful.', 'success')
        return redirect(url_for('index'))
    return render_template('login.html', mode='register', show_hr=False)

@app.route('/register_hr', methods=['GET'])
def register_hr():
    return render_template('login.html', mode='register', show_hr=True)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password')
        user = find_user_by_email(email)
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid email or password.', 'error')
            return render_template('login.html', mode='login')
        login_user(user)
        nxt = request.args.get('next')
        if nxt:
            return redirect(nxt)
        # HR users land on Admin by default
        if user.role == 'hr':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('index'))
    return render_template('login.html', mode='login')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/logout_confirm')
@login_required
def logout_confirm():
    # Simple confirmation page to avoid relying solely on inline JS
    return render_template('logout_confirm.html')

@app.route('/whoami')
@login_required
def whoami():
    return {
        'id': current_user.id,
        'email': current_user.email,
        'name': current_user.name,
        'role': current_user.role,
    }

@app.route('/submit', methods=['POST'])
@login_required
def submit_form():
    if request.method == 'POST':
        # Persist all raw form fields so template/pdf can render comprehensively
        form_fields = {k: v for k, v in request.form.items()}

        form_data = {
            'fields': form_fields,
            'documents': {},
            'meta': {
                'submitted_at': datetime.utcnow().isoformat() + 'Z'
            }
        }

        # Helpers for validation
        def is_pdf(filename: str) -> bool:
            return filename.lower().endswith('.pdf')

        def file_size_ok(storage) -> bool:
            try:
                pos = storage.stream.tell()
            except Exception:
                pos = 0
            try:
                storage.stream.seek(0, os.SEEK_END)
                size = storage.stream.tell()
                storage.stream.seek(pos)
            except Exception:
                # If unable to seek (streamed), fall back to accepting and rely on total limit
                size = 0
            return size == 0 or size <= 10 * 1024 * 1024  # allow 0 (unknown) or <=10MB

        # Checklist keys to process (each allows up to 5 PDFs)
        checklist_keys = [
            'chk_resume', 'chk_edu_docs', 'chk_i94', 'chk_passport', 'chk_us_visas',
            'chk_i797', 'chk_ds2019', 'chk_i612', 'chk_ead', 'chk_paystubs',
            'chk_i20', 'chk_translations'
        ]

        # Create identifiers
        submission_id = uuid.uuid4().hex
        case_number = f"GC{datetime.utcnow().strftime('%Y%m%d')}-{submission_id[:6].upper()}"

        # Handle checklist uploads generically
        for key in checklist_keys:
            if key in request.files:
                files = request.files.getlist(key)
                # Filter to actual chosen files
                files = [f for f in files if getattr(f, 'filename', '')]
                if len(files) > 5:
                    flash(f'You can upload a maximum of 5 files for {key.replace("_"," ")}.', 'error')
                    return redirect(url_for('index'))
                saved_files = []
                for idx, f in enumerate(files, start=1):
                    if not is_pdf(f.filename):
                        flash(f'Only PDF files are allowed for {key.replace("_"," ")}.', 'error')
                        return redirect(url_for('index'))
                    if not file_size_ok(f):
                        flash(f'A file in {key.replace("_"," ")} exceeds the 10MB limit.', 'error')
                        return redirect(url_for('index'))
                    fname = secure_filename(f"{submission_id}_{key}_{idx}_{f.filename}")
                    f.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
                    saved_files.append(fname)
                if saved_files:
                    form_data['documents'][key] = saved_files

        # Merge in any autosaved draft documents for this user (uploaded before submit)
        try:
            dpath = os.path.join(DRAFTS_DIR, f"{current_user.id}.json")
            if os.path.exists(dpath):
                with open(dpath, 'r', encoding='utf-8') as df:
                    draft = json.load(df) or {}
                draft_docs = draft.get('documents', {}) or {}
                # Combine per key, avoiding duplicates, preserving submission-time order first
                merged = dict(form_data['documents'])
                for k, arr in (draft_docs.items() if isinstance(draft_docs, dict) else []):
                    # If submission-time uploads exist for this key, prefer them and skip draft merges for this key
                    if merged.get(k):
                        continue
                    if not arr:
                        continue
                    if isinstance(arr, str):
                        arr = [arr]
                    base = merged.get(k, []) or []
                    seen = set(base)
                    for fname in arr:
                        if fname not in seen:
                            base.append(fname)
                            seen.add(fname)
                    merged[k] = base
                # Also merge any files found on disk for this user (in case draft JSON missed them)
                fs_docs = _collect_draft_uploads_from_fs(current_user.id)
                for k, arr in fs_docs.items():
                    # Again, if submission-time uploads exist for this key, skip adding draft filesystem files
                    if merged.get(k):
                        continue
                    base = merged.get(k, []) or []
                    seen = set(base)
                    for fname in arr:
                        if fname not in seen:
                            base.append(fname)
                            seen.add(fname)
                    merged[k] = base
                form_data['documents'] = merged
        except Exception:
            pass

        # Persist submission to JSON
        record = {
            'id': submission_id,
            'user': {
                'id': current_user.id,
                'email': current_user.email,
                'name': current_user.name,
                'role': current_user.role,
            },
            **form_data
        }
        # add case metadata and initial status
        record.setdefault('meta', {})
        record['meta']['case_number'] = case_number
        record['meta']['status'] = 'Pending with HR-Immigration'
        with open(os.path.join(DATA_DIR, f"{submission_id}.json"), 'w', encoding='utf-8') as f:
            json.dump(record, f, ensure_ascii=False, indent=2)

        # Lock the user's draft so the form becomes read-only
        try:
            dpath = os.path.join(DRAFTS_DIR, f"{current_user.id}.json")
            snap = {
                'user': {
                    'id': current_user.id,
                    'email': current_user.email,
                    'name': current_user.name,
                },
                'fields': form_fields,
                'documents': form_data.get('documents', {}) or {},
                'locked': True,
                'submission_id': submission_id,
                'case_number': case_number,
                'status': 'Pending with HR-Immigration',
                'saved_at': datetime.utcnow().isoformat() + 'Z'
            }
            with open(dpath, 'w', encoding='utf-8') as df:
                json.dump(snap, df, ensure_ascii=False, indent=2)
        except Exception:
            pass

        # Redirect to a thank you page or show a success message
        flash('Your application has been submitted successfully!', 'success')
        return redirect(url_for('confirmation', submission_id=submission_id))

@app.route('/new_application', methods=['POST'])
@login_required
def new_application():
    """Clear the current user's draft and unlock the form to start a new questionnaire."""
    try:
        path = os.path.join(DRAFTS_DIR, f"{current_user.id}.json")
        if os.path.exists(path):
            # Reset to empty draft
            with open(path, 'w', encoding='utf-8') as f:
                json.dump({
                    'user': {
                        'id': current_user.id,
                        'email': current_user.email,
                        'name': current_user.name,
                    },
                    'fields': {},
                    'documents': {},
                    'locked': False,
                    'saved_at': datetime.utcnow().isoformat() + 'Z'
                }, f, ensure_ascii=False, indent=2)
    except Exception:
        pass
    return redirect(url_for('index'))

@app.route('/confirmation/<submission_id>')
def confirmation(submission_id):
    return render_template('confirmation.html', submission_id=submission_id)

@app.route('/submission/<submission_id>')
@login_required
def view_submission(submission_id):
    filepath = os.path.join(DATA_DIR, f"{submission_id}.json")
    if not os.path.exists(filepath):
        return "Submission not found", 404
    with open(filepath, 'r', encoding='utf-8') as f:
        record = json.load(f)
    # Fallback: if submission has no documents, try to merge user's draft documents for display only
    try:
        docs = record.get('documents') or {}
        if not docs:
            uid = (record.get('user') or {}).get('id')
            if uid:
                dpath = os.path.join(DRAFTS_DIR, f"{uid}.json")
                if os.path.exists(dpath):
                    with open(dpath, 'r', encoding='utf-8') as df:
                        draft = json.load(df) or {}
                    draft_docs = draft.get('documents', {}) or {}
                    if isinstance(draft_docs, dict) and draft_docs:
                        record['documents'] = draft_docs
                    else:
                        # Final fallback: scan filesystem for draft uploads
                        fs_docs = _collect_draft_uploads_from_fs(uid)
                        if fs_docs:
                            record['documents'] = fs_docs
    except Exception:
        pass
    # Build grouped entries for Education and Work Experience
    fields = record.get('fields', {}) or {}
    edu_entries = _extract_block_entries(fields, 'edu', EDU_LABELS, EDU_ORDER)
    wb_entries = _extract_block_entries(fields, 'wb', WB_LABELS, WB_ORDER)
    return render_template('submission.html', record=record, uploads_url_prefix='/uploads', edu_entries=edu_entries, wb_entries=wb_entries)

@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    from flask import send_from_directory
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)

if _PDF_ENABLED:
    @app.route('/submission/<submission_id>/pdf')
    @login_required
    def submission_pdf(submission_id):
        # HR only
        if current_user.role != 'hr':
            return redirect(url_for('index'))
        filepath = os.path.join(DATA_DIR, f"{submission_id}.json")
        if not os.path.exists(filepath):
            return "Submission not found", 404
        with open(filepath, 'r', encoding='utf-8') as f:
            record = json.load(f)
        # Build grouped entries for Education and Work Experience
        fields = record.get('fields', {}) or {}
        edu_entries = _extract_block_entries(fields, 'edu', EDU_LABELS, EDU_ORDER)
        wb_entries = _extract_block_entries(fields, 'wb', WB_LABELS, WB_ORDER)
        # Render a PDF-friendly template (inline CSS, no external assets)
        html = render_template('submission_pdf.html', record=record, edu_entries=edu_entries, wb_entries=wb_entries)
        pdf_io = BytesIO()
        pisa_status = pisa.CreatePDF(src=html, dest=pdf_io)
        if pisa_status.err:
            return "Failed to generate PDF", 500
        pdf_io.seek(0)
        from flask import send_file
        return send_file(pdf_io, mimetype='application/pdf', as_attachment=True, download_name=f"submission_{submission_id}.pdf")

@app.route('/submission/<submission_id>/documents.zip')
@login_required
def submission_documents_zip(submission_id):
    # HR only
    if current_user.role != 'hr':
        return redirect(url_for('index'))
    filepath = os.path.join(DATA_DIR, f"{submission_id}.json")
    if not os.path.exists(filepath):
        return "Submission not found", 404
    with open(filepath, 'r', encoding='utf-8') as f:
        record = json.load(f)
    documents = record.get('documents', {}) or {}
    # Fallback: if no documents in submission, include any autosaved draft documents for that user
    if not documents:
        try:
            uid = (record.get('user') or {}).get('id')
            if uid:
                dpath = os.path.join(DRAFTS_DIR, f"{uid}.json")
                if os.path.exists(dpath):
                    with open(dpath, 'r', encoding='utf-8') as df:
                        draft = json.load(df) or {}
                    dd = draft.get('documents', {}) or {}
                    if isinstance(dd, dict):
                        documents = dd
                if not documents:
                    # Final fallback from filesystem
                    documents = _collect_draft_uploads_from_fs(uid)
        except Exception:
            pass
    from io import BytesIO
    import zipfile
    zip_io = BytesIO()
    with zipfile.ZipFile(zip_io, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        for key, files in documents.items():
            if isinstance(files, str):
                files = [files]
            for fname in files or []:
                abs_path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
                if os.path.exists(abs_path):
                    zf.write(abs_path, arcname=f"{key}/{os.path.basename(fname)}")
    zip_io.seek(0)
    from flask import send_file
    return send_file(zip_io, mimetype='application/zip', as_attachment=True, download_name=f"submission_{submission_id}_documents.zip")

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'hr':
        return redirect(url_for('index'))
    # Very simple HR view: list all submissions in data dir
    items = []
    tab = (request.args.get('tab') or 'under').lower()
    for name in sorted(os.listdir(DATA_DIR)):
        if not name.endswith('.json'):
            continue
        sid = name[:-5]
        try:
            with open(os.path.join(DATA_DIR, name), 'r', encoding='utf-8') as f:
                rec = json.load(f)
            meta = rec.get('meta', {}) or {}
            submitted_at = meta.get('submitted_at') or rec.get('fields', {}).get('submitted_at')
            status = meta.get('status') or 'Pending with HR-Immigration'
            case_number = meta.get('case_number') or ''
        except Exception:
            submitted_at = ''
            status = 'Pending with HR-Immigration'
            case_number = ''
        items.append({'id': sid, 'submitted_at': submitted_at, 'status': status, 'case_number': case_number})
    under_items = [it for it in items if it['status'] != 'Approved']
    completed_items = [it for it in items if it['status'] == 'Approved']
    return render_template(
        'admin.html',
        items=items,
        under_items=under_items,
        completed_items=completed_items,
        current_tab=tab if tab in ('under','completed') else 'under',
        allowed_statuses=ALLOWED_STATUSES,
        pdf_enabled=_PDF_ENABLED,
    )

@app.route('/admin/submission/<submission_id>/status', methods=['POST'])
@login_required
def admin_update_status(submission_id):
    if current_user.role != 'hr':
        return redirect(url_for('index'))
    status = (request.form.get('status') or '').strip()
    if status not in ALLOWED_STATUSES:
        flash('Invalid status selection', 'error')
        return redirect(url_for('admin_dashboard'))
    path = os.path.join(DATA_DIR, f"{submission_id}.json")
    if not os.path.exists(path):
        flash('Submission not found', 'error')
        return redirect(url_for('admin_dashboard'))
    try:
        with open(path, 'r', encoding='utf-8') as f:
            rec = json.load(f)
        rec.setdefault('meta', {})
        rec['meta']['status'] = status
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(rec, f, ensure_ascii=False, indent=2)
        flash('Status updated', 'success')
    except Exception as e:
        flash(f'Failed to update status: {e}', 'error')
    # Keep current tab if passed
    tab = request.args.get('tab') or 'under'
    return redirect(url_for('admin_dashboard', tab=tab))

@app.route('/autosave', methods=['GET', 'POST'])
@login_required
def autosave():
    """Server-side autosave tied to the logged-in user.
    GET: return saved draft fields or {}.
    POST: accept JSON {fields: {...}} and persist.
    """
    user_id = current_user.id
    path = os.path.join(DRAFTS_DIR, f"{user_id}.json")
    if request.method == 'GET':
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                return jsonify({ 'ok': True, 'fields': data.get('fields', {}), 'documents': data.get('documents', {}), 'saved_at': data.get('saved_at') })
            except Exception:
                return jsonify({ 'ok': False, 'fields': {}, 'documents': {} }), 200
        return jsonify({ 'ok': True, 'fields': {}, 'documents': {} }), 200
    # POST
    try:
        payload = request.get_json(silent=True) or {}
        fields = payload.get('fields', {})
        # Preserve existing documents so field autosave doesn't wipe them
        existing_documents = {}
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as rf:
                    prev = json.load(rf) or {}
                    existing_documents = prev.get('documents', {}) or {}
            except Exception:
                existing_documents = {}
        doc = {
            'user': {
                'id': current_user.id,
                'email': current_user.email,
                'name': current_user.name,
            },
            'fields': fields,
            'documents': existing_documents,
            'saved_at': datetime.utcnow().isoformat() + 'Z'
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
        return jsonify({ 'ok': True })
    except Exception as e:
        return jsonify({ 'ok': False, 'error': str(e) }), 500

@app.route('/autosave_uploads', methods=['POST', 'DELETE'])
@login_required
def autosave_uploads():
    """Upload/remove draft documents for the logged-in user.
    POST: multipart/form-data with files under field name 'files', query ?key=<checklist_key>
    DELETE: query ?key=<checklist_key>&filename=<saved_name>
    Updates the user's draft JSON under 'documents'.
    """
    key = (request.args.get('key') or '').strip()
    if not key:
        return jsonify({ 'ok': False, 'error': 'missing key' }), 400

    def is_pdf(filename: str) -> bool:
        return filename and filename.lower().endswith('.pdf')

    def file_size_ok(storage) -> bool:
        try:
            pos = storage.stream.tell()
        except Exception:
            pos = 0
        try:
            storage.stream.seek(0, os.SEEK_END)
            size = storage.stream.tell()
            storage.stream.seek(pos)
        except Exception:
            size = 0
        return size == 0 or size <= 10 * 1024 * 1024

    user_id = current_user.id
    draft_path = os.path.join(DRAFTS_DIR, f"{user_id}.json")
    # Load existing draft doc
    draft = { 'fields': {}, 'documents': {}, 'saved_at': None }
    if os.path.exists(draft_path):
        try:
            with open(draft_path, 'r', encoding='utf-8') as f:
                draft = json.load(f) or draft
        except Exception:
            draft = { 'fields': {}, 'documents': {}, 'saved_at': None }

    documents = draft.get('documents') or {}
    existing = list(documents.get(key, []) or [])

    if request.method == 'DELETE':
        filename = (request.args.get('filename') or '').strip()
        if not filename:
            return jsonify({ 'ok': False, 'error': 'missing filename' }), 400
        abs_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            if os.path.exists(abs_path):
                os.remove(abs_path)
        except Exception:
            pass
        if filename in existing:
            existing.remove(filename)
        documents[key] = existing
        draft['documents'] = documents
        draft['saved_at'] = datetime.utcnow().isoformat() + 'Z'
        with open(draft_path, 'w', encoding='utf-8') as f:
            json.dump(draft, f, ensure_ascii=False, indent=2)
        return jsonify({ 'ok': True, 'files': existing })

    # POST upload
    files = request.files.getlist('files')
    files = [f for f in files if getattr(f, 'filename', '')]
    if not files:
        return jsonify({ 'ok': False, 'error': 'no files provided' }), 400
    # enforce maximum 5 total per key
    if len(existing) + len(files) > 5:
        return jsonify({ 'ok': False, 'error': 'maximum 5 files allowed for this document' }), 400

    saved = []
    for f in files:
        if not is_pdf(f.filename):
            return jsonify({ 'ok': False, 'error': 'only PDF files are allowed' }), 400
        if not file_size_ok(f):
            return jsonify({ 'ok': False, 'error': 'file exceeds 10MB limit' }), 400
        base = secure_filename(f"draft_{user_id}_{key}_{uuid.uuid4().hex}_{f.filename}")
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], base))
        saved.append(base)

    documents[key] = existing + saved
    draft['documents'] = documents
    draft['saved_at'] = datetime.utcnow().isoformat() + 'Z'
    with open(draft_path, 'w', encoding='utf-8') as f:
        json.dump(draft, f, ensure_ascii=False, indent=2)
    return jsonify({ 'ok': True, 'files': documents[key] })

if __name__ == '__main__':
    app.run(debug=True)
