import os
import time
import hashlib
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher, exceptions as argon2_exceptions
import db

# --- Backend: crypto + stores ---
MASTER_KEY = os.urandom(32)


def get_sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def derive_key(info: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=info.encode(), backend=default_backend()
    )
    return hkdf.derive(MASTER_KEY)


def encrypt_record(data: str, info: str):
    key = derive_key(info)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
    return nonce, ciphertext


# In-memory stores
USERS = {}  # username -> {password_hash, salt}
BLOCKCHAIN = {}  # pid -> {hash, owner, ts}
RECORDS = {}  # pid -> {owner, nonce(hex), data(hex), created_at}
AUDIT_LOG = []


# --- Web app ---
app = Flask(__name__)
app.secret_key = os.urandom(24)
ph = PasswordHasher()

# Ensure DB/tables exist
db.init_db()


def ensure_csrf():
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(16).hex()


def verify_csrf(token: str) -> bool:
    return token and session.get('csrf_token') == token


def login_required(fn):
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            flash('You must be logged in', 'error')
            return redirect(url_for('login'))
        return fn(*args, **kwargs)

    wrapper.__name__ = fn.__name__
    return wrapper


@app.before_request
def before_request():
    ensure_csrf()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if not verify_csrf(request.form.get('csrf_token')):
            flash('Invalid CSRF token', 'error')
            return redirect(url_for('register'))
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            flash('Username and password required', 'error')
            return redirect(url_for('register'))
        existing = db.get_user(username)
        if existing:
            flash('Username exists', 'error')
            return redirect(url_for('register'))
        salt = os.urandom(16).hex()
        pw_hash = ph.hash(password)
        db.add_user(username, pw_hash, salt)
        USERS[username] = {'password_hash': pw_hash, 'salt': salt}
        session['user'] = username
        flash('Registered and logged in', 'success')
        db.add_audit(username, 'register', None, int(time.time()))
        return redirect(url_for('index'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not verify_csrf(request.form.get('csrf_token')):
            flash('Invalid CSRF token', 'error')
            return redirect(url_for('login'))
        username = request.form['username'].strip()
        password = request.form['password']
        user = db.get_user(username)
        if not user:
            flash('Unknown user', 'error')
            return redirect(url_for('login'))
        try:
            ph.verify(user['password_hash'], password)
        except argon2_exceptions.VerifyMismatchError:
            flash('Invalid password', 'error')
            return redirect(url_for('login'))
        session['user'] = username
        flash('Logged in', 'success')
        db.add_audit(username, 'login', None, int(time.time()))
        return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    user = session.pop('user', None)
    if user:
        flash('Logged out', 'success')
    return redirect(url_for('index'))


@app.route('/add_record', methods=['GET', 'POST'])
@login_required
def add_record():
    if request.method == 'POST':
        if not verify_csrf(request.form.get('csrf_token')):
            flash('Invalid CSRF token', 'error')
            return redirect(url_for('add_record'))
        pid = request.form['pid'].strip()
        data = request.form['data']
        if not pid or not data:
            flash('Patient ID and data required', 'error')
            return redirect(url_for('add_record'))
        owner = session['user']
        data_hash = get_sha256(data)
        ts = int(time.time())
        nonce, ciphertext = encrypt_record(data, owner)
        # persist
        db.add_blockchain(pid, data_hash, owner, ts)
        db.add_record(pid, owner, nonce.hex(), ciphertext.hex(), ts)
        db.add_audit(owner, 'add_record', pid, ts)
        # update in-memory caches as well
        BLOCKCHAIN[pid] = {'hash': data_hash, 'owner': owner, 'timestamp': ts}
        RECORDS[pid] = {'owner': owner, 'nonce': nonce.hex(), 'data': ciphertext.hex(), 'created_at': ts}
        flash('Record stored and hashed to ledger', 'success')
        return redirect(url_for('index'))
    return render_template('add_record.html')


@app.route('/verify', methods=['GET', 'POST'])
@login_required
def verify():
    result = None
    if request.method == 'POST':
        if not verify_csrf(request.form.get('csrf_token')):
            flash('Invalid CSRF token', 'error')
            return redirect(url_for('verify'))
        pid = request.form['pid'].strip()
        data = request.form['data']
        entry = db.get_blockchain(pid)
        if not entry:
            flash('No record for that Patient ID', 'error')
            return redirect(url_for('verify'))
        current_hash = get_sha256(data)
        result = current_hash == entry.get('hash')
    return render_template('verify.html', result=result)


if __name__ == '__main__':
    app.run(debug=True)
