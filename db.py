import os
import sqlite3
from typing import Optional, Dict, Any


DB_FILE = os.path.join(os.path.dirname(__file__), 'app.db')


def get_conn(path: Optional[str] = None) -> sqlite3.Connection:
    return sqlite3.connect(path or DB_FILE)


def init_db(path: Optional[str] = None):
    conn = get_conn(path)
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        salt TEXT
    )
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS blockchain (
        pid TEXT PRIMARY KEY,
        hash TEXT,
        owner TEXT,
        timestamp INTEGER
    )
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS records (
        pid TEXT PRIMARY KEY,
        owner TEXT,
        nonce TEXT,
        data TEXT,
        created_at INTEGER
    )
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        action TEXT,
        pid TEXT,
        ts INTEGER
    )
    ''')
    conn.commit()
    conn.close()


def add_user(username: str, password_hash: str, salt: str, path: Optional[str] = None):
    conn = get_conn(path)
    cur = conn.cursor()
    cur.execute('INSERT OR REPLACE INTO users(username, password_hash, salt) VALUES (?,?,?)',
                (username, password_hash, salt))
    conn.commit()
    conn.close()


def get_user(username: str, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_conn(path)
    cur = conn.cursor()
    cur.execute('SELECT username, password_hash, salt FROM users WHERE username = ?', (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {'username': row[0], 'password_hash': row[1], 'salt': row[2]}


def add_blockchain(pid: str, hash_val: str, owner: str, timestamp: int, path: Optional[str] = None):
    conn = get_conn(path)
    cur = conn.cursor()
    cur.execute('INSERT OR REPLACE INTO blockchain(pid, hash, owner, timestamp) VALUES (?,?,?,?)',
                (pid, hash_val, owner, timestamp))
    conn.commit()
    conn.close()


def get_blockchain(pid: str, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_conn(path)
    cur = conn.cursor()
    cur.execute('SELECT pid, hash, owner, timestamp FROM blockchain WHERE pid = ?', (pid,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {'pid': row[0], 'hash': row[1], 'owner': row[2], 'timestamp': row[3]}


def add_record(pid: str, owner: str, nonce: str, data: str, created_at: int, path: Optional[str] = None):
    conn = get_conn(path)
    cur = conn.cursor()
    cur.execute('INSERT OR REPLACE INTO records(pid, owner, nonce, data, created_at) VALUES (?,?,?,?,?)',
                (pid, owner, nonce, data, created_at))
    conn.commit()
    conn.close()


def get_record(pid: str, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_conn(path)
    cur = conn.cursor()
    cur.execute('SELECT pid, owner, nonce, data, created_at FROM records WHERE pid = ?', (pid,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {'pid': row[0], 'owner': row[1], 'nonce': row[2], 'data': row[3], 'created_at': row[4]}


def add_audit(user: str, action: str, pid: str, ts: int, path: Optional[str] = None):
    conn = get_conn(path)
    cur = conn.cursor()
    cur.execute('INSERT INTO audit_log(user, action, pid, ts) VALUES (?,?,?,?)', (user, action, pid, ts))
    conn.commit()
    conn.close()


def dump_all(path: Optional[str] = None) -> Dict[str, Any]:
    conn = get_conn(path)
    cur = conn.cursor()
    out = {}
    cur.execute('SELECT username, password_hash, salt FROM users')
    out['users'] = [{'username': r[0], 'password_hash': r[1], 'salt': r[2]} for r in cur.fetchall()]
    cur.execute('SELECT pid, hash, owner, timestamp FROM blockchain')
    out['blockchain'] = [{'pid': r[0], 'hash': r[1], 'owner': r[2], 'timestamp': r[3]} for r in cur.fetchall()]
    cur.execute('SELECT pid, owner, nonce, data, created_at FROM records')
    out['records'] = [{'pid': r[0], 'owner': r[1], 'nonce': r[2], 'data': r[3], 'created_at': r[4]} for r in cur.fetchall()]
    cur.execute('SELECT user, action, pid, ts FROM audit_log')
    out['audit_log'] = [{'user': r[0], 'action': r[1], 'pid': r[2], 'ts': r[3]} for r in cur.fetchall()]
    conn.close()
    return out
