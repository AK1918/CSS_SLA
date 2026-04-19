"""Migration script: move in-memory stores from full_app into SQLite DB.

Usage: python migrate_memory.py
"""
import db
import full_app
import time


def migrate():
    db.init_db()
    # users
    for username, info in getattr(full_app, 'USERS', {}).items():
        pw = info.get('password_hash')
        salt = info.get('salt')
        if username and pw:
            db.add_user(username, pw, salt)
    # blockchain
    for pid, entry in getattr(full_app, 'BLOCKCHAIN', {}).items():
        db.add_blockchain(pid, entry.get('hash'), entry.get('owner'), entry.get('timestamp') or int(time.time()))
    # records
    for pid, rec in getattr(full_app, 'RECORDS', {}).items():
        db.add_record(pid, rec.get('owner'), rec.get('nonce'), rec.get('data'), rec.get('created_at') or int(time.time()))
    # audit
    for entry in getattr(full_app, 'AUDIT_LOG', []):
        db.add_audit(entry.get('user'), entry.get('action'), entry.get('pid'), entry.get('ts') or int(time.time()))


if __name__ == '__main__':
    migrate()
    print('Migration complete. DB file:', db.DB_FILE)
