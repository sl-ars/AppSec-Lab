import io
import csv
import os
import sqlite3
import time
import mimetypes
import uuid
from pathlib import Path
from flask import Flask, request, render_template, redirect, url_for, session, abort, flash, send_file, send_from_directory
from utils import  hash_password, verify_password

app = Flask(__name__)
app.config.from_object('config')
app.secret_key = app.config.get('SECRET_KEY')
app.debug = True

DB_PATH = os.environ.get('DB_PATH', 'notes.db')

# --- Upload config ---
app.config.setdefault('UPLOAD_FOLDER', os.environ.get('UPLOAD_FOLDER', 'uploads'))
Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)


def connect_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize DB if missing
if not os.path.exists(DB_PATH):
    conn = connect_db()
    with open('schema.sql', 'r', encoding='utf-8') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()

# --- Auth ---
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','').strip()
        if not username or not password:
            flash('Username and password required', 'danger')
            return render_template('register.html')

        salt, pwd_hash = hash_password(password)
        stored = f"{salt}${pwd_hash}"

        con = connect_db()
        try:
            con.execute('INSERT INTO users(username, password) VALUES (?, ?)', (username, stored))
            con.commit()
            flash('Registered! Now login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'danger')
        finally:
            con.close()
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','')
        password = request.form.get('password','')
        con = connect_db()
        try:
            cur = con.execute('SELECT id, password FROM users WHERE username = ?', (username,))
            row = cur.fetchone()
            if row and row['password'] and verify_password(row['password'], password):
                session['user_id'] = row['id']
                session['username'] = username
                flash('Logged in', 'success')
                return redirect(url_for('list_notes'))
            else:
                flash('Invalid credentials', 'danger')
        finally:
            con.close()
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('login'))

def require_login():
    if 'user_id' not in session:
        abort(401)

@app.route('/')
def index():
    return redirect(url_for('list_notes'))

# --- Notes CRUD ---
@app.route('/notes')
def list_notes():
    require_login()
    con = connect_db()
    try:
        notes = con.execute(
            'SELECT id, title, user_id FROM notes WHERE user_id = ? ORDER BY id DESC',
            (session['user_id'],)
        ).fetchall()
    finally:
        con.close()
    return render_template('notes.html', notes=notes)


def get_note_for_user(con, note_id: int, user_id: int):
    return con.execute('SELECT * FROM notes WHERE id = ? AND user_id = ?', (note_id, user_id)).fetchone()


def _save_attachment_for_note(con, owner_user_id: int, note_id: int, file):
    if not file or not file.filename:
        return False, 'No file'

    ext = file.filename.rsplit('.', 1)[1].lower()
    storage_name = f"{file.filename}_{time.time()}.{ext}"
    target_dir = _note_upload_dir(owner_user_id, note_id)
    storage_path = target_dir / storage_name
    file.save(storage_path)

    mime_type = mimetypes.guess_type(str(storage_path))[0] or 'application/octet-stream'
    size = storage_path.stat().st_size

    con.execute(
        'INSERT INTO attachments(note_id, filename, original_name, mime_type, size, created_at) '
        'VALUES (?,?,?,?,?,?)',
        (note_id, storage_name, file.filename, mime_type, size, int(time.time()))
    )
    return True, None


def _note_upload_dir(user_id: int, note_id: int) -> Path:
    base = Path(app.config['UPLOAD_FOLDER'])
    p = base / str(user_id) / str(note_id)
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_attachments(con, note_id: int):
    return con.execute('SELECT * FROM attachments WHERE note_id = ? ORDER BY id DESC', (note_id,)).fetchall()

@app.route('/note/<int:note_id>')
def view_note(note_id):
    require_login()
    con = connect_db()
    try:
        note = get_note_for_user(con, note_id, session['user_id'])
        if not note:
            abort(404)
        attachments = get_attachments(con, note_id)
    finally:
        con.close()
    return render_template('note_view.html', note=note, attachments=attachments)

@app.route('/note/create', methods=['GET','POST'])
def create_note():
    require_login()
    if request.method == 'POST':
        try:
            title = request.form.get('title', '').strip()
            content = request.form.get('content', '').strip()

            con = connect_db()
            try:
                cur = con.execute(
                    'INSERT INTO notes(user_id, title, content) VALUES (?, ?, ?)',
                    (session['user_id'], title, content)
                )
                note_id = cur.lastrowid

                files = request.files.getlist('files')
                saved, failed = 0, 0
                for f in files:
                    if not f or not f.filename:
                        continue
                    ok, msg = _save_attachment_for_note(con, session['user_id'], note_id, f)
                    if ok:
                        saved += 1
                    else:
                        failed += 1
                con.commit()
            finally:
                con.close()

            if saved or failed:
                flash(f'Note created. Attachments saved: {saved}. Failed: {failed}.', 'info')
            else:
                flash('Note created', 'success')
            return redirect(url_for('view_note', note_id=note_id))
        except Exception as e:
            flash(f'Internal server error: {e}', 'danger')
            return render_template('note_edit.html', note=None), 500

    return render_template('note_edit.html', note=None)


@app.route('/note/<int:note_id>/edit', methods=['GET','POST'])
def edit_note(note_id):
    require_login()
    con = connect_db()
    try:
        note = get_note_for_user(con, note_id, session['user_id'])
        if not note:
            abort(404)

        if request.method == 'POST':
            title = request.form.get('title','').strip()
            content = request.form.get('content','').strip()

            cur = con.execute(
                'UPDATE notes SET title = ?, content = ? WHERE id = ? AND user_id = ?',
                (title, content, note_id, session['user_id'])
            )
            if cur.rowcount == 0:
                abort(403)

            files = request.files.getlist('files')
            saved, failed = 0, 0
            for f in files:
                if not f or not f.filename:
                    continue
                ok, msg = _save_attachment_for_note(con, session['user_id'], note_id, f)
                if ok:
                    saved += 1
                else:
                    failed += 1

            con.commit()
            if saved or failed:
                flash(f'Note updated. Attachments saved: {saved}. Failed: {failed}.', 'info')
            else:
                flash('Note updated', 'success')

            return redirect(url_for('view_note', note_id=note_id))

        # GET
        attachments = get_attachments(con, note_id)
    finally:
        con.close()

    return render_template('note_edit.html', note=note, attachments=attachments)


@app.route('/note/<int:note_id>/delete', methods=['POST'])
def delete_note(note_id):
    require_login()
    con = connect_db()
    try:
        cur = con.execute('DELETE FROM notes WHERE id = ? AND user_id = ?', (note_id, session['user_id']))
        con.commit()
        if cur.rowcount == 0:
            abort(404)
    finally:
        con.close()

    flash('Note deleted', 'warning')
    return redirect(url_for('list_notes'))

@app.route('/import', methods=['POST'])
def import_notes():
    require_login()

    uploaded = request.files.get('file')
    if not uploaded or not uploaded.filename:
        flash('No file provided.', 'warning')
        return redirect(url_for('list_notes'))

    try:
        stream = io.StringIO(uploaded.read().decode("utf-8"))
        reader = csv.DictReader(stream)

        con = connect_db()
        inserted = 0
        for row in reader:
            title = str(row.get("title", "")).strip()
            content = str(row.get("content", "")).strip()
            con.execute(
                "INSERT INTO notes(user_id, title, content) VALUES (?, ?, ?)",
                (session['user_id'], title, content),
            )
            inserted += 1
        con.commit()
        con.close()

        flash(f'Import successful: {inserted} notes added.', 'success')
        return redirect(url_for('list_notes'))

    except Exception as e:
        flash(f'Import failed: {e}', 'danger')
        return redirect(url_for('list_notes'))

@app.route('/export')
def export_notes():
    require_login()

    user_id = session.get('user_id')
    if user_id is None:
        abort(401)

    con = connect_db()
    try:
        rows = con.execute(
            "SELECT id, title, content FROM notes WHERE user_id=? ORDER BY id DESC",
            (user_id,),
        ).fetchall()
    finally:
        con.close()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "title", "content"])  # header
    for r in rows:
        writer.writerow([r["id"], r["title"], r["content"]])

    data = buf.getvalue().encode("utf-8")
    buf.close()

    filename = f"notes_user_{user_id}.csv"
    return send_file(
        io.BytesIO(data),
        as_attachment=True,
        download_name=filename,
        mimetype="text/csv",
    )

@app.route('/note/<int:note_id>/upload', methods=['POST'])
def upload_attachment(note_id):
    require_login()
    file = request.files.get('file')
    if not file or not file.filename:
        flash('No file selected.', 'warning')
        return redirect(url_for('view_note', note_id=note_id))

    con = connect_db()
    try:
        note = get_note_for_user(con, note_id, session['user_id'])
        if not note:
            abort(404)

        ext = file.filename.rsplit('.', 1)[1].lower()
        storage_name = f"{file.filename}_{time.time()}.{ext}"
        target_dir = _note_upload_dir(session['user_id'], note_id)
        storage_path = target_dir / storage_name
        file.save(storage_path)

        mime_type = mimetypes.guess_type(str(storage_path))[0] or 'application/octet-stream'
        size = storage_path.stat().st_size

        con.execute(
            'INSERT INTO attachments(note_id, filename, original_name, mime_type, size, created_at) VALUES (?,?,?,?,?,?)',
            (note_id, storage_name, file.filename, mime_type, size, int(time.time()))
        )
        con.commit()

        flash('File uploaded.', 'success')
        return redirect(url_for('view_note', note_id=note_id))
    finally:
        con.close()

@app.route('/note/<int:note_id>/file/<int:att_id>')
def download_attachment(note_id, att_id):
    require_login()
    con = connect_db()
    try:
        note = get_note_for_user(con, note_id, session['user_id'])
        if not note:
            abort(404)
        att = con.execute('SELECT * FROM attachments WHERE id = ? AND note_id = ?', (att_id, note_id)).fetchone()
        if not att:
            abort(404)
        directory = _note_upload_dir(session['user_id'], note_id)
        return send_from_directory(
            directory, att['filename'], mimetype=att['mime_type'], as_attachment=True, download_name=att['original_name']
        )
    finally:
        con.close()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True, use_debugger=True, use_reloader=True)