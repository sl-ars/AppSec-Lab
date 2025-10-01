import io
import os
import pickle
import sqlite3
import base64
import traceback

from flask import Flask, request, render_template, redirect, url_for, session, abort, flash, send_file
from utils import deserialize, hash_password, verify_password

app = Flask(__name__)
# loads hardcoded secrets (bad)
app.config.from_object('config')
app.secret_key = app.config.get('SECRET_KEY')
app.debug = True

DB_PATH = os.environ.get('DB_PATH', 'notes.db')


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

        # create salt+hash
        salt, pwd_hash = hash_password(password)
        stored = f"{salt}${pwd_hash}"

        con = connect_db()
        try:
            # keep using parameterized query
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
        # SQLi: unsafely concatenated query
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


@app.route('/note/<int:note_id>')
def view_note(note_id):
    require_login()
    con = connect_db()
    try:
        note = get_note_for_user(con, note_id, session['user_id'])
    finally:
        con.close()

    if not note:
        abort(404)
    return render_template('note_view.html', note=note)


@app.route('/note/create', methods=['GET','POST'])
def create_note():
    require_login()
    if request.method == 'POST':
        try:
            title = request.form.get('title', '').strip()
            content = request.form.get('content', '').strip()
            con = connect_db()
            try:
                con.execute(
                    'INSERT INTO notes(user_id, title, content) VALUES (?, ?, ?)',
                    (session['user_id'], title, content)
                )
                con.commit()
            finally:
                con.close()

            flash('Note created', 'success')
            return redirect(url_for('list_notes'))
        except Exception:
            flash('Internal server error. Please try again later.', 'danger')
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
            con.commit()

            if cur.rowcount == 0:
                abort(403)

            flash('Note updated', 'success')
            return redirect(url_for('view_note', note_id=note_id))

    finally:
        con.close()

    return render_template('note_edit.html', note=note)


@app.route('/note/<int:note_id>/delete', methods=['POST'])
def delete_note(note_id):
    require_login()
    con = connect_db()
    try:
        # Delete only if the note belongs to the current user
        cur = con.execute('DELETE FROM notes WHERE id = ? AND user_id = ?', (note_id, session['user_id']))
        con.commit()

        if cur.rowcount == 0:
            abort(404)

    finally:
        con.close()

    flash('Note deleted', 'warning')
    return redirect(url_for('list_notes'))

# --- Insecure deserialization (pickle) ---
@app.route('/import', methods=['POST'])
def import_notes():
    require_login()

    # Try file upload first
    uploaded = request.files.get('file')
    data_b64 = None

    if uploaded and uploaded.filename:
        try:
            raw = uploaded.read()
            if isinstance(raw, bytes):
                data_b64 = raw.decode('utf-8').strip()
            else:
                data_b64 = str(raw).strip()
        except Exception as e:
            flash(f'Failed to read uploaded file: {e}', 'danger')
            return redirect(url_for('list_notes'))

    if not data_b64:
        data_b64 = request.form.get('data', '').strip()

    if not data_b64:
        flash('No import data provided.', 'warning')
        return redirect(url_for('list_notes'))

    try:
        items = deserialize(data_b64) # RCE
        if not isinstance(items, list):
            flash('Imported payload is not a list of notes.', 'danger')
            return redirect(url_for('list_notes'))

        con = connect_db()
        inserted = 0
        for it in items:
            if not isinstance(it, dict):
                continue
            title = it.get('title', '') if isinstance(it.get('title', ''), str) else str(it.get('title', ''))
            content = it.get('content', '') if isinstance(it.get('content', ''), str) else str(it.get('content', ''))
            con.execute('INSERT INTO notes(user_id, title, content) VALUES (?, ?, ?)', (session['user_id'], title, content))
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
            'SELECT id, user_id, title, content FROM notes WHERE user_id=? ORDER BY id DESC',
            (user_id,)
        ).fetchall()
    finally:
        con.close()

    items = [
        {"id": r["id"], "title": r["title"], "content": r["content"]}
        for r in rows
    ]

    payload = base64.b64encode(pickle.dumps(items))

    filename = f"notes_user_{user_id}.pkl.b64"

    buf = io.BytesIO(payload)
    buf.seek(0)
    return send_file(
        buf,
        as_attachment=True,
        download_name=filename,
        mimetype='text/plain'
    )

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True, use_debugger=True, use_reloader=True)