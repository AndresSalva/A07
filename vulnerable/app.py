from flask import Flask, render_template, request, redirect, url_for, session, flash, g
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

DATABASE = 'database.db'

# --- Funciones de Base de Datos ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db_schema():
    conn = sqlite3.connect(DATABASE)
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    with open(schema_path, mode='r') as f:
        conn.cursor().executescript(f.read())
    conn.commit()
    conn.close()
    print("Esquema de base de datos (solo usuarios) inicializado.")

def populate_initial_users():
    users_to_add = {
        "admin": "password123",
        "testuser": "test"
    }
    db = get_db()
    cursor = db.cursor()
    for username, password in users_to_add.items():
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone() is None:
            password_h = generate_password_hash(password, method='pbkdf2:sha256')
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_h))
            print(f"Usuario inicial '{username}' añadido.")
    db.commit()
    print("Usuarios iniciales poblados/verificados.")

# --- Rutas de la Aplicación ---
@app.route('/')
def index():
    # Página de inicio simple
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        error = None

        if not username:
            error = 'Nombre de usuario es requerido.'
        elif not password:
            error = 'Contraseña es requerida.'
        elif len(password) < 6:
             error = 'La contraseña debe tener al menos 6 caracteres.'
        elif password != confirm_password:
            error = 'Las contraseñas no coinciden.'
        
        if error is None:
            db = get_db()
            try:
                password_h = generate_password_hash(password, method='pbkdf2:sha256')
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_h),
                )
                db.commit()
            except db.IntegrityError:
                error = f"El usuario {username} ya está registrado."
            else:
                flash(f'Usuario {username} registrado exitosamente. Por favor, inicia sesión.', 'success')
                return redirect(url_for('login'))
        
        if error:
            flash(error, 'danger')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Inicio de sesión exitoso!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Nombre de usuario o contraseña incorrectos.', 'danger')
            return render_template('login.html', error_login="Credenciales inválidas")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        flash('Debes iniciar sesión para acceder al dashboard.', 'warning')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login'))

# No hay ruta /search ahora

if __name__ == '__main__':
    with app.app_context():
        db_path = os.path.join(os.path.dirname(__file__), DATABASE)
        if not os.path.exists(db_path):
            try:
                init_db_schema()
                populate_initial_users()
            except Exception as e:
                print(f"Error al inicializar la base de datos: {e}")
        else:
            populate_initial_users() 
            
    app.run(host='0.0.0.0', port=5001, debug=True)