from flask import Flask, render_template, request, redirect, url_for, session, flash, g
import sqlite3
import os
# from werkzeug.security import generate_password_hash, check_password_hash # YA NO SE USA
from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

DATABASE = 'database.db'

# --- Funciones de Base de Datos (sin cambios en get_db y close_connection) ---
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

# MODIFICADO: schema.sql necesitaría que password_hash sea TEXT y no necesariamente tan largo
# pero para este ejemplo, no modificaremos schema.sql externamente, asumimos que es TEXT.
def init_db_schema():
    conn = sqlite3.connect(DATABASE)
    schema_sql = """
    DROP TABLE IF EXISTS users;
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL -- Almacenará la contraseña en texto plano
    );
    """
    conn.cursor().executescript(schema_sql)
    conn.commit()
    conn.close()
    print("Esquema de base de datos (usuarios, contraseña en texto plano) inicializado.")

# MODIFICADO: para almacenar contraseñas en texto plano
def populate_initial_users():
    users_to_add = {
        "admin": "password123", # Contraseña en texto plano
        "testuser": "test"      # Contraseña en texto plano
    }
    db = get_db()
    cursor = db.cursor()
    for username, plain_password in users_to_add.items():
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone() is None:
            # YA NO SE USA generate_password_hash
            # Se inserta la contraseña en texto plano directamente en 'password_hash'
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, plain_password))
            print(f"Usuario inicial '{username}' añadido con contraseña en texto plano.")
    db.commit()
    print("Usuarios iniciales (contraseñas en texto plano) poblados/verificados.")

# --- Rutas de la Aplicación ---
@app.route('/')
def index():
    return render_template('index.html')

# MODIFICADO: para almacenar contraseñas en texto plano
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password') # Esta es la contraseña en texto plano
        confirm_password = request.form.get('confirm_password')
        error = None

        if not username:
            error = 'Nombre de usuario es requerido.'
        elif not password:
            error = 'Contraseña es requerida.'
        # Se puede quitar la validación de longitud si se desea para simplificar, pero es buena práctica mantenerla
        elif len(password) < 6:
             error = 'La contraseña debe tener al menos 6 caracteres.'
        elif password != confirm_password:
            error = 'Las contraseñas no coinciden.'
        
        if error is None:
            db = get_db()
            try:
                # YA NO SE USA generate_password_hash
                # Se inserta la contraseña en texto plano directamente
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password), # Guardamos la contraseña en texto plano
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
        password = request.form.get('password') # Esta es la contraseña en texto plano del formulario

        db = get_db()
        # !! VULNERABILIDAD SQLi EXACTAMENTE COMO SE PIDIÓ !!
        # La columna 'password_hash' ahora contiene la contraseña en texto plano.
        # Un login legítimo funcionaría si el usuario y la contraseña coinciden.
        query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password}'"
        
        print(f"Ejecutando consulta vulnerable: {query}")
        user_row = db.execute(query).fetchone()

        if user_row:
            # Si la consulta SQL devuelve una fila, o el login es legítimo (user/pass coinciden)
            # o la SQLi ha tenido éxito en hacer que toda la condición WHERE sea verdadera.
            session.permanent = True
            session['user_id'] = user_row['id']
            session['username'] = user_row['username']
            flash('Inicio de sesión exitoso!', 'success')
            print(f"Login exitoso/SQLi para el usuario: {user_row['username']}")
            return redirect(url_for('dashboard'))
        else:
            flash('Nombre de usuario o contraseña incorrectos.', 'danger')
            # Para depuración, podrías querer saber si es un fallo de SQL o no encontró filas
            # print("Login fallido: no se encontró usuario o la contraseña no coincidió / SQLi no devolvió filas.")
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

if __name__ == '__main__':
    # Asegurarse de que la base de datos se reinicia cada vez para este ejemplo
    # para que use el esquema de contraseñas en texto plano.
    db_path = os.path.join(os.path.dirname(__file__), DATABASE)
    if os.path.exists(db_path):
        print(f"Eliminando base de datos existente: {db_path}")
        os.remove(db_path)

    with app.app_context():
        try:
            init_db_schema() # Esto ahora crea la tabla con password_hash para texto plano
            populate_initial_users() # Esto ahora inserta contraseñas en texto plano
        except Exception as e:
            print(f"Error al inicializar la base de datos: {e}")
            
    app.run(host='0.0.0.0', port=5001, debug=True)