from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = 'esto_es_una_clave_secreta_muy_debil_no_usar_en_prod' # Necesario para las sesiones

# Simulación de base de datos de usuarios (NO HACER ESTO EN PRODUCCIÓN)
# VULNERABILIDAD: Contraseñas en texto plano y credenciales débiles/por defecto
users = {
    "admin": "password123", # Credencial débil
    "testuser": "test",     # Credencial muy débil
    "usuario_comun": "P@$$wOrd!"
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # VULNERABILIDAD: No hay protección contra fuerza bruta (sin límites de intentos, sin CAPTCHA)
        if username in users and users[username] == password:
            session['username'] = username # Inicia la sesión
            flash('Inicio de sesión exitoso!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Nombre de usuario o contraseña incorrectos.', 'danger')
            return render_template('login.html', error="Credenciales inválidas")

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
    # VULNERABILIDAD POTENCIAL: Si comentamos la siguiente línea,
    # la sesión no se invalida correctamente en el servidor.
    # El cliente podría borrar la cookie, pero el servidor aún la consideraría válida si se reenvía.
    # session.pop('username', None) # Invalida la sesión en el servidor
    # session.clear() # Alternativa para borrar toda la sesión

    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Nota: debug=True es inseguro para producción, pero útil para desarrollo.
    app.run(host='0.0.0.0', port=5001, debug=True)