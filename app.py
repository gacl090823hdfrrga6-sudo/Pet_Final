from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
app.secret_key = "tdel_secret"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tdel.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

# ---------------- MODELOS ----------------
class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False)
    correo = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Residuo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(50))
    color = db.Column(db.String(30))
    descripcion = db.Column(db.String(200))
    ejemplos = db.Column(db.String(200))

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

# ---------------- RUTAS ----------------

@app.route('/test')
def test():
    return "FUNCIONA"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/registro', methods=['GET','POST'])
def registro():
    if request.method == 'POST':
        nombre = request.form['nombre']
        correo = request.form['correo']
        password = request.form['password']

        if not re.match(r"[^@]+@[^@]+\.[^@]+", correo):
            flash("Correo electrónico no válido")
            return redirect(url_for('registro'))

        if len(password) < 8:
            flash("La contraseña debe tener mínimo 8 caracteres")
            return redirect(url_for('registro'))

        if Usuario.query.filter_by(correo=correo).first():
            flash("El usuario ya existe")
            return redirect(url_for('registro'))

        nuevo = Usuario(
            nombre=nombre,
            correo=correo,
            password=generate_password_hash(password)
        )
        db.session.add(nuevo)
        db.session.commit()
        flash("Usuario registrado correctamente ✅")
        return redirect(url_for('login'))

    return render_template('registro.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        correo = request.form['correo']
        password = request.form['password']

        user = Usuario.query.filter_by(correo=correo).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash(f"Bienvenido, {user.nombre} 👋")
            return redirect(url_for('index'))
        else:
            flash("Correo o contraseña incorrectos ❌")

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Has cerrado sesión ✅")
    return redirect(url_for('index'))

@app.route('/residuo', methods=['GET','POST'])
@login_required
def residuo():
    if request.method == 'POST':
        nuevo = Residuo(
            tipo=request.form['tipo'],
            color=request.form['color'],
            descripcion=request.form['descripcion'],
            ejemplos=request.form['ejemplos']
        )
        db.session.add(nuevo)
        db.session.commit()
        flash("Residuo registrado correctamente ✅")
        return redirect(url_for('consultas'))

    return render_template('residuo.html')

@app.route('/consultas')
@login_required
def consultas():
    inicial = request.args.get('inicial')
    apariencia = request.args.get('apariencia')
    ejempl = request.args.get('ejempl')

    query = Residuo.query
    if inicial:
        query = query.filter(Residuo.tipo.startswith(inicial))
    if apariencia:
        query = query.filter_by(color=apariencia)
    if ejempl:
        query = query.filter(Residuo.ejemplos.contains(ejempl))

    residuos = query.all()
    return render_template('consultas.html', residuos=residuos)

# ---------------- ELIMINAR RESIDUO ----------------
@app.route('/eliminar_residuo', methods=['POST'])
@login_required
def eliminar_residuo():
    residuo_id = request.form.get('residuo_id')
    pass_eliminar = request.form.get('pass_eliminar')

    if pass_eliminar != "12345":
        flash("Contraseña incorrecta ❌")
        return redirect(url_for('consultas'))

    residuo = Residuo.query.get_or_404(residuo_id)
    db.session.delete(residuo)
    db.session.commit()
    flash("Residuo eliminado correctamente ✅")
    return redirect(url_for('consultas'))

@app.route('/progreso')
@login_required
def progreso():
    return render_template('progreso.html')

# ---------------- EJECUCIÓN ----------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
