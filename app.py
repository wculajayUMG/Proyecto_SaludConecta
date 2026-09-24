# app.py
import os
import joblib
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session
from functools import wraps
from jinja2 import select_autoescape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from database.conexion import obtener_conexion
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt,
    get_jwt_identity,
    set_access_cookies,
    unset_jwt_cookies,
    verify_jwt_in_request,
)
import re
from security.audit import ensure_audit_schema, log_audit, write_audit_log
from security.crypto_utils import (
    encrypt_sensitive,
    hash_password,
    verify_legacy_password,
    verify_password,
)
from security.mfa_utils import (
    create_enrollment_qr,
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_totp_secret,
    verify_totp_code,
)

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.jinja_env.autoescape = select_autoescape(
    enabled_extensions=('html', 'htm', 'xml'), default_for_string=True
)

MODEL_PATH = os.getenv(
    'MODEL_PATH',
    os.path.join(BASE_DIR, 'modelo_espera.pkl'),
)
if not os.path.isfile(MODEL_PATH):
    raise RuntimeError(f"No se encontró el modelo predictivo: {MODEL_PATH}")
modelo_espera = joblib.load(MODEL_PATH)

app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    raise RuntimeError("SECRET_KEY debe estar configurada en el entorno.")
# ==========================================
# 3. CONFIGURACIÓN JWT
jwt_secret_key = os.getenv('JWT_SECRET_KEY')
if not jwt_secret_key:
    raise RuntimeError("JWT_SECRET_KEY debe estar configurada en el entorno.")
app.config['JWT_SECRET_KEY'] = jwt_secret_key
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_CSRF_CHECK_FORM'] = True
app.config['JWT_COOKIE_SAMESITE'] = 'Lax'
app.config['JWT_COOKIE_SECURE'] = os.getenv('JWT_COOKIE_SECURE', 'true').lower() == 'true'
app.config['JWT_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.getenv('JWT_COOKIE_SECURE', 'true').lower() == 'true'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = int(
    os.getenv('JWT_ACCESS_TOKEN_EXPIRES_MINUTES', '1')
) * 60

jwt = JWTManager(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=os.getenv('RATELIMIT_STORAGE_URI', 'memory://'),
)
ensure_audit_schema()


@app.get('/healthz')
def healthz():
    """Endpoint liviano para health checks de Render."""
    return {'status': 'ok'}, 200

# ==========================================
# MANEJO DE ERRORES JWT (Para redireccionar al Login)
# ==========================================
@jwt.unauthorized_loader
def missing_token_callback(error):
    """Se ejecuta si el usuario no tiene la cookie (ej. intentó entrar directo a /paciente)"""
    flash("Por favor, inicia sesión para acceder.", "error")
    return redirect(url_for('login'))

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    """Se ejecuta si el token ya superó su tiempo de vida"""
    flash("Tu sesión ha expirado. Por favor, inicia sesión de nuevo.", "error")
    return redirect(url_for('login'))

@jwt.invalid_token_loader
def invalid_token_callback(error):
    """Se ejecuta si alguien intentó falsificar la cookie"""
    print(f"\n[ERROR DE JWT DETECTADO]: {error}\n")
    flash("Firma de sesión inválida. Inicia sesión nuevamente.", "error")
    return redirect(url_for('login'))


@app.errorhandler(429)
def rate_limit_callback(error):
    """Muestra el límite de intentos en el mismo formulario de autenticación."""
    flash(
        "Límite de ingreso de contraseña permitido alcanzado; "
        "favor espere 1 minuto para intentar de nuevo.",
        "error",
    )
    return redirect(url_for('login'))


# ... (Aquí continúa el @app.context_processor que ya tenías) ...

# ==========================================
# CONTEXTO PARA EL MENÚ HTML
# ==========================================
@app.context_processor
def inyectar_usuario():
    try:
        verify_jwt_in_request(optional=True)
        usuario_actual = get_jwt_identity() # Esto ahora devuelve el string 'admin'
        if usuario_actual:
            claims = get_jwt() # Obtenemos los datos extra
            return dict(
                usuario_jwt=usuario_actual,
                rol_jwt=claims.get('rol'),
                csrf_token=claims.get('csrf'),
            )
    except Exception:
        pass
    return dict(usuario_jwt=None, rol_jwt=None, csrf_token=None)

# ==========================================
# DECORADORES PARA CONTROL DE ACCESO
# ==========================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        verify_jwt_in_request()
        if not _jwt_user_is_active():
            flash("La cuenta está suspendida o la sesión fue invalidada.", "error")
            return redirect(url_for('logout'))
        return f(*args, **kwargs)
    return decorated_function


def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            verify_jwt_in_request()
            if not _jwt_user_is_active():
                flash("La cuenta está suspendida o la sesión fue invalidada.", "error")
                return redirect(url_for('logout'))
            if get_jwt().get('rol') not in roles:
                flash("Acceso denegado. No tiene permisos suficientes.", "error")
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def _jwt_user_is_active() -> bool:
    """Comprueba suspensión y versión para invalidación inmediata de JWT."""
    username = get_jwt_identity()
    claims = get_jwt()
    conn = obtener_conexion()
    if conn is None:
        return False
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT is_suspended, token_version
                FROM usuarios
                WHERE username = %s
                """,
                (username,),
            )
            row = cursor.fetchone()
            return bool(
                row
                and not row[0]
                and int(row[1]) == int(claims.get('token_version', -1))
            )
    finally:
        conn.close()


# ==========================================
# 3. RUTAS DE AUTENTICACIÓN
# ==========================================
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("3 per minute", methods=["POST"])
def login():
    if request.method == 'POST':
        user_input = request.form['username']
        pass_input = request.form['password']
        
        conn = obtener_conexion()
        usuario_db = None
        if conn:
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT username, password_hash, rol, mfa_secret_ciphertext,
                               mfa_enabled, token_version, is_suspended
                        FROM usuarios WHERE username = %s
                        """,
                        (user_input,),
                    )
                    usuario_db = cursor.fetchone()
            finally:
                conn.close()

        password_valida = bool(
            usuario_db
            and (
                verify_password(usuario_db[1], pass_input)
                or verify_legacy_password(usuario_db[1], pass_input)
            )
        )
        if password_valida and not usuario_db[6]:
            if usuario_db[1].startswith(("scrypt:", "pbkdf2:")):
                conn = obtener_conexion()
                if conn is None:
                    flash("No se pudo completar la migración segura de la contraseña.", "error")
                    return render_template('login.html')
                try:
                    with conn:
                        with conn.cursor() as cursor:
                            cursor.execute(
                                "UPDATE usuarios SET password_hash = %s WHERE username = %s",
                                (hash_password(pass_input), usuario_db[0]),
                            )
                finally:
                    conn.close()
            secret = decrypt_totp_secret(usuario_db[3])
            if not secret:
                secret = generate_totp_secret()
                conn = obtener_conexion()
                if conn is None:
                    raise RuntimeError("No se pudo preparar el segundo factor.")
                try:
                    with conn:
                        with conn.cursor() as cursor:
                            cursor.execute(
                                """
                                UPDATE usuarios
                                SET mfa_secret_ciphertext = %s, mfa_enabled = FALSE
                                WHERE username = %s
                                """,
                                (encrypt_totp_secret(secret), usuario_db[0]),
                            )
                finally:
                    conn.close()
            session['mfa_pending'] = {
                'username': usuario_db[0],
                'rol': usuario_db[2],
                'token_version': usuario_db[5],
            }
            session['mfa_setup'] = not usuario_db[4]
            return redirect(url_for('login_mfa'))
        elif usuario_db and usuario_db[6]:
            flash("La cuenta está suspendida. Contacte al administrador.", "error")
        else:
            flash("Usuario o contraseña incorrectos", "error")
            
    return render_template('login.html')


@app.route('/login/mfa', methods=['GET', 'POST'])
@limiter.limit("3 per minute", methods=["POST"])
def login_mfa():
    pending = session.get('mfa_pending')
    if not pending:
        flash("Debe iniciar sesión antes de validar el segundo factor.", "error")
        return redirect(url_for('login'))
    conn = obtener_conexion()
    if conn is None:
        raise RuntimeError("No se pudo consultar la configuración MFA.")
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT mfa_secret_ciphertext, mfa_enabled FROM usuarios WHERE username = %s",
                (pending['username'],),
            )
            row = cursor.fetchone()
    finally:
        conn.close()
    secret = decrypt_totp_secret(row[0]) if row else None
    if not secret:
        raise RuntimeError("La cuenta no tiene semilla MFA configurada.")
    if request.method == 'POST':
        if verify_totp_code(secret, request.form.get('code', '').strip()):
            conn = obtener_conexion()
            if conn is None:
                raise RuntimeError("No se pudo activar MFA.")
            try:
                with conn:
                    with conn.cursor() as cursor:
                        cursor.execute(
                            "UPDATE usuarios SET mfa_enabled = TRUE WHERE username = %s",
                            (pending['username'],),
                        )
            finally:
                conn.close()
            token = create_access_token(
                identity=pending['username'],
                additional_claims={
                    'rol': pending['rol'],
                    'token_version': pending['token_version'],
                },
            )
            session.pop('mfa_pending', None)
            session.pop('mfa_setup', None)
            response = redirect(url_for('home'))
            set_access_cookies(response, token)
            return response
        flash("Código MFA inválido o expirado.", "error")
    qr_code = create_enrollment_qr(pending['username'], secret) if session.get('mfa_setup') else None
    return render_template('login_mfa.html', qr_code=qr_code, enrollment=session.get('mfa_setup'))
@app.route('/logout')
def logout():
    respuesta = redirect(url_for('login'))
    unset_jwt_cookies(respuesta) # Destruye el token/cookie
    return respuesta

# ==========================================
# 4. RUTAS PRINCIPALES (PROTEGIDAS)
# ==========================================
@app.route('/')
@login_required
def home():
    return render_template('home.html')

# --- CRUD: PACIENTE ---
@app.route('/paciente', methods=['GET', 'POST'])
@login_required
def paciente():
    if request.method == 'POST':
        nombre = request.form['nombre']
        apellido = request.form['apellido']
        fechaNacimiento = request.form['fechaNacimiento']
        genero = request.form['genero']
        telefono = request.form['telefono']
        
        conn = obtener_conexion()
        if conn:
            try:
                cursor = conn.cursor()
                # Ajusta el nombre de la tabla según tu esquema (ej. DimPaciente)
                cursor.execute("""
                    INSERT INTO pacientes (nombre, apellido, fecha_nacimiento, genero, telefono) 
                    VALUES (%s, %s, %s, %s, %s)
                """, (nombre, apellido, fechaNacimiento, genero, encrypt_sensitive(telefono)))
                conn.commit()
                flash("Paciente registrado con éxito.", "success")
            except Exception as e:
                flash(f"Error en la base de datos: {e}", "error")
            finally:
                conn.close()
    return render_template('paciente.html')

# --- CRUD: DOCTOR ---
@app.route('/doctor', methods=['GET', 'POST'])
@login_required
def doctor():
    if request.method == 'POST':
        nombre = request.form['nombre']
        especialidad = request.form['especialidad']
        estado = request.form['estado']
        
        conn = obtener_conexion()
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO doctores (nombre_completo, especialidad, estado) 
                    VALUES (%s, %s, %s)
                """, (nombre, especialidad, estado))
                conn.commit()
                flash("Doctor registrado con éxito.", "success")
            except Exception as e:
                flash(f"Error en BD: {e}", "error")
            finally:
                conn.close()
    return render_template('doctor.html')

# --- CRUD: ESPECIALIDAD ---
@app.route('/especialidad', methods=['GET', 'POST'])
@login_required
def especialidad():
    if request.method == 'POST':
        nombre = request.form['nombre']
        costo = request.form['costo']
        precio = request.form['precio']
        
        conn = obtener_conexion()
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO servicios_medicos (nombre_servicio, costo, precio_venta) 
                    VALUES (%s, %s, %s)
                """, (nombre, costo, precio))
                conn.commit()
                flash("Especialidad registrada.", "success")
            except Exception as e:
                flash(f"Error en BD: {e}", "error")
            finally:
                conn.close()
    return render_template('especialidad.html')

# --- CRUD: CONSULTA ---
@app.route('/consulta', methods=['GET', 'POST'])
@login_required
@log_audit('READ', 'visitas')
def consulta():
    conn = obtener_conexion()
    if not conn:
        flash("Error de conexión a la base de datos.", "error")
        return redirect(url_for('home'))
    
    # IMPORTANTE: Quitamos 'cursor_factory=RealDictCursor' 
    # para que p[0] y p[1] funcionen en el HTML
    cursor = conn.cursor()
    prediccion_ia = None

    try:
        if request.method == 'POST':
            # CASO A: IA
            if 'btn_predecir' in request.form:
                try:
                    # Usamos .get() por seguridad
                    id_doc = int(request.form.get('id_doctor'))
                    id_serv = int(request.form.get('id_servicio'))
                    
                    ahora = datetime.now()
                    hora_decimal = ahora.hour + (ahora.minute / 60)

                    if modelo_espera:
                        resultado = modelo_espera.predict([[id_doc, id_serv, hora_decimal]])
                        prediccion_ia = round(resultado[0])
                except Exception as e:
                    print(f"Error IA: {e}")

            # CASO B: GUARDAR
            elif 'btn_guardar' in request.form:
                # Los nombres deben coincidir con el 'name' de tus inputs en HTML
                datos_visita = (
                    request.form['id_paciente'],
                    request.form['id_doctor'],
                    request.form['id_servicio'],
                    encrypt_sensitive(request.form['diagnostico']),
                    request.form['fecha_consulta'],
                    request.form['hora_llegada'],
                    request.form['hora_atencion'],
                    request.form['estado_visita']
                )
                
                cursor.execute("""
                    INSERT INTO visitas 
                    (paciente_id, doctor_id, servicio_id, diagnostico, fecha_consulta, hora_llegada, hora_atencion, estado_visita) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, datos_visita)
                conn.commit()
                write_audit_log('WRITE', 'visitas')
                flash("Consulta guardada exitosamente.", "success")

        # ==========================================
        # CARGA DE DATOS PARA LOS DESPLEGABLES
        # ==========================================
        # Asegúrate de que estos nombres de columna existan en Supabase
        cursor.execute("SELECT paciente_id, nombre, apellido FROM pacientes")
        lista_pacientes = cursor.fetchall()
        
        cursor.execute("SELECT doctor_id, nombre_completo FROM doctores")
        lista_doctores = cursor.fetchall()
        
        cursor.execute("SELECT servicio_id, nombre_servicio FROM servicios_medicos")
        lista_servicios = cursor.fetchall()

    except Exception as e:
        flash(f"Error al procesar la consulta: {e}", "error")
        lista_pacientes, lista_doctores, lista_servicios = [], [], []
    finally:
        conn.close()

    return render_template('consulta.html', 
                           pacientes=lista_pacientes, 
                           doctores=lista_doctores,
                           servicios=lista_servicios,
                           prediccion_ia=prediccion_ia)

# --- CRUD: FACTURACIÓN ---
@app.route('/facturacion', methods=['GET', 'POST'])
@login_required
@log_audit('READ', 'facturacion')
def facturacion():
    conn = obtener_conexion()
    cursor = conn.cursor()
    
    # 1. Cargamos pacientes para el select
    cursor.execute("SELECT paciente_id, nombre, apellido FROM pacientes")
    lista_pacientes = cursor.fetchall()
    
    items = []
    total = 0
    paciente_seleccionado = None

    if request.method == 'POST':
        # ==========================================
        # ACCIÓN A: EL USUARIO BUSCÓ AL PACIENTE
        # ==========================================
        if 'btn_buscar' in request.form:
            id_p = request.form['id_paciente']
            
            cursor.execute("SELECT nombre, apellido, paciente_id FROM pacientes WHERE paciente_id = %s", (id_p,))
            paciente_seleccionado = cursor.fetchone()

            # Traemos el visita_id, nombre del servicio y costo (filtramos las ya pagadas/canceladas)
            cursor.execute("""
                SELECT v.visita_id, s.nombre_servicio, s.precio_venta
                FROM visitas v
                JOIN servicios_medicos s ON v.servicio_id = s.servicio_id
                WHERE v.paciente_id = %s AND v.estado_visita NOT IN ('Cancelada', 'Pagada', 'Finalizada')
            """, (id_p,))
            items = cursor.fetchall()
            
            # Sumamos el costo (índice 2 ahora porque agregamos visita_id)
            total = sum(item[2] for item in items)

        # ==========================================
        # ACCIÓN B: EL USUARIO GUARDÓ LA FACTURA
        # ==========================================
        elif 'btn_guardar_factura' in request.form:
            id_p = request.form['id_paciente_oculto']
            
            # Volvemos a buscar las visitas pendientes para guardarlas
            cursor.execute("""
                SELECT v.visita_id, s.precio_venta 
                FROM visitas v
                JOIN servicios_medicos s ON v.servicio_id = s.servicio_id
                WHERE v.paciente_id = %s AND v.estado_visita NOT IN ('Cancelada', 'Pagada', 'Finalizada')
            """, (id_p,))
            visitas_pendientes = cursor.fetchall()
            
            try:
                for visita in visitas_pendientes:
                    id_visita = visita[0]
                    monto = visita[1]
                    
                    # 1. Insertamos en la tabla de facturación
                    cursor.execute("""
                        INSERT INTO facturacion (visita_id, monto_total)
                        VALUES (%s, %s)
                    """, (id_visita, monto))
                    
                    # 2. Actualizamos la visita para que ya no vuelva a salir por cobrar
                    cursor.execute("""
                        UPDATE visitas SET estado_visita = 'Pagada' WHERE visita_id = %s
                    """, (id_visita,))
                
                conn.commit()
                write_audit_log('WRITE', 'facturacion')
                flash("¡Factura guardada con éxito en la base de datos!", "success")
            except Exception as e:
                conn.rollback() # Si hay error, deshace los cambios por seguridad
                flash(f"Error al guardar la factura: {e}", "error")

    conn.close()
    return render_template('facturacion.html', 
                           pacientes=lista_pacientes, 
                           items=items, 
                           total=total, 
                           p_sel=paciente_seleccionado)

# Función para validar la complejidad de la contraseña
def validar_password(password):
    if len(password) < 8:
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

@app.route('/registro_usuario', methods=['GET', 'POST'])
@roles_required('Admin')
def registro_usuario():
    if request.method == 'POST':
        nombre = request.form['nombre']
        dpi = request.form['dpi']
        edad = request.form['edad']
        telefono = request.form['telefono']
        user = request.form['username']
        password = request.form['password']
        rol = request.form['rol']

        if rol not in ('Admin', 'Usuario'):
            flash("El rol seleccionado no es válido.", "error")
            return redirect(url_for('registro_usuario'))

        # 1. Validar reglas de la contraseña
        if not validar_password(password):
            flash("La contraseña no cumple los requisitos (8 caracteres, 1 Mayúscula, 1 Especial).", "error")
            return redirect(url_for('registro_usuario'))

        # 2. Cifrar la contraseña
        password_encriptada = hash_password(password)

        try:
            conn = obtener_conexion()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO usuarios (nombre_completo, dpi, edad, telefono, username, password_hash, rol)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (nombre, encrypt_sensitive(dpi), edad, encrypt_sensitive(telefono),
                  user, password_encriptada, rol))
            conn.commit()
            conn.close()
            flash(f"Usuario {user} creado exitosamente.", "success")
        except Exception as e:
            flash(f"Error al crear usuario: {e}", "error")

    return render_template('registro_usuario.html')

    # ==========================================
    # CARGAR MODELO DE IA
    # ==========================================
@app.route('/predecir_espera', methods=['POST'])
@login_required
def predecir_espera():
    id_doctor = int(request.form['doctor_id'])
    id_servicio = int(request.form['servicio_id'])
    
    # Obtener la hora actual en formato decimal (ej: 14.5 para las 2:30 PM)
    ahora = datetime.now()
    hora_decimal = ahora.hour + (ahora.minute / 60)

    # La IA predice los minutos
    prediccion = modelo_espera.predict([[id_doctor, id_servicio, hora_decimal]])
    minutos_estimados = round(prediccion[0])

    return {
        "status": "success",
        "minutos_estimados": minutos_estimados,
        "mensaje": f"El tiempo de espera estimado para este doctor es de {minutos_estimados} minutos."
    }
# --- KPIS (SOLO ADMIN) ---
@app.route('/kpis')
@roles_required('Admin')
@log_audit('READ', 'kpis')
def kpis():
    # Reemplaza con tu URL real de publicación de Power BI
    url_power_bi = "https://app.powerbi.com/view?r=eyJrIjoiOGU1MzhhMzItMDhjNy00YjA4LWIzMTItZGZiZDY1YzY1ZjA2IiwidCI6IjVmNTNiNGNlLTYzZDQtNGVlOC04OGQyLTIyZjBiMmQ0YjI3YSIsImMiOjR9"
    return render_template('kpis.html', pbi_url=url_power_bi)

if __name__ == '__main__':
    app.run(
        debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true',
        port=int(os.getenv('PORT', '5000')),
    )