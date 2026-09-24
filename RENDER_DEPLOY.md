# Despliegue en Render con Supabase

## 1. Publicar el repositorio

No publiques `.env`, `venv/`, `backups/`, archivos de claves ni datos locales. El
archivo `modelo_espera.pkl` se mantiene en el repositorio porque la ruta
`/consulta` lo necesita para ejecutar la predicción de espera. Verifica que el
modelo no contenga datos identificables de pacientes antes de publicar.

## 2. Crear el servicio

En Render, selecciona **New > Blueprint** y apunta al repositorio. Render leerá
`render.yaml`, instalará `requirements.txt` y ejecutará Gunicorn mediante
`app:app`.

También se puede crear un Web Service manualmente con:

- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120 app:app`
- Health check path: `/healthz`

## 3. Variables obligatorias

Configura estas variables en Render, nunca en el repositorio:

- `DATABASE_URL`: cadena de conexión PostgreSQL de Supabase.
- `MASTER_ENCRYPTION_KEY`: la misma clave usada para cifrar los datos existentes.
- `RATELIMIT_STORAGE_URI`: Redis administrado para rate limiting compartido entre
  instancias; `memory://` solo es apropiado para una instancia temporal.

`SECRET_KEY` y `JWT_SECRET_KEY` se generan automáticamente mediante `render.yaml`.
Si el servicio ya tenía datos, conserva la `MASTER_ENCRYPTION_KEY`; cambiarla sin
recifrar la base de datos impide descifrar diagnósticos, teléfonos, DPI y semillas
MFA existentes.

## 4. Supabase

Usa la URL de conexión de Supabase con SSL y deja `DB_SSLMODE=require`. Antes del
primer acceso, confirma que el usuario de Supabase tenga permisos para crear las
columnas MFA y la tabla de auditoría. Al iniciar la aplicación se prepara el
esquema requerido.

## 5. MFA inicial

Después del primer despliegue, cada usuario completa el enrolamiento TOTP
escaneando el QR mostrado durante el primer login. Conserva la clave maestra y
realiza respaldos cifrados con `scripts/encrypted_backup.py`.
