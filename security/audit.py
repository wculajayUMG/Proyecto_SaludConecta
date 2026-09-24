"""Auditoría inmutable de accesos y cambios a datos clínicos."""

import hashlib
import json
import logging
from datetime import datetime, timezone
from functools import wraps
from typing import Callable

from flask import request

from database.conexion import obtener_conexion
from flask_jwt_extended import get_jwt_identity

_ACCIONES_VALIDAS = {"READ", "WRITE", "DELETE"}
_logger = logging.getLogger(__name__)


def ensure_audit_schema() -> None:
    """Crea la tabla y las protecciones append-only si aún no existen."""
    conn = obtener_conexion()
    if conn is None:
        _logger.warning("No se pudo preparar la tabla de auditoría.")
        return
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id BIGSERIAL PRIMARY KEY,
                        timestamp_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        usuario_id TEXT NOT NULL,
                        accion VARCHAR(10) NOT NULL
                            CHECK (accion IN ('READ', 'WRITE', 'DELETE')),
                        tabla_afectada VARCHAR(128) NOT NULL,
                        ip_origen INET NOT NULL,
                        hash_integridad CHAR(64) NOT NULL
                    )
                    """
                )
                cursor.execute(
                    """
                    ALTER TABLE usuarios
                    ADD COLUMN IF NOT EXISTS mfa_secret_ciphertext TEXT,
                    ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                    ADD COLUMN IF NOT EXISTS is_suspended BOOLEAN NOT NULL DEFAULT FALSE,
                    ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0
                    """
                )
                for table, column in (
                    ("visitas", "diagnostico"),
                    ("usuarios", "dpi"),
                    ("usuarios", "telefono"),
                    ("pacientes", "telefono"),
                ):
                    cursor.execute(
                        f"ALTER TABLE {table} ALTER COLUMN {column} TYPE TEXT"
                    )
                cursor.execute(
                    """
                    CREATE OR REPLACE FUNCTION impedir_cambios_audit_logs()
                    RETURNS TRIGGER AS $$
                    BEGIN
                        RAISE EXCEPTION 'audit_logs es append-only';
                    END;
                    $$ LANGUAGE plpgsql
                    """
                )
                cursor.execute(
                    """
                    DROP TRIGGER IF EXISTS audit_logs_append_only ON audit_logs;
                    CREATE TRIGGER audit_logs_append_only
                    BEFORE UPDATE OR DELETE ON audit_logs
                    FOR EACH ROW EXECUTE FUNCTION impedir_cambios_audit_logs()
                    """
                )
    except Exception:
        _logger.exception("No se pudo crear el esquema de auditoría.")
    finally:
        conn.close()


def _write_audit_log(action: str, table: str) -> None:
    if action not in _ACCIONES_VALIDAS:
        raise ValueError("Acción de auditoría no permitida.")
    username = get_jwt_identity()
    if not username:
        raise RuntimeError("No existe identidad JWT para registrar auditoría.")
    ip = request.remote_addr or "0.0.0.0"
    timestamp = datetime.now(timezone.utc)
    conn = obtener_conexion()
    if conn is None:
        raise RuntimeError("No se pudo conectar para registrar auditoría.")
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT hash_integridad FROM audit_logs ORDER BY id DESC LIMIT 1"
                )
                previous = cursor.fetchone()
                previous_hash = previous[0] if previous else ""
                payload = json.dumps(
                    {
                        "timestamp_utc": timestamp.isoformat(),
                        "usuario_id": str(username),
                        "accion": action,
                        "tabla_afectada": table,
                        "ip_origen": ip,
                        "previous_hash": previous_hash,
                    },
                    sort_keys=True,
                ).encode("utf-8")
                integrity_hash = hashlib.sha256(payload).hexdigest()
                cursor.execute(
                    """
                    INSERT INTO audit_logs
                        (timestamp_utc, usuario_id, accion, tabla_afectada, ip_origen, hash_integridad)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (timestamp, str(username), action, table, ip, integrity_hash),
                )
    finally:
        conn.close()


def write_audit_log(action: str, table: str) -> None:
    """Registra una operación explícita dentro de una transacción de negocio."""
    _write_audit_log(action, table)


def log_audit(action: str, table: str) -> Callable:
    """Registra automáticamente el acceso exitoso de una ruta protegida."""
    def decorator(view: Callable) -> Callable:
        @wraps(view)
        def wrapped(*args, **kwargs):
            response = view(*args, **kwargs)
            _write_audit_log(action, table)
            return response

        return wrapped

    return decorator
