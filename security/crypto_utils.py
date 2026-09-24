"""Primitivas criptográficas centralizadas para datos y credenciales."""

import base64
import hashlib
import hmac
import os
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.security import check_password_hash

_password_hasher = PasswordHasher()


def _master_key() -> bytes:
    """Obtiene la clave de 256 bits usada por AES-GCM."""
    value = os.getenv("MASTER_ENCRYPTION_KEY")
    if not value:
        raise RuntimeError("MASTER_ENCRYPTION_KEY no está configurada.")
    try:
        key = base64.urlsafe_b64decode(value.encode("ascii"))
        if len(key) != 32:
            raise ValueError
        return key
    except (ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError(
            "MASTER_ENCRYPTION_KEY debe ser una clave Base64 URL-safe de 32 bytes."
        ) from exc
    except Exception as exc:
        raise RuntimeError("MASTER_ENCRYPTION_KEY no es una clave Base64 válida.") from exc


def encrypt_sensitive(value: Optional[str]) -> Optional[str]:
    """Cifra un valor con AES-256-GCM y devuelve nonce+ciphertext en Base64."""
    if value is None:
        return None
    nonce = os.urandom(12)
    ciphertext = AESGCM(_master_key()).encrypt(nonce, value.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_sensitive(value: Optional[str]) -> Optional[str]:
    """Descifra un valor previamente cifrado."""
    if value is None:
        return None
    try:
        encrypted = base64.urlsafe_b64decode(value.encode("ascii"))
        return AESGCM(_master_key()).decrypt(
            encrypted[:12], encrypted[12:], None
        ).decode("utf-8")
    except (InvalidTag, UnicodeError, ValueError) as exc:
        raise ValueError("No se pudo descifrar el dato sensible.") from exc


def pseudonymize(value: str) -> str:
    """Genera un pseudónimo estable HMAC-SHA256 para una identidad."""
    digest = hmac.new(_master_key(), value.encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()


def hash_password(password: str) -> str:
    """Genera un hash Argon2id con parámetros seguros por defecto."""
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Verifica una contraseña Argon2id sin propagar fallos de comparación."""
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def verify_legacy_password(password_hash: str, password: str) -> bool:
    """Verifica hashes Werkzeug antiguos durante la migración a Argon2id."""
    if not password_hash.startswith(("scrypt:", "pbkdf2:")):
        return False
    return check_password_hash(password_hash, password)


def verify_database_integrity() -> dict[str, str]:
    """Calcula SHA-256 reproducibles sobre tablas clínicas para detectar alteraciones."""
    from database.conexion import obtener_conexion

    tables = ("pacientes", "doctores", "servicios_medicos", "visitas", "facturacion")
    conn = obtener_conexion()
    if conn is None:
        raise RuntimeError("No se pudo conectar para verificar integridad.")
    checksums: dict[str, str] = {}
    try:
        with conn.cursor() as cursor:
            for table in tables:
                cursor.execute(
                    f"""
                    SELECT COALESCE(
                        string_agg(row_to_json(t)::text, '' ORDER BY t::text),
                        ''
                    )
                    FROM (SELECT * FROM {table}) AS t
                    """
                )
                serialized = (cursor.fetchone()[0] or "").encode("utf-8")
                checksums[table] = hashlib.sha256(serialized).hexdigest()
    finally:
        conn.close()
    return checksums
