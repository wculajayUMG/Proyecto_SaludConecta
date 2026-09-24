"""MFA TOTP conforme a RFC 6238 para todos los roles de la aplicación."""

import base64
import io
import os
from typing import Optional

import pyotp
import qrcode

from security.crypto_utils import decrypt_sensitive, encrypt_sensitive


def generate_totp_secret() -> str:
    """Genera una semilla aleatoria única para un usuario."""
    return pyotp.random_base32()


def create_enrollment_uri(username: str, secret: str) -> str:
    """Construye la URI otpauth compatible con Google/Microsoft Authenticator."""
    issuer = os.getenv("MFA_ISSUER_NAME", "SaludConecta")
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def create_enrollment_qr(username: str, secret: str) -> str:
    """Devuelve el QR de enrolamiento como data URI SVG para Jinja2."""
    from qrcode.image.svg import SvgImage

    image = qrcode.make(create_enrollment_uri(username, secret), image_factory=SvgImage)
    buffer = io.BytesIO()
    image.save(buffer)
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"


def encrypt_totp_secret(secret: str) -> str:
    """Cifra la semilla antes de persistirla en PostgreSQL."""
    encrypted = encrypt_sensitive(secret)
    if encrypted is None:
        raise RuntimeError("No se pudo cifrar la semilla TOTP.")
    return encrypted


def decrypt_totp_secret(ciphertext: Optional[str]) -> Optional[str]:
    """Descifra una semilla TOTP almacenada."""
    return decrypt_sensitive(ciphertext)


def verify_totp_code(secret: str, code: str) -> bool:
    """Valida un código de seis dígitos con una ventana temporal de 30 segundos."""
    if not code.isdigit() or len(code) != 6:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)
