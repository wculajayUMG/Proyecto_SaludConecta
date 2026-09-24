"""Backup PostgreSQL cifrado para recuperación objetivo RTO < 4 horas."""

import base64
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))


def _key() -> bytes:
    value = os.getenv("MASTER_ENCRYPTION_KEY")
    if not value:
        raise RuntimeError("MASTER_ENCRYPTION_KEY no está configurada.")
    key = base64.urlsafe_b64decode(value.encode("ascii"))
    if len(key) != 32:
        raise RuntimeError("MASTER_ENCRYPTION_KEY debe contener 32 bytes.")
    return key


def create_encrypted_backup() -> Path:
    """Exporta tablas de aplicación, cifra el dump y elimina el temporal."""
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL no está configurada.")
    output_dir = Path(os.getenv("BACKUP_OUTPUT_DIR", "backups"))
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    temporary_dump = output_dir / f".saludconecta-{stamp}.dump"
    destination = output_dir / f"saludconecta-{stamp}.dump.enc"
    tables = (
        "usuarios", "pacientes", "doctores", "servicios_medicos",
        "visitas", "facturacion", "audit_logs",
    )
    command = ["pg_dump", database_url, "--format=custom", "--file", str(temporary_dump)]
    for table in tables:
        command.extend(["--table", table])
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        plaintext = temporary_dump.read_bytes()
        nonce = os.urandom(12)
        ciphertext = AESGCM(_key()).encrypt(nonce, plaintext, stamp.encode("ascii"))
        destination.write_bytes(b"SCB1" + nonce + ciphertext)
        return destination
    finally:
        temporary_dump.unlink(missing_ok=True)


if __name__ == "__main__":
    print(create_encrypted_backup())
