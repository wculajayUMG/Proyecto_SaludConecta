"""Controles de contención rápida para cuentas comprometidas."""

from database.conexion import obtener_conexion


def contain_compromised_user(user_id: str) -> None:
    """Suspende la cuenta e invalida tokens mediante incremento de token_version."""
    conn = obtener_conexion()
    if conn is None:
        raise RuntimeError("No se pudo conectar para contener la cuenta.")
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE usuarios
                    SET is_suspended = TRUE,
                        token_version = COALESCE(token_version, 0) + 1
                    WHERE username = %s
                    """,
                    (user_id,),
                )
                if cursor.rowcount != 1:
                    raise ValueError("La cuenta indicada no existe.")
    finally:
        conn.close()
