# database/conexion.py
import os
import logging
from dotenv import load_dotenv
import psycopg2

# Cargar las variables del archivo .env
load_dotenv()
logger = logging.getLogger(__name__)

def obtener_conexion():
    # Leemos la URL desde el entorno
    database_url = os.getenv('DATABASE_URL')
    
    if not database_url:
        logger.error("DATABASE_URL no está configurada en .env")
        return None

    try:
        conn = psycopg2.connect(
            database_url,
            sslmode=os.getenv('DB_SSLMODE', 'require'),
        )
        return conn
    except Exception as e:
        logger.error("Error conectando a la base de datos: %s", e)
        return None
