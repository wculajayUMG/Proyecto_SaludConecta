import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestRegressor
import joblib
import random

print("Generando datos históricos para predicción de tiempo de espera...")

datos = []
# Simulamos 1500 visitas
for _ in range(1500):
    doctor_id = random.randint(1, 5) # Simulamos 5 doctores con diferentes ritmos
    servicio_id = random.randint(1, 3) # 1: Consulta Gral, 2: Especialidad, 3: Urgencia
    hora_llegada_decimal = random.uniform(8, 17) # De 8:00 AM a 5:00 PM
    
    # LÓGICA PARA QUE LA IA APRENDA:
    # Doctor 3 siempre es lento (+20 min)
    # Servicio 2 (Especialidad) siempre tarda más (+15 min)
    # Horas pico (12:00 a 14:00) añaden espera (+10 min)
    
    espera_base = random.randint(5, 15) # Espera normal de 5 a 15 min
    
    if doctor_id == 3: espera_base += 20
    if servicio_id == 2: espera_base += 15
    if 12 <= hora_llegada_decimal <= 14: espera_base += 10
    
    datos.append([doctor_id, servicio_id, hora_llegada_decimal, espera_base])

# Crear DataFrame
df = pd.DataFrame(datos, columns=['doctor_id', 'servicio_id', 'hora_llegada', 'minutos_espera'])

# Entrenar el Regresor
X = df[['doctor_id', 'servicio_id', 'hora_llegada']]
y = df['minutos_espera']

print("Entrenando IA de tiempos de respuesta...")
modelo_tiempos = RandomForestRegressor(n_estimators=100, random_state=42)
modelo_tiempos.fit(X, y)

# Guardar
joblib.dump(modelo_tiempos, 'modelo_espera.pkl')
print("✅ ¡Modelo de tiempos guardado como 'modelo_espera.pkl'!")