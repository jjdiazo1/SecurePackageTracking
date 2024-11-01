import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Cargar el archivo CSV
data = pd.read_csv("Auxiliar/test_results.csv")

# Configurar el estilo de las gráficas
sns.set(style="whitegrid")

# (i) Comparación de tiempos para descifrar el reto en los diferentes escenarios
plt.figure(figsize=(10, 6))
challenge_data = data[data["Operación"] == "TiempoDeRespuestaDesafío"]
sns.boxplot(x="Escenario", y="Tiempo(ns)", data=challenge_data)
plt.title("Tiempos para Descifrar el Reto en Diferentes Escenarios")
plt.xlabel("Escenario")
plt.ylabel("Tiempo (ns)")
plt.yscale('log')  # Usar escala logarítmica
plt.xticks(rotation=45)
plt.show()

# (ii) Comparación de tiempos para generar G, P y G^x en los diferentes escenarios
plt.figure(figsize=(10, 6))
dh_data = data[data["Operación"] == "TiempoDeGeneraciónDH"]
sns.boxplot(x="Escenario", y="Tiempo(ns)", data=dh_data)
plt.title("Tiempos para Generar G, P y G^x en Diferentes Escenarios")
plt.xlabel("Escenario")
plt.ylabel("Tiempo (ns)")
plt.yscale('log')  # Usar escala logarítmica
plt.xticks(rotation=45)
plt.show()

# (iii) Tiempos para verificar la consulta en los diferentes escenarios
plt.figure(figsize=(10, 6))
verification_data = data[data["Operación"] == "TiempoDeVerificación"]
sns.boxplot(x="Escenario", y="Tiempo(ns)", data=verification_data)
plt.title("Tiempos para Verificar la Consulta en Diferentes Escenarios")
plt.xlabel("Escenario")
plt.ylabel("Tiempo (ns)")
plt.yscale('log')  # Usar escala logarítmica
plt.xticks(rotation=45)
plt.show()

# (iv) Comparación de tiempos de cifrado simétrico y asimétrico en diferentes escenarios
plt.figure(figsize=(10, 6))
encryption_data = data[data["Operación"].isin(["TiempoDeCifradoSimétrico", "TiempoDeCifradoAsimétrico"])]
sns.boxplot(x="Escenario", y="Tiempo(ns)", hue="Operación", data=encryption_data)
plt.title("Tiempos de Cifrado Simétrico y Asimétrico en Diferentes Escenarios")
plt.xlabel("Escenario")
plt.ylabel("Tiempo (ns)")
plt.yscale('log')  # Usar escala logarítmica
plt.legend(title="Operación")
plt.xticks(rotation=45)
plt.show()