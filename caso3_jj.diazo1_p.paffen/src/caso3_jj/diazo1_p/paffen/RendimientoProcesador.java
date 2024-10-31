package caso3_jj.diazo1_p.paffen;

import java.io.*;
import java.util.*;

public class RendimientoProcesador {
    public static void estimarYEscribirEnArchivo() {
        try {
            // Leer los datos de tiempos desde test_results.csv
            Map<String, List<Long>> mapaDatos = new HashMap<>();
            BufferedReader lector = new BufferedReader(new FileReader("resultados_pruebas.csv"));
            String linea;
            lector.readLine(); // Saltar la cabecera

            while ((linea = lector.readLine()) != null) {
                String[] partes = linea.split(",");
                String operacion = partes[1];
                long tiempo = Long.parseLong(partes[2]);

                mapaDatos.computeIfAbsent(operacion, k -> new ArrayList<>()).add(tiempo);
            }
            lector.close();

            // Calcular los tiempos promedio para cifrado simétrico y asimétrico
            double tiempoPromedioSimetricoNs = calcularPromedio(mapaDatos.get("TiempoCifradoSimetrico"));
            double tiempoPromedioAsimetricoNs = calcularPromedio(mapaDatos.get("TiempoCifradoAsimetrico"));

            // Convertir de nanosegundos a segundos para los cálculos de operaciones por segundo
            double tiempoPromedioSimetricoSeg = tiempoPromedioSimetricoNs / 1_000_000_000.0;
            double tiempoPromedioAsimetricoSeg = tiempoPromedioAsimetricoNs / 1_000_000_000.0;

            // Estimar operaciones por segundo
            double operacionesSimetricasPorSeg = 1 / tiempoPromedioSimetricoSeg;
            double operacionesAsimetricasPorSeg = 1 / tiempoPromedioAsimetricoSeg;

            // Obtener velocidad del procesador
            String velocidadProcesador = obtenerVelocidadProcesador();

            // Escribir los resultados y cálculos paso a paso en el archivo
            PrintWriter escritor = new PrintWriter(new FileWriter("rendimiento_procesador.txt"));
            escritor.println("Estimación de Rendimiento del Procesador");
            escritor.println("=======================================");
            escritor.println("Velocidad del Procesador: " + velocidadProcesador);
            escritor.println();
            
            escritor.println("Cálculos de Cifrado Simétrico:");
            escritor.println("---------------------------------");
            escritor.printf("Tiempo Total de Cifrado Simétrico (ns): %.2f\n", tiempoPromedioSimetricoNs);
            escritor.printf("Tiempo Promedio de Cifrado Simétrico (s): %.12f\n", tiempoPromedioSimetricoSeg);
            escritor.printf("Operaciones de Cifrado Simétrico por Segundo: %.2f\n", operacionesSimetricasPorSeg);
            escritor.println();

            escritor.println("Cálculos de Cifrado Asimétrico:");
            escritor.println("-----------------------------------");
            escritor.printf("Tiempo Total de Cifrado Asimétrico (ns): %.2f\n", tiempoPromedioAsimetricoNs);
            escritor.printf("Tiempo Promedio de Cifrado Asimétrico (s): %.12f\n", tiempoPromedioAsimetricoSeg);
            escritor.printf("Operaciones de Cifrado Asimétrico por Segundo: %.2f\n", operacionesAsimetricasPorSeg);
            escritor.println();

            escritor.println("Explicación de los Cálculos:");
            escritor.println("----------------------------");
            escritor.println("1. Calculamos el tiempo promedio en nanosegundos sumando todos los tiempos");
            escritor.println("   individuales de las operaciones y dividiéndolo entre la cantidad de operaciones.");
            escritor.println("2. Convertimos el tiempo promedio de nanosegundos a segundos dividiendo por");
            escritor.println("   1,000,000,000 para obtener el tiempo en segundos.");
            escritor.println("3. Estimamos las operaciones por segundo tomando el inverso del tiempo promedio");
            escritor.println("   en segundos (1 / tiempo_promedio_segundos).");
            escritor.println();
            escritor.println("Nota: Estos cálculos se basan en los datos proporcionados en el archivo 'resultados_pruebas.csv'.");
            
            escritor.close();

            System.out.println("Estimación de rendimiento del procesador guardada en rendimiento_procesador.txt");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static double calcularPromedio(List<Long> tiempos) {
        if (tiempos == null || tiempos.isEmpty()) {
            return 0;
        }
        long suma = 0;
        for (Long tiempo : tiempos) {
            suma += tiempo;
        }
        return (double) suma / tiempos.size();
    }

    private static String obtenerVelocidadProcesador() {
        // Pedir al usuario la velocidad del procesador en GHz
        Scanner scanner = new Scanner(System.in);
        System.out.print("Por favor, ingrese la velocidad de su procesador en GHz (por ejemplo, 2.5): ");
        String velocidad = scanner.nextLine();
        scanner.close();
        return velocidad + " GHz";
    }
}