package caso3_jj.diazo1_p.paffen;

import java.io.*;
import java.util.*;

public class ProcessorPerformanceEstimator {
    public static void estimateAndWriteToFile() {
        try {
            // Leer los datos de tiempos desde test_results.csv
            Map<String, List<Long>> dataMap = new HashMap<>();
            BufferedReader reader = new BufferedReader(new FileReader("test_results.csv"));
            String line;
            reader.readLine(); // Saltar la cabecera

            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                String operation = parts[1];
                long time = Long.parseLong(parts[2]);

                dataMap.computeIfAbsent(operation, k -> new ArrayList<>()).add(time);
            }
            reader.close();

            // Calcular los tiempos promedio para cifrado simétrico y asimétrico
            double avgSymmetricTimeNs = calculateAverage(dataMap.get("SymmetricEncryptionTime"));
            double avgAsymmetricTimeNs = calculateAverage(dataMap.get("AsymmetricEncryptionTime"));

            // Convertir de nanosegundos a segundos para los cálculos de operaciones por segundo
            double avgSymmetricTimeSec = avgSymmetricTimeNs / 1_000_000_000.0;
            double avgAsymmetricTimeSec = avgAsymmetricTimeNs / 1_000_000_000.0;

            // Estimar operaciones por segundo
            double symmetricOpsPerSec = 1 / avgSymmetricTimeSec;
            double asymmetricOpsPerSec = 1 / avgAsymmetricTimeSec;

            // Obtener velocidad del procesador
            String processorSpeed = getProcessorSpeed();

            // Escribir los resultados y cálculos paso a paso en el archivo
            PrintWriter writer = new PrintWriter(new FileWriter("processor_performance.txt"));
            writer.println("Processor Performance Estimation");
            writer.println("==============================");
            writer.println("Processor Speed: " + processorSpeed);
            writer.println();
            
            writer.println("Symmetric Encryption Calculations:");
            writer.println("---------------------------------");
            writer.printf("Total Symmetric Encryption Time (ns): %.2f\n", avgSymmetricTimeNs);
            writer.printf("Average Symmetric Encryption Time (s): %.12f\n", avgSymmetricTimeSec);
            writer.printf("Symmetric Encryption Operations per Second: %.2f\n", symmetricOpsPerSec);
            writer.println();

            writer.println("Asymmetric Encryption Calculations:");
            writer.println("-----------------------------------");
            writer.printf("Total Asymmetric Encryption Time (ns): %.2f\n", avgAsymmetricTimeNs);
            writer.printf("Average Asymmetric Encryption Time (s): %.12f\n", avgAsymmetricTimeSec);
            writer.printf("Asymmetric Encryption Operations per Second: %.2f\n", asymmetricOpsPerSec);
            writer.println();

            writer.println("Calculations Explained:");
            writer.println("------------------------");
            writer.println("1. Calculamos el tiempo promedio en nanosegundos sumando todos los tiempos");
            writer.println("   individuales de las operaciones y dividiéndolo entre la cantidad de operaciones.");
            writer.println("2. Convertimos el tiempo promedio de nanosegundos a segundos dividiendo por");
            writer.println("   1,000,000,000 para obtener el tiempo en segundos.");
            writer.println("3. Estimamos las operaciones por segundo tomando el inverso del tiempo promedio");
            writer.println("   en segundos (1 / tiempo_promedio_segundos).");
            writer.println();
            writer.println("Nota: Estos cálculos se basan en los datos proporcionados en el archivo 'test_results.csv'.");
            
            writer.close();

            System.out.println("Processor performance estimation saved to processor_performance.txt");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static double calculateAverage(List<Long> times) {
        if (times == null || times.isEmpty()) {
            return 0;
        }
        long sum = 0;
        for (Long time : times) {
            sum += time;
        }
        return (double) sum / times.size();
    }

    private static String getProcessorSpeed() {
        // Pedir al usuario la velocidad del procesador en GHz
        Scanner scanner = new Scanner(System.in);
        System.out.print("Please enter your processor speed in GHz (e.g., 2.5): ");
        String speed = scanner.nextLine();
        scanner.close();
        return speed + " GHz";
    }
}
