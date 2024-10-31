package caso3_jj.diazo1_p.paffen;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;

public class Test {
    private static final int[] THREAD_COUNTS = {4, 8, 32};
    private static final int ITERATIVE_REQUESTS = 32;
    private static final String CSV_FILE = "test_results.csv";

    public static void main(String[] args) {
        try {
            PrintWriter writer = new PrintWriter(new FileWriter(CSV_FILE));
            writer.println("Escenario,Operación,Tiempo(ns)");

            // Ejecutar escenario iterativo
            runIterativeScenario(writer);

            // Ejecutar escenarios concurrentes
            for (int threadCount : THREAD_COUNTS) {
                runConcurrentScenario(writer, threadCount);
            }

            writer.close();
            System.out.println("Resultados de la prueba guardados en " + CSV_FILE);

            // Estimar la velocidad del procesador y las operaciones de cifrado por segundo
            estimateProcessorPerformance();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void runIterativeScenario(PrintWriter writer) throws Exception {
        System.out.println("Ejecutando escenario iterativo...");
        PackageServer server = new PackageServer();
        ExecutorService serverExecutor = Executors.newSingleThreadExecutor();
        serverExecutor.submit(() -> {
            try {
                server.startServerIterative();
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    
        Thread.sleep(1000); // Esperar a que el servidor inicie
    
        PackageClient client = new PackageClient();
        client.readServerPublicKey(); // Agregar esta línea
        for (int i = 0; i < ITERATIVE_REQUESTS; i++) {
            client.sendRequest("user" + i, "pkg" + i);
        }
    
        serverExecutor.shutdownNow();
        server.stopServer(); // Agregar esta línea
    
        // Recopilar datos de tiempo
        collectTimingData(writer, "Iterative");
    }

    private static void runConcurrentScenario(PrintWriter writer, int threadCount) throws Exception {
        System.out.println("Ejecutando escenario concurrente con " + threadCount + " hilos...");
        PackageServer server = new PackageServer();
        ExecutorService serverExecutor = Executors.newSingleThreadExecutor();
        serverExecutor.submit(() -> {
            try {
                server.startServerConcurrent(threadCount);
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    
        Thread.sleep(1000); // Esperar a que el servidor inicie
    
        ExecutorService clientExecutor = Executors.newFixedThreadPool(threadCount);
        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            clientExecutor.submit(() -> {
                PackageClient client = new PackageClient();
                try {
                    client.readServerPublicKey(); // Agregar esta línea
                    client.sendRequest("user" + index, "pkg" + index);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
    
        clientExecutor.shutdown();
        clientExecutor.awaitTermination(5, TimeUnit.MINUTES);
    
        serverExecutor.shutdownNow();
        server.stopServer(); // Agregar esta línea
    
        // Esperar a que todas las solicitudes se completen
        Thread.sleep(5000);
    
        // Recopilar datos de tiempo
        collectTimingData(writer, "Concurrent-" + threadCount);
    }
    

    private static void collectTimingData(PrintWriter writer, String scenario) {
        // Dado que los datos están en las colas estáticas del servidor, podemos acceder a ellos directamente

        Iterator<Long> challengeIter = PackageServer.challengeResponseTimes.iterator();
        while (challengeIter.hasNext()) {
            writer.println(scenario + ",TiempoDeRespuestaDesafío," + challengeIter.next());
        }

        Iterator<Long> dhIter = PackageServer.dhGenerationTimes.iterator();
        while (dhIter.hasNext()) {
            writer.println(scenario + ",TiempoDeGeneraciónDH," + dhIter.next());
        }

        Iterator<Long> verificationIter = PackageServer.verificationTimes.iterator();
        while (verificationIter.hasNext()) {
            writer.println(scenario + ",TiempoDeVerificación," + verificationIter.next());
        }

        Iterator<Long> symmetricIter = PackageServer.symmetricEncryptionTimes.iterator();
        while (symmetricIter.hasNext()) {
            writer.println(scenario + ",TiempoDeCifradoSimétrico," + symmetricIter.next());
        }

        Iterator<Long> asymmetricIter = PackageServer.asymmetricEncryptionTimes.iterator();
        while (asymmetricIter.hasNext()) {
            writer.println(scenario + ",TiempoDeCifradoAsimétrico," + asymmetricIter.next());
        }

        // Limpiar las colas para el siguiente escenario
        PackageServer.challengeResponseTimes.clear();
        PackageServer.dhGenerationTimes.clear();
        PackageServer.verificationTimes.clear();
        PackageServer.symmetricEncryptionTimes.clear();
        PackageServer.asymmetricEncryptionTimes.clear();
    }

    private static void estimateProcessorPerformance() {
        // Implementar el cálculo de la velocidad del procesador y las operaciones de cifrado por segundo
        // Escribir los resultados en un archivo de texto
        RendimientoProcesador.estimarYEscribirEnArchivo();
    }
}