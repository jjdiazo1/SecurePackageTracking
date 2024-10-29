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
            writer.println("Scenario,Operation,Time(ns)");

            // Run iterative scenario
            runIterativeScenario(writer);

            // Run concurrent scenarios
            for (int threadCount : THREAD_COUNTS) {
                runConcurrentScenario(writer, threadCount);
            }

            writer.close();
            System.out.println("Test results saved to " + CSV_FILE);

            // Estimate processor speed and encryption operations per second
            estimateProcessorPerformance();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void runIterativeScenario(PrintWriter writer) throws Exception {
        System.out.println("Running iterative scenario...");
        PackageServer server = new PackageServer();
        ExecutorService serverExecutor = Executors.newSingleThreadExecutor();
        serverExecutor.submit(() -> {
            try {
                server.startServerIterative();
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    
        Thread.sleep(1000); // Wait for server to start
    
        PackageClient client = new PackageClient();
        client.readServerPublicKey(); // Add this line
        for (int i = 0; i < ITERATIVE_REQUESTS; i++) {
            client.sendRequest("user" + i, "pkg" + i);
        }
    
        serverExecutor.shutdownNow();
        server.stopServer(); // Add this line
    
        // Collect timing data
        collectTimingData(writer, "Iterative");
    }

    private static void runConcurrentScenario(PrintWriter writer, int threadCount) throws Exception {
        System.out.println("Running concurrent scenario with " + threadCount + " threads...");
        PackageServer server = new PackageServer();
        ExecutorService serverExecutor = Executors.newSingleThreadExecutor();
        serverExecutor.submit(() -> {
            try {
                server.startServerConcurrent(threadCount);
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    
        Thread.sleep(1000); // Wait for server to start
    
        ExecutorService clientExecutor = Executors.newFixedThreadPool(threadCount);
        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            clientExecutor.submit(() -> {
                PackageClient client = new PackageClient();
                try {
                    client.readServerPublicKey(); // Add this line
                    client.sendRequest("user" + index, "pkg" + index);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
    
        clientExecutor.shutdown();
        clientExecutor.awaitTermination(5, TimeUnit.MINUTES);
    
        serverExecutor.shutdownNow();
        server.stopServer(); // Add this line
    
        // Wait for all requests to complete
        Thread.sleep(5000);
    
        // Collect timing data
        collectTimingData(writer, "Concurrent-" + threadCount);
    }
    

    private static void collectTimingData(PrintWriter writer, String scenario) {
        // Since the data is in the server's static queues, we can access them directly

        Iterator<Long> challengeIter = PackageServer.challengeResponseTimes.iterator();
        while (challengeIter.hasNext()) {
            writer.println(scenario + ",ChallengeResponseTime," + challengeIter.next());
        }

        Iterator<Long> dhIter = PackageServer.dhGenerationTimes.iterator();
        while (dhIter.hasNext()) {
            writer.println(scenario + ",DHGenerationTime," + dhIter.next());
        }

        Iterator<Long> verificationIter = PackageServer.verificationTimes.iterator();
        while (verificationIter.hasNext()) {
            writer.println(scenario + ",VerificationTime," + verificationIter.next());
        }

        Iterator<Long> symmetricIter = PackageServer.symmetricEncryptionTimes.iterator();
        while (symmetricIter.hasNext()) {
            writer.println(scenario + ",SymmetricEncryptionTime," + symmetricIter.next());
        }

        Iterator<Long> asymmetricIter = PackageServer.asymmetricEncryptionTimes.iterator();
        while (asymmetricIter.hasNext()) {
            writer.println(scenario + ",AsymmetricEncryptionTime," + asymmetricIter.next());
        }

        // Clear the queues for the next scenario
        PackageServer.challengeResponseTimes.clear();
        PackageServer.dhGenerationTimes.clear();
        PackageServer.verificationTimes.clear();
        PackageServer.symmetricEncryptionTimes.clear();
        PackageServer.asymmetricEncryptionTimes.clear();
    }

    private static void estimateProcessorPerformance() {
        // Implement the calculation of processor speed and encryption operations per second
        // Write the results to a text file
        ProcessorPerformanceEstimator.estimateAndWriteToFile();
    }
}
