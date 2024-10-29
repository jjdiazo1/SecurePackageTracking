package caso3_jj.diazo1_p.paffen;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import caso3_jj.diazo1_p.paffen.PackageServer;

public class Test {
    private static final int[] THREAD_COUNTS = {4, 8, 32};
    private static final int ITERATIVE_REQUESTS = 32;
    private static final String CSV_FILE = "test_results.csv";

    public static void main(String[] args) {
        try {
            PrintWriter writer = new PrintWriter(new FileWriter(CSV_FILE));
            writer.println("Scenario,ChallengeResponseTime,DHGenerationTime,VerificationTime");

            // Run iterative scenario
            runIterativeScenario(writer);

            // Run concurrent scenarios
            for (int threadCount : THREAD_COUNTS) {
                runConcurrentScenario(writer, threadCount);
            }

            writer.close();
            System.out.println("Test results saved to " + CSV_FILE);

            // Generate graphs (optional)
            generateGraphs();

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
        for (int i = 0; i < ITERATIVE_REQUESTS; i++) {
            long[] times = client.sendRequest("user" + i, "pkg" + i);
            writer.println("Iterative," + times[0] + "," + times[1] + "," + times[2]);
        }

        serverExecutor.shutdownNow();
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

        PackageClient client = new PackageClient();
        ExecutorService clientExecutor = Executors.newFixedThreadPool(threadCount);
        List<Future<long[]>> futures = new ArrayList<>();
        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            futures.add(clientExecutor.submit(() -> client.sendRequest("user" + index, "pkg" + index)));
        }

        for (Future<long[]> future : futures) {
            long[] times = future.get();
            writer.println("Concurrent-" + threadCount + "," + times[0] + "," + times[1] + "," + times[2]);
        }

        clientExecutor.shutdown();
        serverExecutor.shutdownNow();
    }

    private static void generateGraphs() {
        // Implement graph generation using a library like JFreeChart or Apache POI for Excel
        // This is optional and can be done separately if needed
    }
}