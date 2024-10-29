<img width="499" alt="image" src="https://github.com/user-attachments/assets/5e942d22-e709-4489-8d92-32f6959cb161"># SecurePackageTracking

## UML

```mermaid
classDiagram
    direction LR
    class PackageClient {
        - String SERVER_ADDRESS
        - int SERVER_PORT
        - String SERVER_PUBLIC_KEY_FILE
        - PublicKey serverPublicKey
        + main(String[] args)
        + readServerPublicKey() : void
        - readKeyFromFile(String filename) : byte[]
        - run() : void
        - runIterative() : void
        - runConcurrent(int numDelegates) : void
        + sendRequest(String uid, String packageId) : long[]
    }

    class PackageServer {
        - int PORT
        - String PRIVATE_KEY_FILE
        - String PUBLIC_KEY_FILE
        - ServerSocket serverSocket
        - Map<String, Integer> packageStates
        - PrivateKey privateKey
        - PublicKey publicKey
        + PackageServer()
        + main(String[] args)
        - run() : void
        - initializePackageStates() : void
        - generateRSAKeys() : void
        - readRSAKeys() : void
        + startServerIterative() : void
        + startServerConcurrent(int numThreads) : void
        + stopServer() : void
        - handleClient(Socket clientSocket) : void
        - getStateString(int state) : String
        - saveKeyToFile(String filename, byte[] keyBytes) : void
        - readKeyFromFile(String filename) : byte[]
    }

    class DiffieHellman {
        + BigInteger getP() : BigInteger
        + BigInteger getG() : BigInteger
    }

    class ProcessorPerformanceEstimator {
        + estimateAndWriteToFile() : void
        - calculateAverage(List<Long> times) : double
        - getProcessorSpeed() : String
    }

    class Test {
        - int[] THREAD_COUNTS
        - int ITERATIVE_REQUESTS
        - String CSV_FILE
        + main(String[] args)
        - runIterativeScenario(PrintWriter writer) : void
        - runConcurrentScenario(PrintWriter writer, int threadCount) : void
        - collectTimingData(PrintWriter writer, String scenario) : void
        - estimateProcessorPerformance() : void
    }

    PackageClient --> PackageServer : interacts with
    PackageServer ..> DiffieHellman : uses
    PackageServer ..> ProcessorPerformanceEstimator : uses
    Test --> PackageClient : uses
    Test --> PackageServer : uses
    Test ..> ProcessorPerformanceEstimator : uses

    style PackageClient fill:#d3d3d3
    style PackageServer fill:#d3d3d3
    style DiffieHellman fill:#d3d3d3
    style ProcessorPerformanceEstimator fill:#d3d3d3
    style Test fill:#d3d3d3
```

## Protocol
Handling Client Connections

The handleClient method performs the protocol steps with the client.

### Key Steps:

1. Step 1: Receive "SECINIT" from the client.
2. Step 2b & 3: Receive encrypted challenge and decrypt it using the server's private key.
3. Step 4: Send the decrypted challenge back to the client.
4. Step 5: Receive "OK" or "ERROR" from the client.
5. Step 7: Generate Diffie-Hellman parameters G, P, G^x.
6. Step 8: Send parameters and signature to the client.
7. Step 10: Receive "OK" or "ERROR" from the client.
8. Step 11b: Compute shared secret and derive session keys.
9. Step 12: Receive IV from the client.
10. Step 13 & 14: Receive encrypted uid and package_id, verify HMACs, and decrypt them.
11. Step 15: Look up the package state.
12. Step 16: Encrypt the state and send it with HMAC.
13. Additional: Measure and print the timings for various operations.

### Key Generation and Encryption
1. Diffie-Hellman Parameters: Use p and g from OpenSSL.
2. Master Key: Compute shared secret using gy.modPow(x, p).
3. Session Keys: Derive from SHA-512 digest of the master key.
   
### Measuring Encryption Times
1. Symmetric Encryption: Measure time to encrypt the state using AES.
2. Asymmetric Encryption: Measure time to encrypt the state using RSA.

### Sending and Receiving Data
- IV: Receive 16-byte IV from the client.
- HMAC Verification: Verify HMACs for uid and package_id.
- Encryption and HMAC: Encrypt the state and compute its HMAC before sending.
