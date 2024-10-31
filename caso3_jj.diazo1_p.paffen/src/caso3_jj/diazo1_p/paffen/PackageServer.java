package caso3_jj.diazo1_p.paffen;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.*;
import javax.crypto.spec.*;

public class PackageServer {
    private static final int PORT = 12345;
    private static final String PRIVATE_KEY_FILE = "private.key";
    private static final String PUBLIC_KEY_FILE = "public.key";

    private ServerSocket serverSocket;

    // Shared queues for timing data
    public static ConcurrentLinkedQueue<Long> challengeResponseTimes = new ConcurrentLinkedQueue<>();
    public static ConcurrentLinkedQueue<Long> dhGenerationTimes = new ConcurrentLinkedQueue<>();
    public static ConcurrentLinkedQueue<Long> verificationTimes = new ConcurrentLinkedQueue<>();
    public static ConcurrentLinkedQueue<Long> symmetricEncryptionTimes = new ConcurrentLinkedQueue<>();
    public static ConcurrentLinkedQueue<Long> asymmetricEncryptionTimes = new ConcurrentLinkedQueue<>();

    // Package states as constants
    private static final int ENOFICINA = 0;
    private static final int RECOGIDO = 1;
    private static final int ENCLASIFICACION = 2;
    private static final int DESPACHADO = 3;
    private static final int ENENTREGA = 4;
    private static final int ENTREGADO = 5;
    private static final int DESCONOCIDO = 6;

    // Map to hold package states
    private Map<String, Integer> packageStates;

    // Server's RSA keys
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public PackageServer() {
        initializePackageStates();
        try {
            readRSAKeys();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    

    public static void main(String[] args) {
        PackageServer server = new PackageServer();
        server.run();
    }

    private void run() {
        try {
            System.out.println("Seleccione una opción:");
            System.out.println("1. Generar llaves RSA");
            System.out.println("2. Iniciar el servidor");

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String option = reader.readLine();

            if ("1".equals(option)) {
                generateRSAKeys();
            } else if ("2".equals(option)) {
                // Read RSA keys from files
                readRSAKeys();
                System.out.println("Seleccione el modo de operación: \n 1. Iterativo \n 2. Concurrente");
                String mode = reader.readLine();
                if ("1".equals(mode)) {
                    startServerIterative();
                } else if ("2".equals(mode)) {
                    System.out.println("Ingrese el número de hilos:");
                    int numThreads = Integer.parseInt(reader.readLine());
                    startServerConcurrent(numThreads);
                } else {
                    System.out.println("Modo no válido.");
                }
            } else {
                System.out.println("Opción no válida.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void initializePackageStates() {
        packageStates = new HashMap<>();
        Random rand = new Random();
        int[] possibleStates = {ENOFICINA, RECOGIDO, ENCLASIFICACION, DESPACHADO, ENENTREGA, ENTREGADO};
    
        for (int i = 0; i < 32; i++) {
            int randomState = possibleStates[rand.nextInt(possibleStates.length)];
            packageStates.put("user" + i + ":pkg" + i, randomState);
        }
    }
    

    private void generateRSAKeys() throws Exception {
        // Generate RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();

        // Save keys to files
        saveKeyToFile(PRIVATE_KEY_FILE, privateKey.getEncoded());
        saveKeyToFile(PUBLIC_KEY_FILE, publicKey.getEncoded());

        System.out.println("Llaves RSA generadas y guardadas.");
    }

    private void readRSAKeys() throws Exception {
        File privateKeyFile = new File(PRIVATE_KEY_FILE);
        File publicKeyFile = new File(PUBLIC_KEY_FILE);
        
        if (!privateKeyFile.exists() || !publicKeyFile.exists()) {
            System.out.println("Key files not found. Generating new RSA keys...");
            generateRSAKeys();
        } else {
            // Read private key
            byte[] privateKeyBytes = readKeyFromFile(PRIVATE_KEY_FILE);
            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(privateSpec);
        
            // Read public key
            byte[] publicKeyBytes = readKeyFromFile(PUBLIC_KEY_FILE);
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);
            publicKey = keyFactory.generatePublic(publicSpec);
        
            System.out.println("Llaves RSA leídas desde archivos.");
        }
    }
    

    public void startServerIterative() throws IOException {
        serverSocket = new ServerSocket(PORT);
        System.out.println("Servidor iterativo iniciado en el puerto " + PORT);

        try {
            while (!Thread.currentThread().isInterrupted()) {
                Socket clientSocket = serverSocket.accept();
                handleClient(clientSocket);
            }
        } catch (IOException e) {
            // Handle exception
        } finally {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        }
    }

    public void startServerConcurrent(int numThreads) throws IOException {
        serverSocket = new ServerSocket(PORT);
        System.out.println("Servidor concurrente iniciado en el puerto " + PORT);
    
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
    
        try {
            while (!Thread.currentThread().isInterrupted()) {
                Socket clientSocket = serverSocket.accept();
                executor.execute(() -> {
                    try {
                        BigInteger[] dhParams = generateDiffieHellmanParameters();
                        handleClient(clientSocket, dhParams[0], dhParams[1]);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            }
        } catch (IOException e) {
            // Handle exception
        } finally {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
            executor.shutdown();
        }
    }

    public void stopServer() {
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
                System.out.println("Server socket closed.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void handleClient(Socket clientSocket, BigInteger p, BigInteger g) {
        try (DataInputStream in = new DataInputStream(clientSocket.getInputStream());
             DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream())) {
    
            // Step 1: Receive "SECINIT" from client
            String secInit = in.readUTF();
            if (!"SECINIT".equals(secInit)) {
                System.out.println("SECINIT no recibido. Cerrando conexión.");
                clientSocket.close();
                return;
            }
    
            // Step 2b: Receive encrypted challenge R from client
            int encryptedChallengeLength = in.readInt();
            byte[] encryptedChallenge = new byte[encryptedChallengeLength];
            in.readFully(encryptedChallenge);
    
            // Step 3: Decrypt R to get Reto
            long startTimeChallenge = System.nanoTime();
    
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] retoBytes = rsaCipher.doFinal(encryptedChallenge);
            String reto = new String(retoBytes);
    
            long endTimeChallenge = System.nanoTime();
            long timeToDecryptChallenge = endTimeChallenge - startTimeChallenge;
    
            // Step 4: Send Rta (Reto) back to client
            out.writeInt(retoBytes.length);
            out.write(retoBytes);
            out.flush();
    
            // Step 5: Receive "OK" or "ERROR" from client
            String authStatus = in.readUTF();
            if (!"OK".equals(authStatus)) {
                System.out.println("Autenticación fallida. Cerrando conexión.");
                clientSocket.close();
                return;
            }
    
            // Step 7: Generate Diffie-Hellman parameters G, P, G^x
            long startTimeDH = System.nanoTime();
    
            // Generate private exponent x and compute G^x mod p
            SecureRandom random = new SecureRandom();
            BigInteger x = new BigInteger(1024, random);
            BigInteger gx = g.modPow(x, p);
    
            long endTimeDH = System.nanoTime();
            long timeToGenerateDH = endTimeDH - startTimeDH;
    
            // Step 8: Send G, P, G^x and signature to client
            // Serialize parameters
            byte[] gBytes = g.toByteArray();
            byte[] pBytes = p.toByteArray();
            byte[] gxBytes = gx.toByteArray();
    
            // Sign the parameters
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(privateKey);
            signature.update(gBytes);
            signature.update(pBytes);
            signature.update(gxBytes);
            byte[] sigBytes = signature.sign();
    
            // Send lengths and data
            out.writeInt(gBytes.length);
            out.write(gBytes);
    
            out.writeInt(pBytes.length);
            out.write(pBytes);
    
            out.writeInt(gxBytes.length);
            out.write(gxBytes);
    
            out.writeInt(sigBytes.length);
            out.write(sigBytes);
            out.flush();
    
            // Step 10: Receive "OK" or "ERROR" from client
            String dhStatus = in.readUTF();
            if (!"OK".equals(dhStatus)) {
                System.out.println("Error en Diffie-Hellman. Cerrando conexión.");
                clientSocket.close();
                return;
            }
    
            // Step 11b: Compute shared secret and derive keys
            // Receive G^y from client
            int gyLength = in.readInt();
            byte[] gyBytes = new byte[gyLength];
            in.readFully(gyBytes);
            BigInteger gy = new BigInteger(gyBytes);
    
            // Compute shared secret K = (G^y)^x mod p
            BigInteger sharedSecret = gy.modPow(x, p);
            byte[] sharedSecretBytes = sharedSecret.toByteArray();
    
            // Compute digest SHA-512 of the master key
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(sharedSecretBytes);
    
            // Split digest into two 32-byte keys
            byte[] keyEncryption = Arrays.copyOfRange(digest, 0, 32); // First 256 bits
            byte[] keyHMAC = Arrays.copyOfRange(digest, 32, 64); // Last 256 bits
    
            SecretKeySpec aesKey = new SecretKeySpec(keyEncryption, "AES");
            SecretKeySpec hmacKey = new SecretKeySpec(keyHMAC, "HmacSHA384");
    
            // Step 12: Receive IV from client
            int ivLength = in.readInt();
            byte[] ivBytes = new byte[ivLength];
            in.readFully(ivBytes);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
    
            // Prepare AES cipher
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            Mac hmac = Mac.getInstance("HmacSHA384");
            hmac.init(hmacKey);
    
            // Step 13: Receive encrypted uid and HMAC
            int encUidLength = in.readInt();
            byte[] encUid = new byte[encUidLength];
            in.readFully(encUid);
    
            int hmacUidLength = in.readInt();
            byte[] hmacUid = new byte[hmacUidLength];
            in.readFully(hmacUid);
    
            // Verify HMAC
            byte[] computedHmacUid = hmac.doFinal(encUid);
            if (!Arrays.equals(hmacUid, computedHmacUid)) {
                System.out.println("HMAC de uid no válido. Cerrando conexión.");
                clientSocket.close();
                return;
            }
    
            // Decrypt uid
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
            byte[] uidBytes = aesCipher.doFinal(encUid);
            String uid = new String(uidBytes);
    
            // Step 14: Receive encrypted package_id and HMAC
            int encPkgIdLength = in.readInt();
            byte[] encPkgId = new byte[encPkgIdLength];
            in.readFully(encPkgId);
    
            int hmacPkgIdLength = in.readInt();
            byte[] hmacPkgId = new byte[hmacPkgIdLength];
            in.readFully(hmacPkgId);
    
            // Verify HMAC
            byte[] computedHmacPkgId = hmac.doFinal(encPkgId);
            if (!Arrays.equals(hmacPkgId, computedHmacPkgId)) {
                System.out.println("HMAC de package_id no válido. Cerrando conexión.");
                clientSocket.close();
                return;
            }
    
            // Decrypt package_id
            byte[] pkgIdBytes = aesCipher.doFinal(encPkgId);
            String packageId = new String(pkgIdBytes);
    
            // Step 15: Verify and respond
            long startTimeVerify = System.nanoTime();
    
            String key = uid + ":" + packageId;
            int state = packageStates.getOrDefault(key, DESCONOCIDO);
    
            long endTimeVerify = System.nanoTime();
            long timeToVerify = endTimeVerify - startTimeVerify;
    
            // Convert state to string
            String stateString = getStateString(state);
            byte[] stateBytes = stateString.getBytes();
    
            // Step 16: Send encrypted state and HMAC
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
            byte[] encState = aesCipher.doFinal(stateBytes);
            byte[] hmacState = hmac.doFinal(encState);
    
            out.writeInt(encState.length);
            out.write(encState);
    
            out.writeInt(hmacState.length);
            out.write(hmacState);
            out.flush();
    
            // Step 18: Terminate
            clientSocket.close();
    
            // Record timings
            // You can save the timings to a file or a data structure for later analysis
            System.out.println("Tiempo para descifrar el reto: " + timeToDecryptChallenge + " ns");
            System.out.println("Tiempo para generar G, P, G^x: " + timeToGenerateDH + " ns");
            System.out.println("Tiempo para verificar la consulta: " + timeToVerify + " ns");
    
            // Additional: Measure time to encrypt state with RSA (for comparison)
            long startTimeAsymmetricEncryption = System.nanoTime();
    
            Cipher rsaCipherEncrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipherEncrypt.init(Cipher.ENCRYPT_MODE, publicKey); // Use server's public key
            byte[] encryptedStateAsymmetric = rsaCipherEncrypt.doFinal(stateBytes);
    
            long endTimeAsymmetricEncryption = System.nanoTime();
            long timeToEncryptStateAsymmetric = endTimeAsymmetricEncryption - startTimeAsymmetricEncryption;
    
            System.out.println("Tiempo para cifrar el estado con cifrado asimétrico: " + timeToEncryptStateAsymmetric + " ns");
    
            // Similarly, measure time to encrypt with symmetric cipher
            long startTimeSymmetricEncryption = System.nanoTime();
    
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
            aesCipher.doFinal(stateBytes);
    
            long endTimeSymmetricEncryption = System.nanoTime();
            long timeToEncryptStateSymmetric = endTimeSymmetricEncryption - startTimeSymmetricEncryption;
    
            System.out.println("Tiempo para cifrar el estado con cifrado simétrico: " + timeToEncryptStateSymmetric + " ns");
    
            // After measuring timeToDecryptChallenge
            challengeResponseTimes.add(timeToDecryptChallenge);
    
            // After measuring timeToGenerateDH
            dhGenerationTimes.add(timeToGenerateDH);
    
            // After measuring timeToVerify
            verificationTimes.add(timeToVerify);
    
            // After measuring timeToEncryptStateSymmetric
            symmetricEncryptionTimes.add(timeToEncryptStateSymmetric);
    
            // After measuring timeToEncryptStateAsymmetric
            asymmetricEncryptionTimes.add(timeToEncryptStateAsymmetric);
    
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void handleClient(Socket clientSocket) {
        handleClient(clientSocket, DiffieHellman.getP(), DiffieHellman.getG());
    }

    private String getStateString(int state) {
        switch (state) {
            case ENOFICINA:
                return "ENOFICINA";
            case RECOGIDO:
                return "RECOGIDO";
            case ENCLASIFICACION:
                return "ENCLASIFICACION";
            case DESPACHADO:
                return "DESPACHADO";
            case ENENTREGA:
                return "ENENTREGA";
            case ENTREGADO:
                return "ENTREGADO";
            default:
                return "DESCONOCIDO";
        }
    }

    private void saveKeyToFile(String filename, byte[] keyBytes) throws IOException {
        FileOutputStream fos = new FileOutputStream(filename);
        fos.write(keyBytes);
        fos.close();
    }

    private byte[] readKeyFromFile(String filename) throws IOException {
        File file = new File(filename);
        FileInputStream fis = new FileInputStream(file);
        byte[] keyBytes = new byte[(int) file.length()];
        fis.read(keyBytes);
        fis.close();
        return keyBytes;
    }

    // Diffie-Hellman parameters generation
    // Diffie-Hellman parameters generation for iterative mode
    private static class DiffieHellman {
        private static BigInteger p;
        private static BigInteger g;

        static {
            // Use p and g generated via OpenSSL
            String pHex = "0098e60e1f707fc8f7b37f8ea5cee0b37d5b93664d19e31b7165ef3c8a8cef45acdecba4016aa0f960ffa2eb0f6a93def57aaacd9a2362bb37d075ad852018d371efa2600605fe465961c7d790f11985ec9f572cf08be42be7603ff5070d2612b4d56820b1c7a022ab96a9ee9aa57061725c02f610dafe9545bab3ec924b72d1bca7";
            p = new BigInteger(pHex, 16);
            g = BigInteger.valueOf(2);
        }

        public static BigInteger getP() {
            return p;
        }

        public static BigInteger getG() {
            return g;
        }
    }

    private BigInteger[] generateDiffieHellmanParameters() throws Exception {
        String opensslPath = Paths.get("OpenSSL-1.1.1h_win32", "OpenSSL-1.1.1h_win32", "openssl.exe").toString();
        ProcessBuilder processBuilder = new ProcessBuilder(opensslPath, "dhparam", "-text", "1024");
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();
    
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        reader.close();
        process.waitFor();
    
        // Parse the output to extract p
        Pattern pPattern = Pattern.compile("prime\\s*:\\s*([0-9A-Fa-f:\\s]+)");
        Matcher pMatcher = pPattern.matcher(output);
    
        BigInteger p = null;
        BigInteger g = null;
    
        if (pMatcher.find()) {
            String pHex = pMatcher.group(1).replaceAll("[^0-9A-Fa-f]", ""); // Remove non-hex characters
            p = new BigInteger(pHex, 16);
        }
    
        // Generate a random value for g
        SecureRandom random = new SecureRandom();
        g = BigInteger.valueOf(random.nextInt(100) + 2); // Random value between 2 and 101
    
        // Verify that p and g are valid
        if (p == null || g == null || p.signum() <= 0 || g.signum() <= 0) {
            System.out.println("Output from OpenSSL: " + output.toString());
            throw new IllegalArgumentException("Invalid Diffie-Hellman parameters generated");
        }
    
        // Print p and g to verify they are changing
        System.out.println("Generated Diffie-Hellman parameters:");
        System.out.println("p: " + p.toString(16));
        System.out.println("g: " + g.toString(16));
    
        return new BigInteger[]{p, g};
    }  
}