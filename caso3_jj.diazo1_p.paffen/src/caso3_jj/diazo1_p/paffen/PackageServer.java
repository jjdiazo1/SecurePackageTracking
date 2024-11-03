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

    // Colas compartidas para datos de tiempo
    public static ConcurrentLinkedQueue<Long> challengeResponseTimes = new ConcurrentLinkedQueue<>();
    public static ConcurrentLinkedQueue<Long> dhGenerationTimes = new ConcurrentLinkedQueue<>();
    public static ConcurrentLinkedQueue<Long> verificationTimes = new ConcurrentLinkedQueue<>();
    public static ConcurrentLinkedQueue<Long> symmetricEncryptionTimes = new ConcurrentLinkedQueue<>();
    public static ConcurrentLinkedQueue<Long> asymmetricEncryptionTimes = new ConcurrentLinkedQueue<>();

    // Estados del paquete como constantes
    private static final int ENOFICINA = 0;
    private static final int RECOGIDO = 1;
    private static final int ENCLASIFICACION = 2;
    private static final int DESPACHADO = 3;
    private static final int ENENTREGA = 4;
    private static final int ENTREGADO = 5;
    private static final int DESCONOCIDO = 6;

    // Mapa para mantener los estados del paquete
    private Map<String, Integer> packageStates;

    // Llaves RSA del servidor
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

    /**
     * Ejecuta el servidor, permitiendo al usuario seleccionar el modo de operación.
     */
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
                // Leer las llaves RSA
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

    /**
     * Inicializa los estados de los paquetes con valores aleatorios.
     */
    private void initializePackageStates() {
        packageStates = new HashMap<>();
        Random rand = new Random();
        int[] possibleStates = {ENOFICINA, RECOGIDO, ENCLASIFICACION, DESPACHADO, ENENTREGA, ENTREGADO};
    
        for (int i = 0; i < 1000; i++) {
            int randomState = possibleStates[rand.nextInt(possibleStates.length)];
            packageStates.put("user" + i + ":pkg" + i, randomState);
        }
    }
    

    /**
     * Genera llaves RSA y las guarda en archivos.
     * 
     * @throws Exception si ocurre un error al generar las llaves.
     */
    private void generateRSAKeys() throws Exception {
        // Generar llaves RSA
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();

        // Leer llaves RSA desde archivos
        saveKeyToFile(PRIVATE_KEY_FILE, privateKey.getEncoded());
        saveKeyToFile(PUBLIC_KEY_FILE, publicKey.getEncoded());

        System.out.println("Llaves RSA generadas y guardadas.");
    }


    /**
     * Lee las llaves RSA desde archivos.
     * 
     * @throws Exception si ocurre un error al leer las llaves.
     */
    private void readRSAKeys() throws Exception {
        File privateKeyFile = new File(PRIVATE_KEY_FILE);
        File publicKeyFile = new File(PUBLIC_KEY_FILE);
        
        if (!privateKeyFile.exists() || !publicKeyFile.exists()) {
            System.out.println("Archivos de llaves no encontrados. Generando nuevas llaves RSA...");
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
    

    /**
     * Inicia el servidor en modo iterativo.
     * 
     * @throws IOException si ocurre un error al iniciar el servidor.
     */
    public void startServerIterative() throws IOException {
        serverSocket = new ServerSocket(PORT);
        System.out.println("Servidor iterativo iniciado en el puerto " + PORT);
    
        try {
            while (!Thread.currentThread().isInterrupted()) {
                Socket clientSocket = serverSocket.accept();
                handleClient(clientSocket, false); // Indicar que no es concurrente
            }
        } catch (IOException e) {
            // Manejar excepción
        } finally {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        }
    }


    /**
     * Inicia el servidor en modo concurrente.
     * 
     * @param numThreads número de hilos a utilizar.
     * @throws IOException si ocurre un error al iniciar el servidor.
     */
    public void startServerConcurrent(int numThreads) throws IOException {
        serverSocket = new ServerSocket(PORT);
        System.out.println("Servidor concurrente iniciado en el puerto " + PORT);
    
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
    
        try {
            while (!Thread.currentThread().isInterrupted()) {
                Socket clientSocket = serverSocket.accept();
                executor.execute(() -> {
                    try {
                        handleClient(clientSocket, true); // Indicar que es concurrente
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            }
        } catch (IOException e) {
            // Manejar excepción
        } finally {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
            executor.shutdown();
        }
    }

    /**
     * Detiene el servidor cerrando el socket del servidor.
     */
    public void stopServer() {
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
                System.out.println("Socket del servidor cerrado.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Maneja la conexión con un cliente.
     * 
     * @param clientSocket socket del cliente.
     * @param isConcurrent indica si el servidor es concurrente.
     */
    private void handleClient(Socket clientSocket, boolean isConcurrent) {
        try (DataInputStream in = new DataInputStream(clientSocket.getInputStream());
             DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream())) {
    
            // Paso 1: Recibir "SECINIT" del cliente
            String secInit = in.readUTF();
            if (!"SECINIT".equals(secInit)) {
                System.out.println("SECINIT no recibido. Cerrando conexión.");
                clientSocket.close();
                return;
            }
    
            // Paso 2b: Recibir desafío cifrado R del cliente
            int encryptedChallengeLength = in.readInt();
            byte[] encryptedChallenge = new byte[encryptedChallengeLength];
            in.readFully(encryptedChallenge);
    
            // Paso 3: Descifrar R para obtener el Reto
            long startTimeChallenge = System.nanoTime();
    
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] retoBytes = rsaCipher.doFinal(encryptedChallenge);
            String reto = new String(retoBytes);
    
            long endTimeChallenge = System.nanoTime();
            long timeToDecryptChallenge = endTimeChallenge - startTimeChallenge;
    
            // Paso 4: Enviar Rta (Reto) de vuelta al cliente
            out.writeInt(retoBytes.length);
            out.write(retoBytes);
            out.flush();
    
            // Paso 5: Recibir "OK" o "ERROR" del cliente
            String authStatus = in.readUTF();
            if (!"OK".equals(authStatus)) {
                System.out.println("Autenticación fallida. Cerrando conexión.");
                clientSocket.close();
                return;
            }
    
            // Paso 7: Generar parámetros Diffie-Hellman G, P, G^x
            long startTimeDH = System.nanoTime();
    
            BigInteger p, g;
            if (isConcurrent) {
                // Generar parámetros Diffie-Hellman para el servidor concurrente
                BigInteger[] dhParams = generateDiffieHellmanParameters();
                p = dhParams[0];
                g = dhParams[1];
            } else {
                // Usar parámetros constantes para el servidor iterativo
                p = DiffieHellman.getP();
                g = DiffieHellman.getG();
            }
    
            // Generar exponente privado x y calcular G^x mod p
            SecureRandom random = new SecureRandom();
            BigInteger x = new BigInteger(1024, random);
            BigInteger gx = g.modPow(x, p);
    
            long endTimeDH = System.nanoTime();
            long timeToGenerateDH = endTimeDH - startTimeDH;
    
            // Paso 8: Enviar G, P, G^x y firma al cliente
            // Serializar parámetros
            byte[] gBytes = g.toByteArray();
            byte[] pBytes = p.toByteArray();
            byte[] gxBytes = gx.toByteArray();
    
            // Firmar los parámetros
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(privateKey);
            signature.update(gBytes);
            signature.update(pBytes);
            signature.update(gxBytes);
            byte[] sigBytes = signature.sign();
    
            // Enviar longitudes y datos
            out.writeInt(gBytes.length);
            out.write(gBytes);
    
            out.writeInt(pBytes.length);
            out.write(pBytes);
    
            out.writeInt(gxBytes.length);
            out.write(gxBytes);
    
            out.writeInt(sigBytes.length);
            out.write(sigBytes);
            out.flush();
    
            // Paso 10: Recibir "OK" o "ERROR" del cliente
            String dhStatus = in.readUTF();
            if (!"OK".equals(dhStatus)) {
                System.out.println("Error en Diffie-Hellman. Cerrando conexión.");
                clientSocket.close();
                return;
            }
    
            // Paso 11b: Calcular secreto compartido y derivar llaves
            // Recibir G^y del cliente
            int gyLength = in.readInt();
            byte[] gyBytes = new byte[gyLength];
            in.readFully(gyBytes);
            BigInteger gy = new BigInteger(gyBytes);
    
            // Calcular secreto compartido K = (G^y)^x mod p
            BigInteger sharedSecret = gy.modPow(x, p);
            byte[] sharedSecretBytes = sharedSecret.toByteArray();
    
            // Calcular digest SHA-512 de la llave maestra
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(sharedSecretBytes);
    
            // Dividir digest en dos llaves de 32 bytes
            byte[] keyEncryption = Arrays.copyOfRange(digest, 0, 32); // Primeros 256 bits
            byte[] keyHMAC = Arrays.copyOfRange(digest, 32, 64); // Últimos 256 bits
    
            SecretKeySpec aesKey = new SecretKeySpec(keyEncryption, "AES");
            SecretKeySpec hmacKey = new SecretKeySpec(keyHMAC, "HmacSHA384");
    
            // Paso 12: Recibir IV del cliente
            int ivLength = in.readInt();
            byte[] ivBytes = new byte[ivLength];
            in.readFully(ivBytes);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
    
            // Preparar cifrador AES
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            Mac hmac = Mac.getInstance("HmacSHA384");
            hmac.init(hmacKey);
    
            // Paso 13: Recibir uid cifrado y HMAC
            int encUidLength = in.readInt();
            byte[] encUid = new byte[encUidLength];
            in.readFully(encUid);
    
            int hmacUidLength = in.readInt();
            byte[] hmacUid = new byte[hmacUidLength];
            in.readFully(hmacUid);
    
            // Verificar HMAC
            byte[] computedHmacUid = hmac.doFinal(encUid);
            if (!Arrays.equals(hmacUid, computedHmacUid)) {
                System.out.println("HMAC de uid no válido. Cerrando conexión.");
                clientSocket.close();
                return;
            }
    
            // Descifrar uid
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
            byte[] uidBytes = aesCipher.doFinal(encUid);
            String uid = new String(uidBytes);
    
            // Paso 14: Recibir package_id cifrado y HMAC
            int encPkgIdLength = in.readInt();
            byte[] encPkgId = new byte[encPkgIdLength];
            in.readFully(encPkgId);
    
            int hmacPkgIdLength = in.readInt();
            byte[] hmacPkgId = new byte[hmacPkgIdLength];
            in.readFully(hmacPkgId);
    
            // Verificar HMAC
            byte[] computedHmacPkgId = hmac.doFinal(encPkgId);
            if (!Arrays.equals(hmacPkgId, computedHmacPkgId)) {
                System.out.println("HMAC de package_id no válido. Cerrando conexión.");
                clientSocket.close();
                return;
            }
    
            // Descifrar package_id
            byte[] pkgIdBytes = aesCipher.doFinal(encPkgId);
            String packageId = new String(pkgIdBytes);
    
            // Paso 15: Verificar y responder
            long startTimeVerify = System.nanoTime();
    
            String key = uid + ":" + packageId;
            int state = packageStates.getOrDefault(key, DESCONOCIDO);
    
            long endTimeVerify = System.nanoTime();
            long timeToVerify = endTimeVerify - startTimeVerify;
    
            // Convertir estado a cadena
            String stateString = getStateString(state);
            byte[] stateBytes = stateString.getBytes();
    
            // Paso 16: Enviar estado cifrado y HMAC
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
            byte[] encState = aesCipher.doFinal(stateBytes);
            byte[] hmacState = hmac.doFinal(encState);
    
            out.writeInt(encState.length);
            out.write(encState);
    
            out.writeInt(hmacState.length);
            out.write(hmacState);
            out.flush();
    
            // Paso 18: Terminar
            clientSocket.close();
    
            // Registrar tiempos
            System.out.println("Tiempo para descifrar el reto: " + timeToDecryptChallenge + " ns");
            System.out.println("Tiempo para generar G, P, G^x: " + timeToGenerateDH + " ns");
            System.out.println("Tiempo para verificar la consulta: " + timeToVerify + " ns");
    
            // Adicional: Medir tiempo para cifrar estado con RSA (para comparación)
            long startTimeAsymmetricEncryption = System.nanoTime();
    
            Cipher rsaCipherEncrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipherEncrypt.init(Cipher.ENCRYPT_MODE, publicKey); // Usar llave pública del servidor
            byte[] encryptedStateAsymmetric = rsaCipherEncrypt.doFinal(stateBytes);
    
            long endTimeAsymmetricEncryption = System.nanoTime();
            long timeToEncryptStateAsymmetric = endTimeAsymmetricEncryption - startTimeAsymmetricEncryption;
    
            System.out.println("Tiempo para cifrar el estado con cifrado asimétrico: " + timeToEncryptStateAsymmetric + " ns");
    
            // De manera similar, medir tiempo para cifrar con cifrado simétrico
            long startTimeSymmetricEncryption = System.nanoTime();
    
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
            aesCipher.doFinal(stateBytes);
    
            long endTimeSymmetricEncryption = System.nanoTime();
            long timeToEncryptStateSymmetric = endTimeSymmetricEncryption - startTimeSymmetricEncryption;
    
            System.out.println("Tiempo para cifrar el estado con cifrado simétrico: " + timeToEncryptStateSymmetric + " ns");
    
            // Después de medir timeToDecryptChallenge
            challengeResponseTimes.add(timeToDecryptChallenge);
    
            // Después de medir timeToGenerateDH
            dhGenerationTimes.add(timeToGenerateDH);
    
            // Después de medir timeToVerify
            verificationTimes.add(timeToVerify);
    
            // Después de medir timeToEncryptStateSymmetric
            symmetricEncryptionTimes.add(timeToEncryptStateSymmetric);
    
            // Después de medir timeToEncryptStateAsymmetric
            asymmetricEncryptionTimes.add(timeToEncryptStateAsymmetric);
    
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Obtiene la cadena correspondiente a un estado.
     * 
     * @param state estado del paquete.
     * @return cadena correspondiente al estado.
     */
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


    /**
 * Guarda una llave en un archivo.
 * 
 * @param filename el nombre del archivo donde se guardará la llave.
 * @param keyBytes un arreglo de bytes que representa la llave.
 * @throws IOException si ocurre un error al escribir en el archivo.
 */
private void saveKeyToFile(String filename, byte[] keyBytes) throws IOException {
    FileOutputStream fos = new FileOutputStream(filename);
    fos.write(keyBytes);
    fos.close();
}

/**
 * Lee una llave desde un archivo.
 * 
 * @param filename el nombre del archivo que contiene la llave.
 * @return un arreglo de bytes que representa la llave.
 * @throws IOException si ocurre un error al leer el archivo.
 */
private byte[] readKeyFromFile(String filename) throws IOException {
    File file = new File(filename);
    FileInputStream fis = new FileInputStream(file);
    byte[] keyBytes = new byte[(int) file.length()];
    fis.read(keyBytes);
    fis.close();
    return keyBytes;
}

/**
 * Clase estática para la generación de parámetros Diffie-Hellman.
 */
private static class DiffieHellman {
    private static BigInteger p;
    private static BigInteger g;

    static {
        // p y g generados por OpenSSL
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

/**
 * Genera parámetros Diffie-Hellman utilizando OpenSSL.
 * 
 * @return un arreglo de BigInteger que contiene p y g.
 * @throws Exception si ocurre un error al generar los parámetros.
 */
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

    Pattern pPattern = Pattern.compile("prime\\s*:\\s*([0-9A-Fa-f:\\s]+)");
    Matcher pMatcher = pPattern.matcher(output);

    BigInteger p = null;
    BigInteger g = null;

    if (pMatcher.find()) {
        String pHex = pMatcher.group(1).replaceAll("[^0-9A-Fa-f]", ""); // Eliminar caracteres no hexadecimales
        p = new BigInteger(pHex, 16);
    }

    // Valor aleatorio para g
    SecureRandom random = new SecureRandom();
    g = BigInteger.valueOf(random.nextInt(100) + 2); // Valor aleatorio entre 2 y 101

    // Verificar que p y g sean válidos
    if (p == null || g == null || p.signum() <= 0 || g.signum() <= 0) {
        System.out.println("Salida de OpenSSL: " + output.toString());
        throw new IllegalArgumentException("Parámetros Diffie-Hellman inválidos generados");
    }

    // Mostrar los parámetros generados por OpenSSL
    System.out.println("Parámetros Diffie-Hellman generados:");
    System.out.println("p: " + p.toString(16));
    System.out.println("g: " + g.toString(16));

    return new BigInteger[]{p, g};
}
}