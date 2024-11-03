package caso3_jj.diazo1_p.paffen;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class PackageClient {
    private static final String SERVER_ADDRESS = "localhost"; // Dirección del servidor
    private static final int SERVER_PORT = 12345; // Puerto del servidor
    private static final String SERVER_PUBLIC_KEY_FILE = "public.key"; // Archivo de la llave pública del servidor

    private PublicKey serverPublicKey; // Llave pública del servidor

    public static void main(String[] args) {
        PackageClient client = new PackageClient();
        try {
            client.readServerPublicKey(); // Leer la llave pública del servidor
            client.run(); // Ejecutar el cliente
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Lee la llave pública del servidor desde un archivo.
     * 
     * @throws Exception si ocurre un error al leer la llave pública.
     */
    public void readServerPublicKey() throws Exception {
        byte[] publicKeyBytes = readKeyFromFile(SERVER_PUBLIC_KEY_FILE);
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        serverPublicKey = keyFactory.generatePublic(publicSpec);
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
     * Ejecuta el cliente, permitiendo al usuario seleccionar el modo de operación.
     */
    private void run() {
        try {
            Scanner scanner = new Scanner(System.in);
            System.out.println("Seleccione el modo de operación: \n 1. Iterativo \n 2. Concurrente");
            int mode = scanner.nextInt();
            if (mode == 1) {
                runIterative(); // Ejecutar en modo iterativo
            } else if (mode == 2) {
                System.out.println("Ingrese el número de delegados:");
                int numDelegates = scanner.nextInt();
                runConcurrent(numDelegates); // Ejecutar en modo concurrente
            } else {
                System.out.println("Modo no válido.");
            }
            scanner.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Ejecuta el cliente en modo iterativo, enviando solicitudes secuenciales.
     */
    private void runIterative() {
        for (int i = 0; i < 32; i++) {
            sendRequest("user" + i, "pkg" + i);
        }
    }

    /**
     * Ejecuta el cliente en modo concurrente, enviando solicitudes en paralelo.
     * 
     * @param numDelegates el número de delegados (solicitudes) a enviar.
     */
    private void runConcurrent(int numDelegates) {
        // Enviar el número de delegados al servidor
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {
            out.writeInt(numDelegates);
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    
        // Limitar el número máximo de delegados a 40
        int maxDelegates = 40;
        Semaphore delegateSemaphore = new Semaphore(maxDelegates);
    
        ExecutorService executorService = Executors.newFixedThreadPool(numDelegates);
        for (int i = 0; i < numDelegates; i++) {
            final int index = i;
            executorService.submit(() -> {
                try {
                    // Adquirir un permiso antes de enviar la solicitud
                    delegateSemaphore.acquire();
                    try {
                        sendRequest("user" + index, "pkg" + index);
                    } finally {
                        // Liberar el permiso después de que la solicitud haya sido manejada
                        delegateSemaphore.release();
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            });
    
            // Cada vez que se completa un grupo de 40 delegados, esperar 1 ms
            if ((i + 1) % maxDelegates == 0 || i == numDelegates - 1) {
                try {
                    // Esperar a que todos los delegados actuales terminen
                    delegateSemaphore.acquire(maxDelegates);
                    delegateSemaphore.release(maxDelegates);
                    System.out.println("Se liberaron 40 delegados.");
                    // Esperar 1 ms antes de permitir que el siguiente grupo de delegados se ejecute
                    Thread.sleep(1);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
        executorService.shutdown();
    }

    /**
     * Envía una solicitud al servidor para obtener el estado de un paquete.
     * 
     * @param uid el identificador del usuario.
     * @param packageId el identificador del paquete.
     * @return un arreglo de tiempos medidos durante la solicitud.
     */
    public long[] sendRequest(String uid, String packageId) {
        long[] times = new long[3];
        try {
            Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
    
            // Paso 1: Enviar "SECINIT" al servidor
            out.writeUTF("SECINIT");
            out.flush();
    
            // Paso 2a: Generar desafío aleatorio (Reto)
            SecureRandom random = new SecureRandom();
            byte[] retoBytes = new byte[16]; // Desafío de 16 bytes
            random.nextBytes(retoBytes);
            String reto = Base64.getEncoder().encodeToString(retoBytes);
    
            // Cifrar Reto con la llave pública del servidor
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            byte[] encryptedReto = rsaCipher.doFinal(reto.getBytes());
    
            // Paso 2b: Enviar Reto cifrado (R) al servidor
            out.writeInt(encryptedReto.length);
            out.write(encryptedReto);
            out.flush();
    
            // Paso 4: Recibir Rta del servidor
            int rtaLength = in.readInt();
            byte[] rtaBytes = new byte[rtaLength];
            in.readFully(rtaBytes);
            String rta = new String(rtaBytes);
    
            // Paso 5: Verificar que Rta == Reto
            if (!reto.equals(rta)) {
                System.out.println("Autenticación del servidor fallida.");
                out.writeUTF("ERROR");
                socket.close();
                return times;
            } else {
                out.writeUTF("OK");
                out.flush();
            }
    
            // Paso 8: Recibir G, P, G^x y firma del servidor
            int gLength = in.readInt();
            byte[] gBytes = new byte[gLength];
            in.readFully(gBytes);
            BigInteger g = new BigInteger(gBytes);
    
            int pLength = in.readInt();
            byte[] pBytes = new byte[pLength];
            in.readFully(pBytes);
            BigInteger p = new BigInteger(pBytes);
    
            int gxLength = in.readInt();
            byte[] gxBytes = new byte[gxLength];
            in.readFully(gxBytes);
            BigInteger gx = new BigInteger(gxBytes);
    
            int sigLength = in.readInt();
            byte[] sigBytes = new byte[sigLength];
            in.readFully(sigBytes);
    
            // Paso 9: Verificar firma
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(serverPublicKey);
            signature.update(gBytes);
            signature.update(pBytes);
            signature.update(gxBytes);
    
            if (!signature.verify(sigBytes)) {
                System.out.println("Firma de Diffie-Hellman no válida.");
                out.writeUTF("ERROR");
                socket.close();
                return times;
            } else {
                out.writeUTF("OK");
                out.flush();
            }
    
            // Paso 11a: Calcular G^y y derivar llaves
            SecureRandom randomY = new SecureRandom();
            BigInteger y = new BigInteger(1024, randomY);
            BigInteger gy = g.modPow(y, p);
    
            // Enviar G^y al servidor
            byte[] gyBytes = gy.toByteArray();
            out.writeInt(gyBytes.length);
            out.write(gyBytes);
            out.flush();
    
            // Calcular secreto compartido K = (G^x)^y mod p
            BigInteger sharedSecret = gx.modPow(y, p);
            byte[] sharedSecretBytes = sharedSecret.toByteArray();
    
            // Calcular digest SHA-512 de la llave maestra
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(sharedSecretBytes);
    
            // Dividir digest en dos llaves de 32 bytes
            byte[] keyEncryption = Arrays.copyOfRange(digest, 0, 32); // Primeros 256 bits
            byte[] keyHMAC = Arrays.copyOfRange(digest, 32, 64); // Últimos 256 bits
    
            SecretKeySpec aesKey = new SecretKeySpec(keyEncryption, "AES");
            SecretKeySpec hmacKey = new SecretKeySpec(keyHMAC, "HmacSHA384");
    
            // Paso 12: Enviar IV al servidor
            byte[] ivBytes = new byte[16]; // IV de 16 bytes
            random.nextBytes(ivBytes);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
    
            out.writeInt(ivBytes.length);
            out.write(ivBytes);
            out.flush();
    
            // Preparar cifrador AES
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            Mac hmac = Mac.getInstance("HmacSHA384");
            hmac.init(hmacKey);
    
            // Paso 13: Enviar uid cifrado y HMAC
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
            byte[] encUid = aesCipher.doFinal(uid.getBytes());
            byte[] hmacUid = hmac.doFinal(encUid);
    
            out.writeInt(encUid.length);
            out.write(encUid);
    
            out.writeInt(hmacUid.length);
            out.write(hmacUid);
            out.flush();
    
            // Paso 14: Enviar package_id cifrado y HMAC
            byte[] encPkgId = aesCipher.doFinal(packageId.getBytes());
            byte[] hmacPkgId = hmac.doFinal(encPkgId);
    
            out.writeInt(encPkgId.length);
            out.write(encPkgId);
    
            out.writeInt(hmacPkgId.length);
            out.write(hmacPkgId);
            out.flush();
    
            // Paso 16: Recibir estado cifrado y HMAC
            int encStateLength = in.readInt();
            byte[] encState = new byte[encStateLength];
            in.readFully(encState);
    
            int hmacStateLength = in.readInt();
            byte[] hmacState = new byte[hmacStateLength];
            in.readFully(hmacState);
    
            // Verificar HMAC
            byte[] computedHmacState = hmac.doFinal(encState);
            if (!Arrays.equals(hmacState, computedHmacState)) {
                System.out.println("HMAC del estado no válido.");
                socket.close();
                return times;
            }
    
            // Descifrar estado
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
            byte[] stateBytes = aesCipher.doFinal(encState);
            String state = new String(stateBytes);
    
            System.out.println("Estado del paquete: " + state);
    
            // Paso 18: Terminar
            socket.close();
    
        } catch (Exception e) {
            e.printStackTrace();
        }
        return times;
    }
}