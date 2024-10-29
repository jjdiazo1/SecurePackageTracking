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
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 12345;
    private static final String SERVER_PUBLIC_KEY_FILE = "public.key";

    private PublicKey serverPublicKey;

    public static void main(String[] args) {
        PackageClient client = new PackageClient();
        try {
            client.readServerPublicKey();
            client.run();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void readServerPublicKey() throws Exception {
        // Read public key
        byte[] publicKeyBytes = readKeyFromFile(SERVER_PUBLIC_KEY_FILE);
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        serverPublicKey = keyFactory.generatePublic(publicSpec);
    }

    private byte[] readKeyFromFile(String filename) throws IOException {
        File file = new File(filename);
        FileInputStream fis = new FileInputStream(file);
        byte[] keyBytes = new byte[(int) file.length()];
        fis.read(keyBytes);
        fis.close();
        return keyBytes;
    }

    private void run() {
        try {
            Scanner scanner = new Scanner(System.in);
            System.out.println("Seleccione el modo de operación: \n 1. Iterativo \n 2. Concurrente");
            int mode = scanner.nextInt();
            if (mode == 1) {
                runIterative();
            } else if (mode == 2) {
                System.out.println("Ingrese el número de delegados:");
                int numDelegates = scanner.nextInt();
                runConcurrent(numDelegates);
            } else {
                System.out.println("Modo no válido.");
            }
            scanner.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void runIterative() {
        for (int i = 0; i < 32; i++) {
            sendRequest("user" + i, "pkg" + i);
        }
    }

    private void runConcurrent(int numDelegates) {
        ExecutorService executorService = Executors.newFixedThreadPool(numDelegates);
        for (int i = 0; i < numDelegates; i++) {
            final int index = i;
            executorService.submit(() -> sendRequest("user" + index, "pkg" + index));
        }
        executorService.shutdown();
    }

    public long[] sendRequest(String uid, String packageId) {
        long[] times = new long[3];
        try {
            Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
    
            // Step 1: Send "SECINIT" to server
            out.writeUTF("SECINIT");
            out.flush();
    
            // Step 2a: Generate random challenge (Reto)
            SecureRandom random = new SecureRandom();
            byte[] retoBytes = new byte[16]; // 16 bytes challenge
            random.nextBytes(retoBytes);
            String reto = Base64.getEncoder().encodeToString(retoBytes);
    
            // Encrypt Reto with server's public key
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            byte[] encryptedReto = rsaCipher.doFinal(reto.getBytes());
    
            // Step 2b: Send encrypted Reto (R) to server
            out.writeInt(encryptedReto.length);
            out.write(encryptedReto);
            out.flush();
    
            // Step 4: Receive Rta from server
            int rtaLength = in.readInt();
            byte[] rtaBytes = new byte[rtaLength];
            in.readFully(rtaBytes);
            String rta = new String(rtaBytes);
    
            // Step 5: Verify Rta == Reto
            if (!reto.equals(rta)) {
                System.out.println("Autenticación del servidor fallida.");
                out.writeUTF("ERROR");
                socket.close();
                return times;
            } else {
                out.writeUTF("OK");
                out.flush();
            }
    
            // Step 8: Receive G, P, G^x and signature from server
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
    
            // Step 9: Verify signature
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
    
            // Step 11a: Compute G^y and derive keys
            SecureRandom randomY = new SecureRandom();
            BigInteger y = new BigInteger(1024, randomY);
            BigInteger gy = g.modPow(y, p);
    
            // Send G^y to server
            byte[] gyBytes = gy.toByteArray();
            out.writeInt(gyBytes.length);
            out.write(gyBytes);
            out.flush();
    
            // Compute shared secret K = (G^x)^y mod p
            BigInteger sharedSecret = gx.modPow(y, p);
            byte[] sharedSecretBytes = sharedSecret.toByteArray();

            // Compute digest SHA-512 of the master key
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(sharedSecretBytes);

            // Split digest into two 32-byte keys
            byte[] keyEncryption = Arrays.copyOfRange(digest, 0, 32); // First 256 bits
            byte[] keyHMAC = Arrays.copyOfRange(digest, 32, 64); // Last 256 bits

            SecretKeySpec aesKey = new SecretKeySpec(keyEncryption, "AES");
            SecretKeySpec hmacKey = new SecretKeySpec(keyHMAC, "HmacSHA384");

            // Step 12: Send IV to server
            byte[] ivBytes = new byte[16]; // 16 bytes IV
            random.nextBytes(ivBytes);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
    
            out.writeInt(ivBytes.length);
            out.write(ivBytes);
            out.flush();
    
            // Prepare AES cipher
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            Mac hmac = Mac.getInstance("HmacSHA384");
            hmac.init(hmacKey);
    
            // Step 13: Send encrypted uid and HMAC
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
            byte[] encUid = aesCipher.doFinal(uid.getBytes());
            byte[] hmacUid = hmac.doFinal(encUid);
    
            out.writeInt(encUid.length);
            out.write(encUid);
    
            out.writeInt(hmacUid.length);
            out.write(hmacUid);
            out.flush();
    
            // Step 14: Send encrypted package_id and HMAC
            byte[] encPkgId = aesCipher.doFinal(packageId.getBytes());
            byte[] hmacPkgId = hmac.doFinal(encPkgId);
    
            out.writeInt(encPkgId.length);
            out.write(encPkgId);
    
            out.writeInt(hmacPkgId.length);
            out.write(hmacPkgId);
            out.flush();
    
            // Step 16: Receive encrypted state and HMAC
            int encStateLength = in.readInt();
            byte[] encState = new byte[encStateLength];
            in.readFully(encState);
    
            int hmacStateLength = in.readInt();
            byte[] hmacState = new byte[hmacStateLength];
            in.readFully(hmacState);
    
            // Verify HMAC
            byte[] computedHmacState = hmac.doFinal(encState);
            if (!Arrays.equals(hmacState, computedHmacState)) {
                System.out.println("HMAC del estado no válido.");
                socket.close();
                return times;
            }
    
            // Decrypt state
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
            byte[] stateBytes = aesCipher.doFinal(encState);
            String state = new String(stateBytes);
    
            System.out.println("Estado del paquete: " + state);
    
            // Step 18: Terminate
            socket.close();
    
        } catch (Exception e) {
            e.printStackTrace();
        }
        return times;
    }
}