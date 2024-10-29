package caso3_jj.diazo1_p.paffen;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class DiffieHellman {
    public static void main(String[] args) {
        // Valores de p y g obtenidos de la salida de OpenSSL
        String pHex = "0098e60e1f707fc8f7b37f8ea5cee0b37d5b93664d19e31b7165ef3c8a8cef45acdecba4016aa0f960ffa2eb0f6a93def57aaacd9a2362bb37d075ad852018d371efa2600605fe465961c7d790f11985ec9f572cf08be42be7603ff5070d2612b4d56820b1c7a022ab96a9ee9aa57061725c02f610dafe9545bab3ec924b72d1bca7";
        BigInteger p = new BigInteger(pHex, 16);
        BigInteger g = BigInteger.valueOf(2); // Generador g es 2
        
        // Generar un número aleatorio (clave privada)
        SecureRandom random = new SecureRandom();
        BigInteger privateKey = new BigInteger(1024, random);
        
        // Calcular la clave pública usando g^privateKey mod p
        BigInteger publicKey = g.modPow(privateKey, p);
        System.out.println("Clave pública: " + publicKey);
        
        // Simular otra clave privada y clave pública para pruebas
        BigInteger otherPrivateKey = new BigInteger(1024, random);
        BigInteger otherPublicKey = g.modPow(otherPrivateKey, p);
        System.out.println("Clave pública del otro participante (simulada): " + otherPublicKey);
        
        // Calcular la clave secreta compartida usando la clave pública del otro y tu clave privada
        BigInteger sharedSecret = otherPublicKey.modPow(privateKey, p);
        System.out.println("Clave secreta compartida: " + sharedSecret);

        // Convertir la clave secreta a un arreglo de bytes
        byte[] sharedSecretBytes = sharedSecret.toByteArray();

        try {
            // Calcular el digest SHA-512
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(sharedSecretBytes);

            // Mostrar el digest
            System.out.println("Digest (SHA-512): " + bytesToHex(digest));
            
            byte[] dig = sha512.digest(sharedSecretBytes);
            KeyDerivation keyDerivation = new KeyDerivation(dig);
            keyDerivation.deriveKeys();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
       

    }

    // Método auxiliar para convertir bytes a una representación en hexadecimal
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
