package caso3_jj.diazo1_p.paffen;

public class KeyDerivation {
    private byte[] digest;

    // Constructor para recibir el digest desde otra parte del programa
    public KeyDerivation(byte[] digest) {
        if (digest.length != 64) {
            throw new IllegalArgumentException("El digest debe tener 64 bytes (512 bits).");
        }
        this.digest = digest;
    }

    public void deriveKeys() {
        // Obtener los primeros 32 bytes para la clave de cifrado
        byte[] encryptionKey = new byte[32];
        System.arraycopy(digest, 0, encryptionKey, 0, 32);

        // Obtener los últimos 32 bytes para la clave HMAC
        byte[] hmacKey = new byte[32];
        System.arraycopy(digest, 32, hmacKey, 0, 32);

        // Mostrar las claves generadas
        System.out.println("Clave de cifrado: " + bytesToHex(encryptionKey));
        System.out.println("Clave HMAC: " + bytesToHex(hmacKey));
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

    // Método principal para pruebas
    public static void main(String[] args) {
        // Supongamos que el digest calculado es de 64 bytes (512 bits) - Esto es solo un ejemplo
        byte[] exampleDigest = new byte[64]; // Reemplaza con el digest real que obtuviste previamente
        for (int i = 0; i < 64; i++) {
            exampleDigest[i] = (byte) i; // Datos de ejemplo
        }

        // Crear instancia de KeyDerivation y derivar claves
        KeyDerivation keyDerivation = new KeyDerivation(exampleDigest);
        keyDerivation.deriveKeys();
    }
}
