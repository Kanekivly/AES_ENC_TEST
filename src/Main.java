
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        boolean running = true;

        while (running) {
            System.out.println("AES Encryption Tool");
            System.out.println("   DarkOaks Tech   ");
            System.out.println("---------------");
            System.out.println("1. Encrypt");
            System.out.println("2. Decrypt");
            System.out.println("3. Exit");
            System.out.print("Choose an option: ");
            int option = scanner.nextInt();
            scanner.nextLine(); 

            if (option == 3) {
                running = false;
                continue;
            }

            if (option < 1 || option > 3) {
                System.out.println("Invalid option. Please choose again.");
                continue;
            }

            System.out.print("Enter message: ");
            String message = scanner.nextLine();

            System.out.print("Enter password: ");
            String password = scanner.nextLine();

            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);

            SecretKey key = deriveKey(password, salt);

            try {
                if (option == 1) {
                    String encryptedMessage = encrypt(message, key);
                    System.out.println("Encrypted Message: " + encryptedMessage);
                } else {
                    String decryptedMessage = decrypt(message, key);
                    System.out.println("Decrypted Message: " + decryptedMessage);
                }
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }

            System.out.println();
        }

        scanner.close();
    }

    // Derive a secret key from a password
    public static SecretKey deriveKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHMACSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256); 
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    // Encrypt a message
    public static String encrypt(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Decrypt a message
    public static String decrypt(String encryptedMessage, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}
