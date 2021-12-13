import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;


public class BUBU {
    private final static String ALGO="AES/CBC/PKCS5PADDING";
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        KeyGenerator key=KeyGenerator.getInstance("AES");
        key.init(128);
        //SecretKey secretKey = key.generateKey();
        //##############################################################CHANGE KEY HERE####################################################################
        SecretKeySpec sks=new SecretKeySpec("qqqEncryptionKey".getBytes(),"AES");
        byte[] bs=new byte[128];
        //##############################################################CHANGE VECTOR HERE####################################################################
        String sab = "wwwryptionIntVec";
        bs = sab.getBytes();
        //SecureRandom random=new SecureRandom();
        //random.nextBytes(bs);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(bs);

        Cipher cipher=Cipher.getInstance(ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, sks, ivParameterSpec);

        //##############################################################CHANGE PLAINTEXT HERE####################################################################
        byte[] outputEncryption = Base64.getEncoder().encode(cipher.doFinal("newhelliTEXT".getBytes()));
        String output = new String(outputEncryption,"UTF-8");
        System.out.println(output);
        //System.out.println(new String(outputEncryption));
        //System.out.println(new String(outputEncryption));

        //DECRYPT
        cipher.init(Cipher.DECRYPT_MODE, sks, ivParameterSpec);
        //decrypts the text you encrypted
        byte[] outputDecrypted = cipher.doFinal(Base64.getDecoder().decode(output.getBytes()));
        //decrypts custom text
        //##############################################################CHANGE ENCRYPTED STRING HERE####################################################################
        byte[] outputDecryptedCustom = cipher.doFinal(Base64.getDecoder().decode("pmspJktRY+jET9pGxRoyZA==".getBytes()));

        System.out.println(new String(outputDecrypted,"UTF-8"));
        System.out.println(new String(outputDecryptedCustom,"UTF-8"));
    }
}
