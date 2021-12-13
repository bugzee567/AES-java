import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.util.Base64;


public class BUBU {
    private final static String ALGO="AES/CBC/PKCS5PADDING";
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        //GUI stuff
        JFrame frame = new JFrame();
        frame.setTitle("AES");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(800,600);
        frame.setLayout(null);
        frame.setVisible(true);

        JLabel label = new JLabel();
        label.setText("hello");
        label.setForeground(new Color(0x00FF00));
        label.setFont(new Font("MV Boli",Font.BOLD,35));
        label.setVerticalAlignment(JLabel.TOP);
        label.setHorizontalAlignment(JLabel.CENTER);
        label.setBounds(300,0,250,50);
        frame.add(label);

        JTextField textField = new JTextField();
        textField.setPreferredSize(new Dimension(250,40));
        //textField.setVerticalAlignment(JLabel.TOP);
        textField.setHorizontalAlignment(JLabel.CENTER);
        textField.setBounds(300,50,250,50);
        textField.setVisible(true);
        //textField.setBorder();
        frame.add(textField);


        String inputPath = "src/files/plain.txt";
        String outputPath = "src/files/ciphered.txt";

        String inputText = readInputFile(inputPath);

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

        try (Writer writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(outputPath), "UTF-8"))) {
            writer.write(inputText);
    }
}
    private static String readInputFile(String inputPath)
    {
        String content = "";

        try
        {
            content = new String ( Files.readAllBytes( Paths.get(inputPath) ) );
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }

        return content;
    }

}