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
import javax.swing.border.Border;
import java.util.Base64;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.event.*;
import javax.swing.JFileChooser;


public class BUBU {
    JButton btnEncrypt;
    JButton btnDecrypt;
    private final static String ALGO="AES/CBC/PKCS5PADDING";
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException{
        //GUI stuff
        JFrame frame = new JFrame();
        frame.setLayout(null);

        //frame.setVisible(true);



        String inputPath = "src/files/plain.txt";
        String outputPath = "src/files/ciphered.txt";

        String inputText = readInputFile(inputPath);

        KeyGenerator key=KeyGenerator.getInstance("AES");
        key.init(128);
        //SecretKey secretKey = key.generateKey();
        //##############################################################CHANGE KEY HERE####################################################################
        SecretKeySpec sks=new SecretKeySpec("aesEncryptionKey".getBytes(),"AES");
        byte[] bs=new byte[128];
        //##############################################################CHANGE VECTOR HERE####################################################################
        String sab = "aesEncryptionKey";
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
        byte[] outputDecryptedCustom = cipher.doFinal(Base64.getDecoder().decode("3fHgXD6NRGZIxBMFos0NaWg89NboBzgJfYCyQJdAenI=".getBytes()));

        System.out.println(new String(outputDecrypted,"UTF-8"));
        System.out.println(new String(outputDecryptedCustom,"UTF-8"));

/*        try (Writer writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(outputPath), "UTF-8"))) {
            writer.write(inputText);
    }*/
        JLabel lblKey = new JLabel();
        lblKey.setText("IEVADIET KEY 128BIT");
        lblKey.setForeground(new Color(0x00FF00));
        lblKey.setFont(new Font("MV Boli",Font.BOLD,15));
        lblKey.setVerticalAlignment(JLabel.TOP);
        lblKey.setHorizontalAlignment(JLabel.CENTER);
        lblKey.setBounds(100,0,250,50);
        frame.add(lblKey);

        JLabel lblVector = new JLabel();
        lblVector.setText("IEVADIET VEKTORU 128BIT");
        lblVector.setForeground(new Color(0x00FF00));
        lblVector.setFont(new Font("MV Boli",Font.BOLD,15));
        lblVector.setVerticalAlignment(JLabel.TOP);
        lblVector.setHorizontalAlignment(JLabel.CENTER);
        lblVector.setBounds(100,100,250,50);
        frame.add(lblVector);

        Border border = BorderFactory.createLineBorder(Color.black,3);

        JTextField txtKey = new JTextField();
        txtKey.setPreferredSize(new Dimension(250,40));
        //textField.setVerticalAlignment(JLabel.TOP);
        txtKey.setHorizontalAlignment(JLabel.CENTER);
        txtKey.setBounds(100,50,250,50);
        txtKey.setVisible(true);
        txtKey.setBorder(border);
        frame.add(txtKey);

        JTextField txtVector = new JTextField();
        txtVector.setPreferredSize(new Dimension(250,40));
        //textField.setVerticalAlignment(JLabel.TOP);
        txtVector.setHorizontalAlignment(JLabel.CENTER);
        txtVector.setBounds(100,150,250,50);
        txtVector.setVisible(true);
        txtVector.setBorder(border);
        frame.add(txtVector);

        JLabel lblEncryption = new JLabel();
        lblEncryption.setText("ENCRYPTION REZULTATS:");
        lblEncryption.setForeground(new Color(0x00FF00));
        lblEncryption.setFont(new Font("MV Boli",Font.BOLD,15));
        lblEncryption.setVerticalAlignment(JLabel.TOP);
        lblEncryption.setHorizontalAlignment(JLabel.CENTER);
        lblEncryption.setBounds(10,400,800,50);
        frame.add(lblEncryption);

        JLabel lblPlaintext = new JLabel();
        lblPlaintext.setText("IEVADIET PLAIN TEKSTU");
        lblPlaintext.setForeground(new Color(0x00FF00));
        lblPlaintext.setFont(new Font("MV Boli",Font.BOLD,15));
        lblPlaintext.setVerticalAlignment(JLabel.TOP);
        lblPlaintext.setHorizontalAlignment(JLabel.CENTER);
        lblPlaintext.setBounds(100,200,250,50);
        frame.add(lblPlaintext);

        JTextField txtPlaintext = new JTextField();
        txtPlaintext.setPreferredSize(new Dimension(250,40));
        //textField.setVerticalAlignment(JLabel.TOP);
        txtPlaintext.setHorizontalAlignment(JLabel.CENTER);
        txtPlaintext.setBounds(100,250,250,50);
        txtPlaintext.setVisible(true);
        txtPlaintext.setBorder(border);
        frame.add(txtPlaintext);

        JButton btnEncrypt = new JButton("ENCRYPT");
        btnEncrypt.setBounds(100,350, 250,50);
        frame.add(btnEncrypt);
        btnEncrypt.addActionListener(e -> {
            try {
                KeyGenerator key1=KeyGenerator.getInstance("AES");
            } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                noSuchAlgorithmException.printStackTrace();
            }
            key.init(128);
            //SecretKey secretKey = key.generateKey();
            //##############################################################CHANGE KEY HERE####################################################################
            SecretKeySpec sks1=new SecretKeySpec(txtKey.getText().getBytes(),"AES");
            byte[] bs1=new byte[128];
            //##############################################################CHANGE VECTOR HERE####################################################################
            String sab1 = txtVector.getText();
            bs1 = sab1.getBytes();
            //SecureRandom random=new SecureRandom();
            //random.nextBytes(bs);
            IvParameterSpec ivParameterSpec1 = new IvParameterSpec(bs1);

            Cipher cipher1= null;
            try {
                cipher1 = Cipher.getInstance(ALGO);
            } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                noSuchAlgorithmException.printStackTrace();
            } catch (NoSuchPaddingException noSuchPaddingException) {
                noSuchPaddingException.printStackTrace();
            }
            try {
                cipher1.init(Cipher.ENCRYPT_MODE, sks1, ivParameterSpec1);
            } catch (InvalidKeyException invalidKeyException) {
                invalidKeyException.printStackTrace();
            } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
                invalidAlgorithmParameterException.printStackTrace();
            }

            //##############################################################CHANGE PLAINTEXT HERE####################################################################
            byte[] outputEncryption1 = new byte[0];
            try {
                outputEncryption1 = Base64.getEncoder().encode(cipher1.doFinal(txtPlaintext.getText().getBytes()));
            } catch (IllegalBlockSizeException illegalBlockSizeException) {
                illegalBlockSizeException.printStackTrace();
            } catch (BadPaddingException badPaddingException) {
                badPaddingException.printStackTrace();
            }
            String output1 = null;
            try {
                output1 = new String(outputEncryption1,"UTF-8");
            } catch (UnsupportedEncodingException unsupportedEncodingException) {
                unsupportedEncodingException.printStackTrace();
            }
            System.out.println(output1);
            lblEncryption.setText("ENCRYPTION REZULTATS: " + output1);
        });















        JLabel lblKeyDecrypt = new JLabel();
        lblKeyDecrypt.setText("IEVADIET KEY 128BIT");
        lblKeyDecrypt.setForeground(new Color(0x00FF00));
        lblKeyDecrypt.setFont(new Font("MV Boli",Font.BOLD,15));
        lblKeyDecrypt.setVerticalAlignment(JLabel.TOP);
        lblKeyDecrypt.setHorizontalAlignment(JLabel.CENTER);
        lblKeyDecrypt.setBounds(400,0,250,50);
        frame.add(lblKeyDecrypt);

        JLabel lblVectorDecrypt = new JLabel();
        lblVectorDecrypt.setText("IEVADIET VEKTORU 128BIT");
        lblVectorDecrypt.setForeground(new Color(0x00FF00));
        lblVectorDecrypt.setFont(new Font("MV Boli",Font.BOLD,15));
        lblVectorDecrypt.setVerticalAlignment(JLabel.TOP);
        lblVectorDecrypt.setHorizontalAlignment(JLabel.CENTER);
        lblVectorDecrypt.setBounds(400,100,250,50);
        frame.add(lblVectorDecrypt);


        JTextField txtKeyDecrypt = new JTextField();
        txtKeyDecrypt.setPreferredSize(new Dimension(250,40));
        //textField.setVerticalAlignment(JLabel.TOP);
        txtKeyDecrypt.setHorizontalAlignment(JLabel.CENTER);
        txtKeyDecrypt.setBounds(400,50,250,50);
        txtKeyDecrypt.setVisible(true);
        txtKeyDecrypt.setBorder(border);
        frame.add(txtKeyDecrypt);

        JTextField txtVectorDecrypt = new JTextField();
        txtVectorDecrypt.setPreferredSize(new Dimension(250,40));
        //textField.setVerticalAlignment(JLabel.TOP);
        txtVectorDecrypt.setHorizontalAlignment(JLabel.CENTER);
        txtVectorDecrypt.setBounds(400,150,250,50);
        txtVectorDecrypt.setVisible(true);
        txtVectorDecrypt.setBorder(border);
        frame.add(txtVectorDecrypt);

        JLabel lblDecryption = new JLabel();
        lblDecryption.setText("DECRYPTION REZULTATS:");
        lblDecryption.setForeground(new Color(0x00FF00));
        lblDecryption.setFont(new Font("MV Boli",Font.BOLD,15));
        lblDecryption.setVerticalAlignment(JLabel.TOP);
        lblDecryption.setHorizontalAlignment(JLabel.CENTER);
        lblDecryption.setBounds(10,450,800,50);
        frame.add(lblDecryption);

        JLabel lblCiphertext = new JLabel();
        lblCiphertext.setText("IEVADIET CIPHER TEKSTU");
        lblCiphertext.setForeground(new Color(0x00FF00));
        lblCiphertext.setFont(new Font("MV Boli",Font.BOLD,15));
        lblCiphertext.setVerticalAlignment(JLabel.TOP);
        lblCiphertext.setHorizontalAlignment(JLabel.CENTER);
        lblCiphertext.setBounds(400,200,250,50);
        frame.add(lblCiphertext);

        JTextField txtCiphertext = new JTextField();
        txtCiphertext.setPreferredSize(new Dimension(250,40));
        //textField.setVerticalAlignment(JLabel.TOP);
        txtCiphertext.setHorizontalAlignment(JLabel.CENTER);
        txtCiphertext.setBounds(400,250,250,50);
        txtCiphertext.setVisible(true);
        txtCiphertext.setBorder(border);
        frame.add(txtCiphertext);

        JButton btnDecrypt = new JButton("DECRYPT");
        btnDecrypt.setBounds(400,350, 250,50);
        frame.add(btnDecrypt);
        btnDecrypt.addActionListener(e -> {
            SecretKeySpec sks9=new SecretKeySpec(txtKeyDecrypt.getText().getBytes(),"AES");
            byte[] bs9=new byte[128];
            //##############################################################CHANGE VECTOR HERE####################################################################
            String sab9 = txtVectorDecrypt.getText();
            bs9 = sab9.getBytes();
            //SecureRandom random=new SecureRandom();
            //random.nextBytes(bs);
            IvParameterSpec ivParameterSpec9 = new IvParameterSpec(bs9);

            Cipher cipher9= null;
            try {
                cipher9 = Cipher.getInstance(ALGO);
            } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                noSuchAlgorithmException.printStackTrace();
            } catch (NoSuchPaddingException noSuchPaddingException) {
                noSuchPaddingException.printStackTrace();
            }

            try {
                cipher9.init(Cipher.DECRYPT_MODE, sks9, ivParameterSpec9);
            } catch (InvalidKeyException invalidKeyException) {
                invalidKeyException.printStackTrace();
            } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
                invalidAlgorithmParameterException.printStackTrace();
            }

            //decrypts custom text
            //##############################################################CHANGE ENCRYPTED STRING HERE####################################################################
            byte[] outputDecryptedCustom9 = new byte[0];
            try {
                outputDecryptedCustom9 = cipher9.doFinal(Base64.getDecoder().decode(txtCiphertext.getText().getBytes()));
            } catch (IllegalBlockSizeException illegalBlockSizeException) {
                illegalBlockSizeException.printStackTrace();
            } catch (BadPaddingException badPaddingException) {
                badPaddingException.printStackTrace();
            }
            String output9 =null;
            try {
                System.out.println(new String(outputDecryptedCustom9,"UTF-8"));
                output9 = new String(outputDecryptedCustom9,"UTF-8");
            } catch (UnsupportedEncodingException unsupportedEncodingException) {
                unsupportedEncodingException.printStackTrace();
            }
            lblDecryption.setText("DECRIPTION REZULTATS: " + output9);

        });

        JButton btnFile = new JButton("Sifret failu");
        btnFile.setBounds(100,500, 250,50);
        btnFile.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();

            int response = fileChooser.showOpenDialog(null);
            if(response == JFileChooser.APPROVE_OPTION){
                File file = new File(fileChooser.getSelectedFile().getAbsolutePath());
                String inputTextFromFile = readInputFile(file.toString());
                System.out.println(inputTextFromFile);



                try {
                    KeyGenerator key1=KeyGenerator.getInstance("AES");
                } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                    noSuchAlgorithmException.printStackTrace();
                }
                key.init(128);
                //SecretKey secretKey = key.generateKey();
                //##############################################################CHANGE KEY HERE####################################################################
                SecretKeySpec sks11=new SecretKeySpec("encryptionIntVec".getBytes(),"AES");
                byte[] bs11=new byte[128];
                //##############################################################CHANGE VECTOR HERE####################################################################
                String sab11 = "encryptionIntVec";
                bs11 = sab11.getBytes();
                //SecureRandom random=new SecureRandom();
                //random.nextBytes(bs);
                IvParameterSpec ivParameterSpec11 = new IvParameterSpec(bs11);

                Cipher cipher11= null;
                try {
                    cipher11 = Cipher.getInstance(ALGO);
                } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                    noSuchAlgorithmException.printStackTrace();
                } catch (NoSuchPaddingException noSuchPaddingException) {
                    noSuchPaddingException.printStackTrace();
                }
                try {
                    cipher11.init(Cipher.ENCRYPT_MODE, sks11, ivParameterSpec11);
                } catch (InvalidKeyException invalidKeyException) {
                    invalidKeyException.printStackTrace();
                } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
                    invalidAlgorithmParameterException.printStackTrace();
                }

                //##############################################################CHANGE PLAINTEXT HERE####################################################################
                byte[] outputEncryption11 = new byte[0];
                try {
                    outputEncryption11 = Base64.getEncoder().encode(cipher11.doFinal(inputTextFromFile.getBytes()));
                } catch (IllegalBlockSizeException illegalBlockSizeException) {
                    illegalBlockSizeException.printStackTrace();
                } catch (BadPaddingException badPaddingException) {
                    badPaddingException.printStackTrace();
                }
                String output11 = null;
                try {
                    output11 = new String(outputEncryption11,"UTF-8");
                } catch (UnsupportedEncodingException unsupportedEncodingException) {
                    unsupportedEncodingException.printStackTrace();
                }
                System.out.println(output11);
                try (Writer writer11 = new BufferedWriter(new OutputStreamWriter(
                        new FileOutputStream(outputPath), "UTF-8"))) {
                    writer11.write(output11);
                } catch (UnsupportedEncodingException unsupportedEncodingException) {
                    unsupportedEncodingException.printStackTrace();
                } catch (FileNotFoundException fileNotFoundException) {
                    fileNotFoundException.printStackTrace();
                } catch (IOException ioException) {
                    ioException.printStackTrace();
                }

            }
        });
        frame.add(btnFile);






        JButton btnFileDecrypt = new JButton("Atsifret failu");
        btnFileDecrypt.setBounds(400,500, 250,50);
        btnFileDecrypt.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();

            int response = fileChooser.showOpenDialog(null);
            if(response == JFileChooser.APPROVE_OPTION) {
                File file = new File(fileChooser.getSelectedFile().getAbsolutePath());
                String inputTextFromFile99 = readInputFile(file.toString());
                System.out.println(inputTextFromFile99);



                SecretKeySpec sks99=new SecretKeySpec("encryptionIntVec".getBytes(),"AES");
                byte[] bs99=new byte[128];
                //##############################################################CHANGE VECTOR HERE####################################################################
                String sab99 = "encryptionIntVec";
                bs99 = sab99.getBytes();
                //SecureRandom random=new SecureRandom();
                //random.nextBytes(bs);
                IvParameterSpec ivParameterSpec99 = new IvParameterSpec(bs99);

                Cipher cipher99= null;
                try {
                    cipher99 = Cipher.getInstance(ALGO);
                } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                    noSuchAlgorithmException.printStackTrace();
                } catch (NoSuchPaddingException noSuchPaddingException) {
                    noSuchPaddingException.printStackTrace();
                }

                try {
                    cipher99.init(Cipher.DECRYPT_MODE, sks99, ivParameterSpec99);
                } catch (InvalidKeyException invalidKeyException) {
                    invalidKeyException.printStackTrace();
                } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
                    invalidAlgorithmParameterException.printStackTrace();
                }

                //decrypts custom text
                //##############################################################CHANGE ENCRYPTED STRING HERE####################################################################
                byte[] outputDecryptedCustom99 = new byte[0];
                try {
                    outputDecryptedCustom99 = cipher99.doFinal(Base64.getDecoder().decode(inputTextFromFile99.getBytes()));
                } catch (IllegalBlockSizeException illegalBlockSizeException) {
                    illegalBlockSizeException.printStackTrace();
                } catch (BadPaddingException badPaddingException) {
                    badPaddingException.printStackTrace();
                }
                String output99 =null;
                try {
                    System.out.println(new String(outputDecryptedCustom99,"UTF-8"));
                    output99 = new String(outputDecryptedCustom99,"UTF-8");
                } catch (UnsupportedEncodingException unsupportedEncodingException) {
                    unsupportedEncodingException.printStackTrace();
                }
                try (Writer writer99 = new BufferedWriter(new OutputStreamWriter(
                        new FileOutputStream(outputPath), "UTF-8"))) {
                    writer99.write(output99);
                } catch (UnsupportedEncodingException unsupportedEncodingException) {
                    unsupportedEncodingException.printStackTrace();
                } catch (FileNotFoundException fileNotFoundException) {
                    fileNotFoundException.printStackTrace();
                } catch (IOException ioException) {
                    ioException.printStackTrace();
                }

            }
        });
        frame.add(btnFileDecrypt);















        frame.setTitle("AES");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setSize(800,600);

        frame.setVisible(true);
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