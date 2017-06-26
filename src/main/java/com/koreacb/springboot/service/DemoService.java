package com.koreacb.springboot.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * Referred from http://swlock.blogspot.kr/2016/01/rsa-java-2-3.html
 *
 * @author Myungkyo Jung
 */
@Service
public class DemoService {

    private static final Logger logger = LoggerFactory.getLogger(DemoService.class);

    /**
     * 공개키를 Key, 개인키를 Value로 담고 있는 키조합 저장장소.
     * 실전에서는 메모리가 아닌 DB에 저장되어야 한다.
     */
    private static final Map<String, String> keyRepository = new HashMap<>();

    /**
     * 공개키, 개인키 쌍을 생성한다. 생성된 공개키는 클라이언트(브라우저, 모바일폰)에 전달해주고, 개인키는 DB 등에 보관한다.
     * @return 생성된 공개키(Modulus, Exponent) 해시맵
     */
    public Map<String, String> generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        SecureRandom random = new SecureRandom();
        //KeyPairGenerator generator = KeyPairGenerator.getInstance("DiffieHellman", "SunJCE"); Not an RSA key: DH
        //KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "SunRsaSign"); // OK
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "SunJSSE"); // OK

        generator.initialize(2048, random); // 여기에서는 2048 bit 키를 생성하였음
        KeyPair pair = generator.generateKeyPair();
        Key publicKey = pair.getPublic();
        Key privateKey = pair.getPrivate();

        final String publicKeyString = byteArrayToHex(publicKey.getEncoded());
        final String privateKeyString = byteArrayToHex(privateKey.getEncoded());
        logger.debug("Key Generated(Public Key): " + publicKeyString);
        logger.debug("Key Generated(Private Key): " + privateKeyString);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
        String publicKeyModulus = publicKeySpec.getModulus().toString(16);
        String publicKeyExponent = publicKeySpec.getPublicExponent().toString(16);
        logger.debug("Key Generated(Public Key Modulus): " + publicKeyModulus);
        logger.debug("Key Generated(Public Key Exponent): "+ publicKeyExponent);
        keyRepository.put(publicKeyModulus, privateKeyString);

        Map<String, String> publicKeyMap = new HashMap<>();
        publicKeyMap.put("publicKeyModulus", publicKeyModulus);
        publicKeyMap.put("publicKeyExponent", publicKeyExponent);
        return publicKeyMap;
    }

    /**
     * 전달받은 문자열을 공개키로 암호화 한다.
     * 이 로직은 클라이언트단에서 수행하기 때문에 본 프로젝트에서는 직접 호출되지 않고 index.html에 동일한 로직을 수행하는 자바스크립트 로직이 구현되어 있다
     * @param inputString 암호화 대상이 되는 평문
     * @param publicKeyString 공개키
     * @return 공개키로 암호화된 암호문
     */
    public String encryptWithPublicKey(final String inputString, final String publicKeyString) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING", "SunJCE");

        // Turn the encoded key into a real RSA public key.
        // Public keys are encoded in X.509.
        X509EncodedKeySpec ukeySpec = new X509EncodedKeySpec(hexToByteArray(publicKeyString));
        KeyFactory ukeyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = null;
        try {
            publicKey = ukeyFactory.generatePublic(ukeySpec);
            System.out.println("pubKeyHex:" + byteArrayToHex(publicKey.getEncoded()));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        // 공개키를 전달하여 암호화
        byte[] input = inputString.getBytes();
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = cipher.doFinal(input);
        logger.debug("inputText:" + new String(input));
        logger.debug("inputHex:(" + input.length + "):" + byteArrayToHex(input));
        final String encryptedString = byteArrayToHex(cipherText);
        logger.debug("cipherHex:(" + cipherText.length + "):" + encryptedString);

        return encryptedString;
    }

    /**
     * 개인키를 사용해서 해당 문자열을 복호화한다.
     * @param publicKeyString Private key
     * @param cipherText Encrypted string to be decrypted
     */
    public void decrypt(final String publicKeyString, final String cipherText) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING", "SunJCE");
        // Turn the encoded key into a real RSA private key.
        // Private keys are encoded in PKCS#8.
        final String privateKeyString = keyRepository.get(publicKeyString);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(hexToByteArray(privateKeyString));
        KeyFactory rkeyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = null;
        try {
            privateKey = rkeyFactory.generatePrivate(keySpec);
            logger.debug("Let's decrypt with this Private Key:" + byteArrayToHex(privateKey.getEncoded()));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        // 개인키를 가지고있는쪽에서 복호화
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainText = cipher.doFinal(hexToByteArray(cipherText));
        System.out.println("Decrypted Result: " + new String(plainText));
    }


    /**
     * hex string to byte[]
     *
     * @param hex HEX String
     * @return converted byte array from hex string
     */
    private static byte[] hexToByteArray(String hex) {
        if (hex == null || hex.length() == 0) {
            return null;
        }
        byte[] ba = new byte[hex.length() / 2];
        for (int i = 0; i < ba.length; i++) {
            ba[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return ba;
    }

    // byte[] to hex sting
    public static String byteArrayToHex(byte[] byteArray) {
        if (byteArray == null || byteArray.length == 0) {
            return null;
        }
        StringBuilder stringBuffer = new StringBuilder(byteArray.length * 2);
        String hexNumber;
        for (byte aBa : byteArray) {
            hexNumber = "0" + Integer.toHexString(0xff & aBa);

            stringBuffer.append(hexNumber.substring(hexNumber.length() - 2));
        }
        return stringBuffer.toString();
    }
}