import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AESServiceImpl implements AESService {

	private String salt = "ssshhhhhhhhhhh!!!!";

	@Override
	public String decrypt(String strToEncrypt, String key) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException,
			IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = getCipher(Cipher.DECRYPT_MODE, getSecretKey(key));
		return new String(cipher.doFinal(Base64.getDecoder().decode(strToEncrypt)));
	}

	@Override
	public String encrypt(String strToDecrypt, String key) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException,
			IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, getSecretKey(key));
		return Base64.getEncoder().encodeToString(cipher.doFinal(strToDecrypt.getBytes("UTF-8")));
	}

	/**
	 * Can be used to construct a SecretKey from a byte array,without having to go
	 * through a (provider-based) SecretKeyFactory
	 * 
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private SecretKeySpec getSecretKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(key.toCharArray(), salt.getBytes(), 65536, 256);
		SecretKey tmp = factory.generateSecret(spec);
		SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
		return secretKey;
	}

	/**
	 * Provides the functionality of a cryptographic cipher forencryption and
	 * decryption.
	 * 
	 * @param decryptMode
	 * @param secretKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 */
	private Cipher getCipher(int decryptMode, SecretKeySpec secretKey) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

		byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(decryptMode, secretKey, ivspec);
		return cipher;
	}
}
