import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public interface AES {

	/**
	 * Encrypt the givent String
	 * 
	 * @param strToDecrypt
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeySpecException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 */
	String encrypt(String strToDecrypt, String key) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException,
			IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException;

	/**
	 * Decrypt the givent String
	 * 
	 * @param strToEncrypt
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeySpecException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	String decrypt(String strToEncrypt, String key)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException;

}
