import static org.junit.jupiter.api.Assertions.fail;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AESServiceTest {

	private AESService underTest;

	@BeforeEach
	void setUp() throws Exception {

		underTest = new AESServiceImpl();
	}

	@Test
	void testDecrypt() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException,
			UnsupportedEncodingException {

		String expected = "This should be encrypted!";
		String key = "Shuuuuuuuuuuuuush";
		String encrypted = underTest.encrypt(expected, key);
		String actual = underTest.decrypt(encrypted, key);

		Assert.assertEquals(expected, actual);
	}

	@Test
	void testDecryptFail() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException,
			UnsupportedEncodingException {

		String expected = "This should be encrypted!";
		String key = "Shuuuuuuuuuuuuush";
		String key1 = "fsdf sfsdfdsfsdaf";
		String encrypted = underTest.encrypt(expected, key);
		String actual = underTest.decrypt(encrypted, key1);

		Assert.assertNotEquals(expected, actual);
	}

	@Ignore
	@Test
	void testEncrypt() {
		fail("Not yet implemented");
	}

}
