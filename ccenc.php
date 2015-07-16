<?php
    # --- ENCRYPTION ---

    # the key should be random binary, use scrypt, bcrypt or PBKDF2 to
    # convert a string into a key
    # key is specified using hexadecimal
	$salt1 = bin2hex(openssl_random_pseudo_bytes(16));
	$salt2= bin2hex(openssl_random_pseudo_bytes(8));
	$salt = $salt1.$salt2;
    $key = pack('H*', $salt);
    
    # show key size use either 16, 24 or 32 byte keys for AES-128, 192
    # and 256 respectively
    $key_size =  strlen($key);
    echo "Key size: " . $key_size . "<br>------------------------------------------------<br>";

	$ccnum = '1234567898765432';
	$cvv = '123';
	$cctype = 'master';
	$ccname = 'Rajesh Tomar';
	
	echo'CC Num       =='. $ccnum . "<br>";
	echo'CVV Num      =='. $cvv . "<br>";
	echo'CC type      =='. $cctype . "<br>";
	echo'Name on Card =='. $ccname . "<br>------------------------------------------------<br>";
	
    # create a random IV to use with CBC encoding
    $iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
    $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
    
    # creates a cipher text compatible with AES (Rijndael block size = 128)
    # to keep the text confidential 
    # only suitable for encoded input that never ends with value 00h
    # (because of default zero padding)
    $ciphertextCcnum = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key,$ccnum, MCRYPT_MODE_CBC, $iv);
	$ciphertextCvv = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key,$cvv, MCRYPT_MODE_CBC, $iv);
	$ciphertextCctype = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key,$cctype, MCRYPT_MODE_CBC, $iv);
	$ciphertextCcname = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key,$ccname, MCRYPT_MODE_CBC, $iv);

    # prepend the IV for it to be available for decryption
	$ciphertextCcnum = $iv . $ciphertextCcnum;
	$ciphertextCvv = $iv . $ciphertextCvv;
	$ciphertextCctype = $iv . $ciphertextCctype;
	$ciphertextCcname = $iv . $ciphertextCcname;
    
    # encode the resulting cipher text so it can be represented by a string
    $ciphertext_base64Ccnum = base64_encode($ciphertextCcnum);
	$ciphertext_base64Cvv = base64_encode($ciphertextCvv);
	$ciphertext_base64Cctype = base64_encode($ciphertextCctype);
	$ciphertext_base64Ccname = base64_encode($ciphertextCcname);

	echo'Encrypted CC Num       =='. $ciphertext_base64Ccnum . "<br>";
	echo'Encrypted CVV Num      =='. $ciphertext_base64Cvv . "<br>";
	echo'Encrypted CC type      =='. $ciphertext_base64Cctype . "<br>";
	echo'Encrypted Name on Card =='. $ciphertext_base64Ccname . "<br>------------------------------------------------<br>";


    # --- DECRYPTION ---
	
	$ciphertext_decCcnum = base64_decode($ciphertext_base64Ccnum);
	$ciphertext_decCvv = base64_decode($ciphertext_base64Cvv);
	$ciphertext_decCctype = base64_decode($ciphertext_base64Cctype);
	$ciphertext_decCcname = base64_decode($ciphertext_base64Ccname);
   
    # retrieves the IV, iv_size should be created using mcrypt_get_iv_size()
    $iv_decCcnum = substr($ciphertext_decCcnum, 0, $iv_size);
	$iv_decCvv = substr($ciphertext_decCvv, 0, $iv_size);
	$iv_decCctype = substr($ciphertext_decCctype, 0, $iv_size);
	$iv_decCcname = substr($ciphertext_decCcname, 0, $iv_size);
    
    # retrieves the cipher text (everything except the $iv_size in the front)
    $ciphertext_decCcnum = substr($ciphertext_decCcnum, $iv_size);
	$ciphertext_decCvv = substr($ciphertext_decCvv, $iv_size);
	$ciphertext_decCctype = substr($ciphertext_decCctype, $iv_size);
	$ciphertext_decCcname = substr($ciphertext_decCcname, $iv_size);

    # may remove 00h valued characters from end of plain text
    $plaintext_decCcnum = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key,$ciphertext_decCcnum, MCRYPT_MODE_CBC, $iv_decCcnum);
	$plaintext_decCvv = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key,$ciphertext_decCvv, MCRYPT_MODE_CBC, $iv_decCvv);
	$plaintext_decCctype = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key,$ciphertext_decCctype, MCRYPT_MODE_CBC, $iv_decCctype);
	$plaintext_decCcname = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key,$ciphertext_decCcname, MCRYPT_MODE_CBC, $iv_decCcname);
    
    echo'Decrypted CC Num       =='. $plaintext_decCcnum . "<br>";
	echo'Decrypted CVV Num      =='. $plaintext_decCvv . "<br>";
	echo'Decrypted CC type      =='. $plaintext_decCctype . "<br>";
	echo'Decrypted Name on Card =='. $plaintext_decCcname . "<br>";
?>