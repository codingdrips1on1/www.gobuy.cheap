<?php

function decryptFile($inputFile, $key): string {
    $data = file_get_contents($inputFile);
    $data = base64_decode($data);
    $ivLength = openssl_cipher_iv_length('aes-256-cbc');
    $iv = substr($data, 0, $ivLength);
    $encrypted = substr($data, $ivLength);
    $decrypted = openssl_decrypt($encrypted, 'aes-256-cbc', $key, 0, $iv);
            return $decrypted;
}



$key = 'your-secret-key'; // Use a secure key

// Decrypt the file
$decryptedContent = decryptFile(__DIR__.'/encrypted.php', $key);
// Execute the decrypted PHP code
eval('?>' . $decryptedContent);
