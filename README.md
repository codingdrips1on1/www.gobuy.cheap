## Table of Contents

- [About app](#about-app)
  - [Features](#features)
  - [Requirements](#requirements)
  - [CMS Functionality](#cms-functionality)
  - [Built-in Logging](#built-in-logging)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Cascading Encryption Stages](#cascading-encryption-stages)
- [Advanced Encryption (CMS and PKCS) Including Chain of Trust and Diffie-Hellman.](#advanced-encryption-cms-and-pkcs-including-chain-of-trust-and-diffie-hellman)
  - [To sign a file](#to-sign-a-file)
  - [Choosing Between .pem, .crt, and .key extensions for data storage](#choosing-between-pem-crt-and-key-extensions-for-data-storage)
  - [Example of File Content:](#example-of-file-content)
  - [Best Practices](#best-practices)
  - [Explanation of the `openssl.cnf` file Contents](#explanation-of-the-opensslcnf-file-contents)
    - [\[req\] Section](#req-section)
    - [Distinguished Name Section](#distinguished-name-section)
    - [Attributes Section](#attributes-section)
    - [X.509 Extensions Section](#x509-extensions-section)
    - [\[req\_distinguished\_name\] Section](#req_distinguished_name-section)
    - [\[req\_attributes\] Section](#req_attributes-section)
    - [\[v3\_req\] Section](#v3_req-section)
    - [\[alt\_names\] Section](#alt_names-section)
  - [Cascading intermediate certificate](#cascading-intermediate-certificate)
    - [output](#output)
    - [Types of Certificate Bundles](#types-of-certificate-bundles)
  - [Usage Contexts](#usage-contexts)
    - [Only Cascaded Intermediate Certificates](#only-cascaded-intermediate-certificates)
      - [Certificate Chain (Including Root CA)](#certificate-chain-including-root-ca)
    - [in Summary](#in-summary)
    - [Optionals](#optionals)
  - [To encrypt a file](#to-encrypt-a-file)
    - [1. MIME-Version: 1.0](#1-mime-version-10)
    - [2. Content-Disposition: attachment; filename="smime.p7m"](#2-content-disposition-attachment-filenamesmimep7m)
    - [3. Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"](#3-content-type-applicationpkcs7-mime-smime-typeenveloped-data-namesmimep7m)
    - [4. Content-Transfer-Encoding: base64](#4-content-transfer-encoding-base64)
    - [Putting It All Together](#putting-it-all-together)
    - [Usage in S/MIME](#usage-in-smime)
  - [Padding](#padding)
  - [Receiver](#receiver)
  - [Using PKCS7 System](#using-pkcs7-system)
  - [Alternative Certificate Generation](#alternative-certificate-generation)
  - [Use these for you convenience:](#use-these-for-you-convenience)
    - [Explanation](#explanation)
- [Diffie-Hellman](#diffie-hellman)
  - [Blade Template Code](#blade-template-code)
      - [Explanation](#explanation-1)
    - [HTML Div Element for Diffie-Hellman Key Exchange Data](#html-div-element-for-diffie-hellman-key-exchange-data)
      - [HTML Code](#html-code)
      - [Explanation](#explanation-2)
    - [Detailed Explanation](#detailed-explanation)
  - [Controller method](#controller-method)
    - [Detailed Explanation](#detailed-explanation-1)
  - [Alternatively on Diffie-Hellman's](#alternatively-on-diffie-hellmans)
  - [Symmetric Key Generation](#symmetric-key-generation)
  - [Message Authentication Codes (MACs)](#message-authentication-codes-macs)
  - [Key Derivation](#key-derivation)
  - [Forward Secrecy](#forward-secrecy)
  - [Secure Authentication](#secure-authentication)
- [Certificate Info](#certificate-info)
- [Fetching a Certificate Revocation List (CRL)](#fetching-a-certificate-revocation-list-crl)
- [Exception Handling](#exception-handling)
- [Initial Work](#initial-work)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)
- [Author](#author)
- [Books for your information.](#books-for-your-information)

Encrypt with confidence, stay secure with our APIs. Your data's shield in transit - powered by our encryption. Protecting every bit, byte, and heartbeat of your data. Trust us to keep your secrets safe on the move. We offer the encryption you can rely on, security you can trust.



# About app 

Ensuring the safety of user data during transit is crucial in today's digital age, and our encryption APIs are designed to provide robust protection. By leveraging advanced encryption standards, we ensure that your data is transformed into a secure format that can only be decrypted by authorized parties. This not only protects the data from unauthorized access but also maintains its integrity throughout the transmission process. Users can count on our APIs to provide a seamless and secure encryption experience, making their applications more resilient against data breaches and cyber threats.

Our encryption stages involve multiple layers of security to disguise data effectively. First, data is encrypted using strong algorithms, converting it into ciphertext that is unreadable without the correct decryption key. This process ensures that even if data is intercepted, it remains inaccessible to malicious actors. Additionally, our APIs support key management protocols that safeguard the encryption keys themselves, adding an extra layer of protection. By utilizing our comprehensive encryption stages, users can rest assured that their sensitive information is shielded from prying eyes at every step of its journey.

We understand that the security of your applications is paramount, and our encryption APIs are designed with this in mind. From initial encryption to key management and final decryption, every stage is meticulously crafted to provide maximum security. Our solutions are continuously updated to adhere to the latest security standards and practices, ensuring that your data remains secure in an ever-evolving threat landscape. Trust in our encryption stages to keep your data safe, allowing you to focus on delivering exceptional experiences to your users without compromising on security.

## Features

- **Easy-to-use CMS**: Manage your content efficiently with our user-friendly CMS.
- **PKCS7 Encryption**: Secure your data with advanced PKCS7 signing, encrypting, decrypting, and signature-verifying capabilities.
- **Diffie-Hellman's**: Secured using DH's key-exchange mechanism.
- **Built-in Logging**: Comprehensive logging provided by Monolog.
- **Exception Handling**: Robust error management to ensure smooth operation.

## Requirements

- **PHP 7.4 or higher**: Ensure your server is running PHP version 7.4 or later.
- **OpenSSL extension enabled**: Make sure the OpenSSL extension is enabled in your PHP configuration.
- **Composer**: Dependency management is handled through Composer.



1. Ensure your PHP environment meets the [Requirements](#requirements).


## CMS Functionality

1. Access the CMS interface to manage your content easily.


## Built-in Logging

Logging is managed by Monolog. You can configure logging settings in the `config/logging.php` file:


## Installation

Use Composer to install the library:

```bash
composer require www.gobuy.cheap/data_encryption
```

## Usage

To use the CMS Signer, you need to include the Composer autoload file and start invoking class members with the instance `$gobuy`.  Class name is `GoBuyEncryption` incase you prefer a different class object name. The class constructor takes no argument.


Check if OpenSSL module is loaded.

```php

// Load the OpenSSL module
if (!extension_loaded('openssl')) {
    die('OpenSSL extension is not loaded.');
}

```
For Laravel users. You have to inject our object as parameter in your method to be able to work with the class members as shown below. Or you could simply instantiate our class:
```php
protected $gobuy;
public function index( Request $req, GoBuyEncryption $gobuy ) {

        $this->gobuy = $gobuy;

}  
```
For output dispalys and display of OpenSSL errors use the helpers below for your convinience:
```php

$gobuy->output( "Some output message", "Title of the output" ); // Display errors if string or var_dumps if an array.
$gobuy->showAnyError( ); // Displays all openssl_error_string()
$gobuy->log->warning('Foo');

// Error file is in public/log/
```
You may also decide to log your output in a different location. Then try the below solution:
```php
    $gobuy->initLogger( "ERR_NAME" )
                ->thenSetPath( $root."app/log.log" );
    $gobuy->log->info('The file has been successfully created.');
```
For Laravel users, the root path `$this->getRoot()` stops in the directory where the laravel `app` folder and `vendor` are. The App folder and the vendor are to be in the same directory for this class method to serve properly. If you dont use it, then files are expected to be in the `public` folder. To use, you can say:
```php


$root = $gobuy->getRoot( ); // You could proceed to generate your own path, if you choose not to use ours.
$gobuy->create( $folderName ); // This helper helps you create new folders only in the 'app' folder.
$gobuy->checkAndCreateFile($root."app/CMS/data.txt"); // This helper helps you create a new folder, if it does not exist, and its file. Supply full path with the file name.

$gobuy->folderExistsOrCreate( $root."/FOO" ); // Create folder if it does not exist.

```
## Cascading Encryption Stages
We cascade encryption stages to strengthen your digital footprints, and secure your digital presence. This also makes it very hard for the man-in-the-middle or any other cryptoanalyst to figure out the key with one of the methods out there. If you desire more layers of encryption on the already existing encryption (which we recommend) then simply call the method `harden(...)`.
```php
      $hardened = $gobuy->harden( $data, $strongKey );
```
On the receiving side  call the method `ease()` to return back to working with `$encryptedData`. You can also use this to disguise passwords when signin up your users (very handy).
```php
    @inject('gobuy', 'App\Services\GoBuy')
  //Blade
    @php
      $encryptedData = $gobuy->ease( $hardened, $strongKey );
    @endphp
```
After hashing a password, simply call this method to help disfigure the password more, making it harder for any cryptoanalyst who may be on your output. This is symetrical - meaning that both you and the client need the same key.
```php
  $damagedPassword = $gobuy->damageThis( $password, $key );
```
Call the below method to reverse this. This is symetrical - meaning that both you and the client need the same key.
```php
  $gobuy->restore( $damagedPassword, $key );
```
Call the veil on your passwords, messages, or data, in general, for a much stronger disguise. 
```php
    $veiled = $gobuy->veil( "abcdefghijklmnopqrstuvwxyz0123456789", $key );
```
Call the below method to undo the above. This is symetrical - meaning that both you and the client need the same key.
```php
    $originalData = $gobuy->unveil( $veiled, $key );
```
Call `cipher` to have your data encrypted. Our output is quite robust since we have employed more advanced padding, and we give you the chance to select how many stages of encryption you want by adjusting the argument `$itrCount`. The higher this value, the stronger the encryption and harder for analysts to detect. Be careful of overhead as you increase the number count. `12` is the recommended value; unless you are certain your CPU or server can handle a higher value. We understand the threats out there; which were brought to careful consideration as these encryption blocks were built. Your input is efficiently disguised for transit, in order to ensure safe delivery to the receiving side. If you do not supply `$itrCount`, `$key` and `$padding` arguments, then we will internally. Ours are firm and recommended, unless you have a particular standard you plan to use.
```php

    $cipher = $gobuy->cipher( "Hello, world!!!!", $strongKey, $itrCount, $padding ); // The last two arguments are optional

```
On the receiving side just easily call the method `decipher()` to return back to working with `$encrypted`data.
```php
  //Blade
    @php
      $deciphered = $gobuy->decipher( $cipher, $strongKey, $padding ); // The last two are still optional.
    @endphp

```
Use the below to return an array list of all the available encryption methods in OpenSSL. 
```php
  //Blade
    @php
       $gobuy->getEncMethods(  );
    @endphp

```

Before we go into the advanced stuff, remember this method, which helps you quickly generate a pair of private and public keys in PEM format. The method returns an array of the keys. The first item is the private key, while the second is the public key.
```php
   list( $privateKey, $publicKey ) = $gobuy->genKeyPair();
```


# Advanced Encryption (CMS and PKCS) Including Chain of Trust and Diffie-Hellman.


## To sign a file
You are to set the necessary paths to the files you wish to work with before signing, encrypting, decrypting, and verifying.
```php

/**
 *  The input and output files could be ".cms" or ".p7m".
 *  Do not use "file://" just "./folder/file.txt" for example.
 */


// Set the input filename for the data to be signed
$gobuy->setInputFilename($root."app/path/to/the/original/message/data.txt"); // This is the human-readable message you wish to encrypt.

// Set the path to the sender's certificate
$gobuy->setSenderCertPath($root."app/path/to/sender/certificate.pem");

// Set the path to the sender's private key with password. Default pass is "12345", in case you don't specify password.
$gobuy->setSenderPrivateKey($root."app/path/to/sender/private_key.pem", "12345");

// Or
// Set the password for the sender's private key, then call "setSenderPrivateKey" with only first argument.
$gobuy->setPrivateKeyPassword("12345");

// Optional: Set email headers for the S/MIME message
// Below are optional
$gobuy->setCMSEncoding( OPENSSL_ENCODING_SMIME ); 
$gobuy->setCMSCipherAlgo( OPENSSL_CIPHER_AES_128_CBC );

$gobuy->setHeader([
    "From" => "sender@example.com",
    "To" => "recipient@example.com",
    "Subject" => "Signed Data"
]);


```

## Choosing Between .pem, .crt, and .key extensions for data storage
- **PEM**: If you need a flexible format that can handle different types of cryptographic data (certificates, private keys, public keys), `.pem` is often the best choice. It is commonly used in various applications because it can store different types of data.
- **CRT**: Use `.crt` when you specifically need to store a public certificate. This format is clear and unambiguous for distributing public certificates.
- **KEY**: Use `.key` when you need to store private keys separately from other data types. This helps in maintaining security and clarity, as the file is specifically understood to contain only private keys.

## Example of File Content:
- **.pem**:
  ```plaintext
  -----BEGIN CERTIFICATE-----
  MIIC+zCCAeOgAwIBAgIJAL3QkuepS6UnMA0GCSqGSIb3DQEBCwUAMIGVMQswCQYD
  ...
  -----END CERTIFICATE-----
  ```

- **.crt**:
  ```plaintext
  -----BEGIN CERTIFICATE-----
  MIIC+zCCAeOgAwIBAgIJAL3QkuepS6UnMA0GCSqGSIb3DQEBCwUAMIGVMQswCQYD
  ...
  -----END CERTIFICATE-----
  ```

- **.key**:
  ```plaintext
  -----BEGIN RSA PRIVATE KEY-----
  MIIEpAIBAAKCAQEA1zC3qv2upZ5F+3OofOw8uAL5Do2RWPMJv/mh2u83hRxgpT7W
  ...
  -----END RSA PRIVATE KEY-----
  ```

## Best Practices
- Use `.pem` files for flexibility when you need to handle multiple types of cryptographic data.
- Use `.crt` files for clarity when distributing public certificates.
- Use `.key` files to securely store and manage private keys separately.

In case you are new to this and don't know how to get a key and self-signed certificate for both the sender and receiver, follow the below to quickly acquire them:
```php
$out = $gobuy->createPrivateKey( sprintf( "%sapp/Output/private_key.pem", $root ) );
```
Generates a private RSA key in PEM format and saves it to your `.pem` file. Returns the contents of the certificate.
```php
$out = $gobuy->createPublicKey( sprintf( "%sapp/Output/private_key.pem", $root ), 
                sprintf( "%sapp/Output/public_key.pem", $root ) );
```
```php

```
Extracts the public key from the private key and saves it to your specified file.
```php
$out = $gobuy->createCSR( sprintf( "%spath/to//private_key.pem", $root ), 
                sprintf( "%sapp/Output/crs.pem", $root ), 
                sprintf( "%spath/to/openssl.cnf", $root ) );
```
Where `openssl.cnf` should look something like below: 

```php
[ req ]
default_bits       = 2048
default_md         = sha256
default_keyfile    = private.pem
prompt             = no
encrypt_key        = no

# distinguished_name section
distinguished_name = req_distinguished_name

# attributes section
attributes = req_attributes

# x509 extensions section
x509_extensions = v3_req

[ req_distinguished_name ]
countryName            = DE
stateOrProvinceName    = Hessen
localityName           = Frankfurt
organizationName       = GoBuy
organizationalUnitName = Tech Team
commonName             = www.gobuy.cheap
emailAddress           = info@gobuy.cheap

[ req_attributes ]
challengePassword              = A3D3GHP
unstructuredName               = My Unstructured Name

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = example.com
DNS.2 = www.example.com

```
## Explanation of the `openssl.cnf` file Contents
### [req] Section

```ini
[ req ]
```
This section defines the settings for the OpenSSL "req" command, which is used to create certificate requests (CSRs).

```ini
default_bits       = 2048
```
This sets the default key size for the RSA key to 2048 bits. This is a good balance between security and performance.

```ini
default_md         = sha256
```
This sets the default message digest algorithm to SHA-256. SHA-256 is widely used and provides a good level of security.

```ini
default_keyfile    = private.pem
```
This specifies the default file name for the private key if one is not provided explicitly. In this case, the key will be named `private.pem`.

```ini
prompt             = no
```
This option tells OpenSSL not to prompt the user for the distinguished name fields. Instead, it will use the values specified in the configuration file.

```ini
encrypt_key        = no
```
This option specifies whether the private key should be encrypted. `no` means the private key will not be encrypted. Change to `yes` if you want to encrypt the private key.

### Distinguished Name Section

```ini
distinguished_name = req_distinguished_name
```
This specifies the section in the configuration file that contains the distinguished name fields. It refers to the `[req_distinguished_name]` section.

### Attributes Section

```ini
attributes = req_attributes
```
This specifies the section in the configuration file that contains optional attributes. It refers to the `[req_attributes]` section.

### X.509 Extensions Section

```ini
x509_extensions = v3_req
```
This specifies the section in the configuration file that contains X.509 v3 extensions. It refers to the `[v3_req]` section.

### [req_distinguished_name] Section

```ini
[ req_distinguished_name ]
```
This section defines the fields for the distinguished name (DN) that will be included in the certificate request.

```ini
countryName            = DE
```
The country code, which is a two-letter ISO country code. For example, `DE` for the United States.

```ini
stateOrProvinceName    = Hessen
```
The full name of the state or province.

```ini
localityName           = Frankfurt
```
The name of the city or locality.

```ini
organizationName       = GoBuy
```
The legal name of the organization.

```ini
organizationalUnitName = Tech Team
```
The name of the organizational unit or department within the organization.

```ini
commonName             = www.gobuy.cheap
```
The common name (CN), typically the fully qualified domain name (FQDN) of the server or user.

```ini
emailAddress           = info@gobuy.cheap
```
The email address associated with the certificate request.

### [req_attributes] Section

```ini
[ req_attributes ]
```
This section defines optional attributes that can be included in the certificate request.

```ini
challengePassword              = A3D3GHP
```
An optional challenge password that can be used to authenticate certificate revocation requests.

```ini
unstructuredName               = My Unstructured Name
```
An optional unstructured name that can be used for additional information.

### [v3_req] Section

```ini
[ v3_req ]
```
This section defines the X.509 v3 extensions that can be included in the certificate request.

```ini
subjectAltName = @alt_names
```
This specifies that the subject alternative names (SANs) should be included in the certificate. It refers to the `[alt_names]` section.

### [alt_names] Section

```ini
[ alt_names ]
```
This section defines the subject alternative names (SANs) that can be included in the certificate.

```ini
DNS.1 = example.com
```
This specifies the first SAN, which is a DNS name. Here, it is set to `example.com`.

```ini
DNS.2 = www.example.com
```
This specifies the second SAN, which is a DNS name. Here, it is set to `www.example.com`.

The `openssl.cnf` file is used to configure various aspects of creating a certificate request. The `[req]` section sets general options for the request, such as key size, message digest, and file names. The `[req_distinguished_name]` section specifies the fields for the distinguished name, while the `[req_attributes]` section allows for optional attributes. The `[v3_req]` section is used to include X.509 v3 extensions, such as subject alternative names, which are defined in the `[alt_names]` section. This configuration ensures that the CSR contains all the necessary information in a standardized format.

```php
$out = $gobuy->generateSelfSignedCert( sprintf( "%sapp/Output/private_key.pem", $root ), 
            sprintf( "%sapp/Output/root_cert.pem", $root ), 
                sprintf( "%sapp/Output/openssl.cnf", $root ), $days );
```
Generate self-signed certificate with the above API.

We are securing you with chain of trust. So we generate an intermediate certificate for the `$untrusted_certificates_filename`. This is typically done to provide additional layer of security and also more certificates that will be needed to complete the verification stage.
```php
list( $caCert, $caKey, $csr ) = $gobuy->generateCACertAndPrivateKey( $certOutPath,  $keyOutPath,  $csrOutPath); // Self-signed CA certificate needed to sign the intermediates.
```
You may find this CA certificat in a `CA` folder in your outer structure.
```php
$dn= array( [
                'countryName' => 'AU',
                'stateOrProvinceName' => 'State',
                'localityName' => 'City',
                'organizationName' => 'Organization',
                'organizationalUnitName' => 'Organizational Unit',
                'commonName' => 'intermediateCA',
                'emailAddress' => 'email@example.com'
            ], [ 
                'countryName' => 'US',
                'stateOrProvinceName' => 'State',
                //...
            ], 
            [ 
                'countryName' => 'DE',
                'stateOrProvinceName' => 'State',
                //...
            ]
        );
$bundleArr = $gobuy->generateIntermediates( $caCert, $caKey, $dn,  3 );
```
The forth argument is the iteration count - the number of intermediate certificates that will be generate.
 As you increase, you monitor power consumpption and CPU performance. Also monitor memory usage. The length of `$dn` array must match the iteration count or an error is thrown.
```php
$intermediatCert = $gobuy->getInterCert( $bundleArr );
$intermediatePrivateKey = $gobuy->getInterKey( $bundleArr );
```
With the above two methods, you get the last intermediate certificate in the bundle and its respective key. These are necessary for signing/creating the end-entity (sender) certificate
```php
// Now the end entity's certificate can be created. End entity is also the sender. The sender needs to submit a Certificate Signing Request (CSR) for a certificate to be issued to them.
$days = 365; // How long the certificate will be valid. You can increase this further
$serial = rand(); // The serial number of issued certificate. If not specified it will default to 0. 
$gobuy->endEntityCertPath = $gobuy->root."app/endEntityCert.pem"; // endEntity is same as sender
list( $endEntityCert, $endEntityCertPath ) = $gobuy->signEndEntityCert( "path/to/stored/end_entity/csr.pem", 
                                $intermediatCert, $intermediatePrivateKey, 
                                  $days, $serial );

```
For end entity's CSR, you may use the sender's CSR from the prompt above. The sender certificate will look something like below. This is a PEM format.
```vbnet
-----BEGIN CERTIFICATE-----
MIID1DCCArygAwIBAgIEBiKpijANBgkqhkiG9w0BAQsFADCBnDELMAkGA1UEBhMC
VVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5MRUwEwYDVQQKDAxPcmdh
bml6YXRpb24xHDAaBgNVBAsME09yZ2FuaXphdGlvbmFsIFVuaXQxFzAVBgNVBAMM
DmludGVybWVkaWF0ZUNBMSAwHgYJKoZIhvcNAQkBFhFlbWFpbEBleGFtcGxlLmNv
bTAeFw0yNDA3MTMxNjAxNDlaFw0yNTA3MTMxNjAxNDlaMGYxCzAJBgNVBAYTAkRF
MQwwCgYDVQQIDANFRkYxDDAKBgNVBAcMA1NTUzEMMAoGA1UECgwDQUFBMQswCQYD
VQQLDAJERDEMMAoGA1UEAwwDRkZGMRIwEAYJKoZIhvcNAQkBFgNXRUUwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjqU1MMUFRmjmey3lFJQJd0sxUnw/4
U7aWH59v1nNzpPk7AE6nGHfWbBNHfYHSXoU2gkRnu8mjSW3qsslx3fj6J16K0bRO
+tnTiR57d5/XQx1wvKi2vnB3w9uoMKa8sE9qaPddhwYBet0ieJx8QaQDqQLFltK8
Q9G4jnRWTJtCa6YYM8oCIdGgiKNrwn8BdRT5Y8EC5yiQN6FGOQ/zdPMlAbMPLvfZ
rHrysmRVuz/hnJS5dgtA4X9bzQaPWf+FYaknqojVqwY/1u4Im2wSGI4Ltuc4vfCC
VaEaD8aqqaYEB9Mj7AOvcvj6P+NRSevS73wxee1WowvYUekCp8xm3Ac5AgMBAAGj
UzBRMB0GA1UdDgQWBBS6aL9bxdLvvp82/mYC1ggLBTjJwTAfBgNVHSMEGDAWgBTv
mEZ9gJEk5WsC7yeF52vOpG4MeTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEB
CwUAA4IBAQA+Lezlhy6Iy0mVWjaAy5AUX5CKalkAl15gb5hNJw86gy9VyJ0a0pvK
zIOuJ+vMW42AJRs0tquj/2sFTqZYi9LRe1lrUBTPq/N7YlpzQnS+gX7ATnvgq9+X
dO6fa4PTO9vtDlX584rUYNhT5hi+6Djv9y9TWGwSGAraWQJyM4icvUYNvzLhO4AP
z4kSV5dC7qVxASP2jFYTnJUIbRnb8C0GMjJochdUy6MHEzdvQCq5Ch4oDF/ym9rM
d9GlPEDYVFRe0vuBfbffVQjvwc5JsdtPknmwSL4H2zUK7FzbZRK+OkfvFLgNO1mb
kfNwUfGUxzkIpYd2s4k8NbuZzrlHzPFe
-----END CERTIFICATE-----
```

## Cascading intermediate certificate

```php
$gobuy->cascadeUntrustedCertificate( $bundleArr[0], "path/to/store/concatenated_cert.pem" );

```
### output
The output will look like so:
```vbnet
-----BEGIN CERTIFICATE-----
MIIDwzCCAqugAwIBAgIEKy4j1jANBgkqhkiG9w0BAQsFADBVMQ4wDAYDVQQDDAVN
eSBDQTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDA2MjIwOTMyNTFaFw0yNTA2
MjIwOTMyNTFaMIGcMQswCQYDVQQGEwJVUzEOMAwGA1UECAwFU3RhdGUxDTALBgNV
BAcMBENpdHkxFTATBgNVBAoMDE9yZ2FuaXphdGlvbjEcMBoGA1UECwwTT3JnYW5p
emF0aW9uYWwgVW5pdDEXMBUGA1UEAwwOaW50ZXJtZWRpYXRlQ0ExIDAeBgkqhkiG
9w0BCQEWEWVtYWlsQGV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAxjZkwvojmHy0248+BqPCrKYt7BbsKAQ9NcdUh0vjvDST8sjIC0Hp
z3xpMUa8j4M3akeiUyGzO/vVapNQWEhll5yMgf5YcKsaDLE6Ia8syBud+QwY4QKA
H/cDtfU+No2ciBaO9mmLQb93SnVJC6ugSf69psrSruxqp9aZXBZiUHRqy1I7+zVZ
DiKdeb30GFg44KN8sJojvgq8Rsp3htxfq+uv7NStQqux8G+YGzB8GKhwuzlLkxPc
GfKNL9w7imftCpo4o8+y31Y6O7BzFPPb/BRe/UqJJ0xTFRhzZMdh8OFEFzAuLEP7
2XAgOj09utbcpD8Zgc0uTJK9cGv5nQ5KrwIDAQABo1MwUTAdBgNVHQ4EFgQUBb5J
Mf4guZY/t5i8VG2xW8o9VxAwHwYDVR0jBBgwFoAU0+jIdL2nZDtnftLwZIFxDzh5
JhgwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEARYCKOoLf8hB2
tld+puoUlmVRplZztD1G+SKovg32TnfFqaUXzLu5LD+fq9ttDzs1QDkpQminUi1r
GACjZ86Z5QIf1t+hI9XHqpfkWyO69kW7Ue7DANGssDITV5YmZnErMP9/s3GwKcZZ
V4iJot3cyAaMxKFT/sIx6OOG6gdPLGOOOZsYQ317yaML/d/rPOKo4Zg6V7Yh9zl+
bVHuK/m+SFbXNFQUrzj/hi/vqSoykBJbdesIh+0Qs2FEhyN81touNLQPQq2FKZhr
+3amghXhlplXonmQ+FMepLBglBJbvfeRMVAhYeE/zHr3p/QRl5rblWdqRmxTfWa+
qjfiLf+t8Q==
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIDwzCCAqugAwIBAgIEDMKr+DANBgkqhkiG9w0BAQsFADBVMQ4wDAYDVQQDDAVN
eSBDQTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDA2MjIwOTMyNTFaFw0yNTA2
MjIwOTMyNTFaMIGcMQswCQYDVQQGEwJVUzEOMAwGA1UECAwFU3RhdGUxDTALBgNV
BAcMBENpdHkxFTATBgNVBAoMDE9yZ2FuaXphdGlvbjEcMBoGA1UECwwTT3JnYW5p
emF0aW9uYWwgVW5pdDEXMBUGA1UEAwwOaW50ZXJtZWRpYXRlQ0ExIDAeBgkqhkiG
9w0BCQEWEWVtYWlsQGV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEApvbaqixp819WRemwd8Jtth+Vz5SF68x0z65TX9ObOmz2GaNzzh0O
F4BvrbiRfMMzOlynIySNg/PyqH+BGO5PGuxrOeGDz4F1Y9s75OUczXwQULmOcm7G
qPp0ZktghLZAiKhUXx6VnyAF9Paic8Jy8715Xt3/gSDzSjEa2hZJNn9i49HtSCf3
aWLPTgtIMPCDvyfvRWHau5GcEoBo+EybR5a6Fos8prBJ1c7i93dxwTcxFiILa5bm
BxpyU1LsN3VfGzoZ/4GvhQs+aEVyg8tqk45FQQXNGa1mDSX7eG72KHEUacr9EeAn
myMkiGvtGtWABNJRf326QpzMlvhH0+QB0wIDAQABo1MwUTAdBgNVHQ4EFgQUZ3vM
U2ujf6V1UWAL0JZicNsy4NowHwYDVR0jBBgwFoAURKgsE5iWXR2+apEW43Cl2X1j
GUYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAidpyQ0yjcOoi
i7oY7hi/wR1X5XKe1eSE+LAZyG+9ecX6eb5aeguc5PNncyuonDxJmqlPPV4cUKPE
mj00f65VcUP6oNyM5e/TP85U8N+jSd2/zumf9nQD32OnUghNLwFGYOTazKZUjTY4
PyC70/HjDs4zev0EiOrsxPo4HKUL1xnTtJHuQWlKJDjq8df4UE9F8XL2NcC1SSAv
7DaKeKbc5Zxm94Zo2TJTtXflXJYdMuNleubsEYo6Dje4HmMOBeWPwUt167QTrVhm
qtMPmxB52AiY5HvMNgnUu62K6lVKzgRDy1nH8PMwfPlaUz2IL8xJlWWN7AuYcCXo
wQKtbTtCfA==
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIDwzCCAqugAwIBAgIEDhE6GTANBgkqhkiG9w0BAQsFADBVMQ4wDAYDVQQDDAVN
eSBDQTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDA2MjIwOTMyNTJaFw0yNTA2
MjIwOTMyNTJaMIGcMQswCQYDVQQGEwJVUzEOMAwGA1UECAwFU3RhdGUxDTALBgNV
BAcMBENpdHkxFTATBgNVBAoMDE9yZ2FuaXphdGlvbjEcMBoGA1UECwwTT3JnYW5p
emF0aW9uYWwgVW5pdDEXMBUGA1UEAwwOaW50ZXJtZWRpYXRlQ0ExIDAeBgkqhkiG
9w0BCQEWEWVtYWlsQGV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAr4ZLkUn25bRoyh4pOyfEWJI34hfa4oMEJAyLkdljekEURMN5wk12
KH3nckqaoXl51s3jaExvrqkkfOydg7P6tP5xiaQI96j9G+8KsFVcn6WcHIghIQbs
RyjVieZpZWscKVrYWIxMQnfX0pIlTAWzS/S24qv19g1zBgzuGpsUMQUgcLe9Qepu
+YLHHAUpWfpaKztrNuBST3tNXnWQO2Kcj5zwAwFYP4GPg5ka7dv9BPT5gT0YVc51
iPpspXwisE3Zy2S3IpvH3q4AZWQPb1/Oh7jKED1aceevUKysWtNRF5ic9yD1LF/M
zl1ZIngzmQpPJrjKYi8qwPi5qN2ZU/LLSQIDAQABo1MwUTAdBgNVHQ4EFgQUkn35
fx64ludckSCrrkhFma9TKRQwHwYDVR0jBBgwFoAUu9zlf1GvYr906Fu0/JfyfIel
8XAwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAgWL0FeW85J/D
190YTX1ZjFV2T2YRhy9Q3cdbqJllgL4ejjP5ihQvp/+1yGDS+mJ4iPXa435VmQAM
r+drL5vn8f+1b9dnMKL56ReE/uVkPIw6uI5+L+6IxwAb2tROH4ZFFO9L57nCXAXe
2F5MVWMJLBkhETk8Y/HsSZ1dREn/ukBUhrt8NMYXUeWLw7+URW3hK2jI8lN0hKx+
rN+T6ZesidS+XsUDIO2OLdHrYyu7amm5j/vzQxvmceHShZVTC25xPKBaNyviBUzZ
6XoyZMQ9MlCUmMDls8ev1ec0OHKLBDc+LN5/CvgDuW3DS1ffpUf9zoC4qZbHkroG
qP2eCOA24g==
-----END CERTIFICATE-----


```
The above stage is necessary to bundle all the intermediate certificates you have generated. This bundling plays a great roll during signature verification. The client wants as much information as possible, if trust will be estalished. 
```php
// set $untrusted_certificates_filename. This is needed to verify the sender's signature.
$gobuy->setUntrustedCertificatesFilename( "path/to/concatenated_cert.pem" );

```
```php
$gobuy->createCertChain(sprintf( "%sapp/CMS/concatenated_cert.pem", $root ), 
        sprintf( "%sCA/ca.crt", $root ),
                        sprintf( "%sapp/Output/chain.pem", $root ) );
```
Remember: in the context of OpenSSL and certificates, the term "bundle" can refer to different types of certificate collections depending on the specific context and use case. Here's a detailed explanation:

### Types of Certificate Bundles

1. **Cascaded Intermediate Certificates**
   - This refers to a collection of intermediate certificates (`concatenated_cert.pem`) that form a bundle from the first-signed intermediate certificate by the root CA certificate up to the last intermediate certificate. The "leaf" certificate is not included, that is: `intermediate1.pem + intermediate2.pem + intermediate3.pem ...`. Do not include the end-entity certificate in this bundle, unless in the case of Nginx configuration where for `ssl_certificate` you may concatenate end-entity and an already existing bundle of intermediates: `cat server_certificate.crt intermediate_bundle.crt > chain.crt`.
   - It is often used in scenarios where you want to present the chain of trust without including the root CA, which is typically already trusted by the recipient.

2. **Certificate Chain**
   - This includes both the cascaded intermediate certificates and the root CA certificate.
   - This full chain is often used in scenarios where you need to ensure the complete chain of trust is presented, including the root CA, especially when the root CA might not be pre-installed or trusted by default by the recipient.

## Usage Contexts

### Only Cascaded Intermediate Certificates

1. **Web Servers (e.g., Apache, Nginx)**
   - When configuring a web server, you usually provide the server (end-entity) certificate along with the intermediate certificates in a bundle. The root CA is not included because browsers and operating systems already have a store of trusted root CA certificates.
   - Example:
     ```apache
     SSLCertificateFile /path/to/your_server_certificate.crt
     SSLCertificateChainFile /path/to/your_intermediate_certificates_bundle.crt
     ```

2. **Client Certificate Authentication**
   - In some client authentication setups, only the intermediate certificates are needed to verify the client's certificate, assuming the root CA is already trusted by the server.

#### Certificate Chain (Including Root CA)

1. **Email (S/MIME)**
   - When sending an S/MIME signed email, including the full chain (intermediates + root) ensures the recipient's email client can validate the entire chain of trust, especially if the root CA is not already trusted.

2. **Mobile Devices and Embedded Systems**
   - These devices may not have a comprehensive set of trusted root certificates installed. Including the full chain ensures the certificate can be validated without relying on the device's existing trust store.

3. **Certificate Installation on Some Systems**
   - Some systems, especially older or less common ones, may require the full chain, including the root CA, to be presented during installation or validation processes.


### in Summary

- **Cascaded Intermediate Certificates**: Used when the root CA is assumed to be already trusted, such as in web server configurations.
- **Certificate Chain (Including Root CA)**: Used when the full chain of trust needs to be presented, such as in email communications, mobile devices, and some specific systems where the root CA might not be pre-installed or trusted by default.

By understanding these distinctions and usage contexts, you can ensure proper handling and presentation of certificate bundles in your applications and systems.

### Optionals
Below are optional. You may set them before signing your data:
```php
$gobuy->setCMSFlag( OPENSSL_CMS_BINARY );
$gobuy->setCMSEncoding( OPENSSL_ENCODING_SMIME );
$gobuy->setHeader([
    "From" => "sender@example.com",
    "To" => "recipient@example.com",
    "Subject" => "Signed Data"
]);

```

## To encrypt a file

```php

// Set the output filename where the CMS signed data will be saved
$gobuy->setCMSOutputFilename($root."app/path/to/store/signed_data.cms");

// Here you must have invoked the setters like above
if ( $gobuy->cmsSign( $endEntityCert ) ) {
// This scope means a digital signature was established successfully.
$data = $gobuy->getCMSSigned(); // Get signed certificate data;

// Preparing for encryption
// Set the output filename where the CMS. encrypted data will be saved
$gobuy->setCMSEncryptedOutput( $root."app/path/to/encrypted_data.cms" );
// Set the path to recipient's certificate.
$gobuy->setRecipientCertPath( $root."app/path/to/recievers/certificate.pem" );

// Optional 
$gobuy->setCMSCipherAlgo( OPENSSL_CIPHER_AES_128_CBC );

// Encrypt the signed data using CMS. 
if ($gobuy->cmsEncrypt($root."path/to/signed_data.cms") ) {

$gobuy->output( $gobuy->getCMSEncrypted(), "Original" );

} 

} else {
throw new \Exception( "Signing failed: " . openssl_error_string() );
}


```
Signed data will look something like below. This signature can still be detached from the main message to have the staying separately.
```vbnet
MIME-Version: 1.0
Content-Disposition: attachment; filename="smime.p7m"
Content-Type: application/pkcs7-mime; smime-type=signed-data; name="smime.p7m"
Content-Transfer-Encoding: base64

MIISsQYJKoZIhvcNAQcCoIISojCCEp4CAQExDTALBglghkgBZQMEAgEwDwYJKoZI
hvcNAQcBoAIEAKCCD70wggPDMIICq6ADAgECAgR5nsLKMA0GCSqGSIb3DQEBCwUA
MFUxDjAMBgNVBAMMBU15IENBMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1T
dGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMB4XDTI0MDcx
MzE2NTExMVoXDTI1MDcxMzE2NTExMVowgZwxCzAJBgNVBAYTAlVTMQ4wDAYDVQQI
DAVTdGF0ZTENMAsGA1UEBwwEQ2l0eTEVMBMGA1UECgwMT3JnYW5pemF0aW9uMRww
GgYDVQQLDBNPcmdhbml6YXRpb25hbCBVbml0MRcwFQYDVQQDDA5pbnRlcm1lZGlh
dGVDQTEgMB4GCSqGSIb3DQEJARYRZW1haWxAZXhhbXBsZS5jb20wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2a8s1ckl1dt5lygY50fMYQMArwpWsjdxv
RAbq1JtoHTo9Elc9Bcf4RpSmna3UFlYY8DmQHVPiL6h0OZ9QkxoFQMdJDes/O3rW
kPvrZNJWrF/JGCAeukHUXJ6duWkMnmfXW+4fsnO4Z4tscbug6++B5CSzVi9I+/QD
knCEt/JTTLPEUtd+nMtYBUStHcEgDxMhajvbAvy364TrD6l4uZ3lEuE8iIeQYMeq
rYJJEwgb/DLNktiz1MrG/JP+6REDV+UOib7dRimaiFqNBiUNJQnyaQInTNPQ2nH+

....
```
The header is used to define how the message should be processed, interpreted, and handled by email clients and other software that can read S/MIME (Secure/Multipurpose Internet Mail Extensions) messages.

### 1. MIME-Version: 1.0
- **Purpose**: This indicates that the message is formatted according to the MIME standard, version 1.0. MIME (Multipurpose Internet Mail Extensions) is a standard that allows for the inclusion of various content types, such as text, images, and other media types, in email.

### 2. Content-Disposition: attachment; filename="smime.p7m"
- **Purpose**: This header suggests how the content should be presented to the user. 
  - `attachment` means that the content should be presented as a downloadable file rather than inline within the email body.
  - `filename="smime.p7m"` indicates the name of the file attachment, which is commonly used for S/MIME encrypted messages.

### 3. Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"
- **Purpose**: This header specifies the MIME type of the content.
  - `application/pkcs7-mime` indicates that the content is a PKCS #7 MIME, which is used for S/MIME messages.
  - `smime-type=enveloped-data` specifies that the message is encrypted (enveloped data) as opposed to being signed or containing other S/MIME data types.
  - `name="smime.p7m"` is another way to indicate the filename associated with this MIME part.

### 4. Content-Transfer-Encoding: base64
- **Purpose**: This header specifies the encoding used to safely transmit the binary content over protocols that are designed to handle text, such as SMTP (Simple Mail Transfer Protocol) for email.
  - `base64` means that the binary content of the encrypted message has been encoded in base64, which ensures that it remains intact during transmission.

### Putting It All Together
These headers collectively ensure that:
1. The message is recognized as a MIME message by email clients.
2. The content is treated as an attachment and saved with the specified filename.
3. The email client knows that the attachment is an encrypted S/MIME message.
4. The email client decodes the base64 content back into its original binary form before processing it.

### Usage in S/MIME
S/MIME uses these headers to facilitate secure email communication by allowing messages to be encrypted, signed, or both. Encrypted messages ensure confidentiality, meaning that only the intended recipient can decrypt and read the message. When combined with signing, it also provides authentication and integrity, ensuring the message has not been tampered with and verifying the sender's identity.

In summary, these headers are crucial for ensuring the proper handling of S/MIME encrypted messages, providing clear instructions to email clients on how to process and display the message content.


## Padding
We will effortlessly pad your encrypted data. This stage is well recommended to give you more complex structure and randomness. This is to make the encrypted more resistant to brute force attack, and other attacks that exploit the simplicity of cryptographic cipher texts. 

```php
$padded = $gobuy->paddCMSEncrypted( $strongKey ); // Pad the encrypted data before sending (recommended)
```

```php

@inject('gobuy', 'App\Services\GoBuy')
// Blade 
@php
    $gobuy->unPadCMSEncrypted( $padded, $strongKey ); // unpad the padded encrypted data before the decryption stage.
@endphp
```
Where GoBuy Service class is as below:
```php
<?php

namespace App\Services;
use GoBuy\Encryption\GoBuyEncryption;
class GoBuy extends GoBuyEncryption{
   
  

}
```

It is recommended to compress the file before it takes flight. This will reduce the file size and prevent any latency due to file being too large. If you believe you are working with a small file, you may want to skip this stage of encryption. Below shows how we can effortlessly compress your file after encryption.
```php
// Begin the compression process and create a new ZIP file named "comp.zip".
$gobuy->compressData("comp.zip")
    ->thenAddFileFromString("index.txt", "echo 'Hello, world!' ") // Add a file from a string with the name "index.php" containing a simple PHP echo statement.
    ->thenAttach("comp.zip", "pic/dog.jpg")// Attach an image file "dog.jpg" from the "pic" directory to the ZIP archive.
    ->thenAttach("comp.zip", "pic/car.png") // Attach another image file "car.png" from the "pic" directory to the ZIP archive.
    ->thenAttach("comp.zip", "docs/doc.pdf") // Attach a PDF document "doc.pdf" from the "docs" directory to the ZIP archive.
    ->thenAfterCloseZip();  // Finalize the ZIP archive and close it.
```

The above is just an example. You don't have to do it first. You may now proceed as follows:
```php

// Begin the compression process and create a new ZIP file named "comp.zip".
$gobuy->compressData("encryption.zip")
    // Attach an image file "dog.jpg" from the "pic" directory to the ZIP archive.
    ->thenAttach("encryption.zip", $root."app/encrypted/encrypted_data.cms")
    // Finalize the ZIP archive and close it.
    ->thenAfterCloseZip();


```
## Receiver
This is the reciever's end, who will now decrypt the file.
```php

// Continuation from above. Ensure to have called all relevant setters here.



$gobuy->setRecipientPrivateKey( $root."app/CMS/private_key.pem", "12345" ); // Password-protected

// Set the output filename where the decrypted data will be saved
$gobuy->setDecryptedData($root."app/path/to/decrypted_data.cms");

// Decrypt the CMS encrypted data
$gobuy->cmsDecrypt($root."app/path/to/encrypted_data.cms");
$gobuy->getDecryptedDataRaw(); // Get the decrypted data.


```
For Laravel users, the client side may look something like below. Now remember that in some cases, it is the client who is the sender. Where the server receives and decrypts, authenticates the user and so on.
```php

<body class="antialiased">
@inject('gobuy', 'App\Services\GoBuy')


@php
        

$gobuy->setRecipientCertPath( $gobuy->getRoot()."app/bob_cred/certificate.crt" );
$gobuy->setRecipientPrivateKey( $gobuy->getRoot()."app/bob_cred/private_key.key", "12345" );

$gobuy->setDecryptedData( $gobuy->getRoot()."app/data/decrypted_data.cms" );
$gobuy->cmsDecrypt($gobuy->getRoot()."app/data/encrypted_data.cms");

//echo $gobuy->getDecryptedDataRaw(); // Get the decrypted data.

// Here is where the CA certificate is added to the caInfo array.
$gobuy->caInfo = [
            'file' => $root.'path/t/hashed/b8218ee6c6064ec03d4129cf4d72f12ab3f07c3b5dccdf0f1e019ae02297bc18.0', // CA certificate file name
            'dir' => 'path/to/hashed/CA/certificate/files/' // Path to a directory containing the CA certificates specified as "file" in this array above
        ];

// set $flag = PKCS7_NOVERIFY to skip CA verification otherwise set it to 0. Integer value.
if ($gobuy->cmsVerify ( $gobuy->getDecryptedData(), 
                    $gobuy->getRoot()."app/where/to/store/cms_content_data.pem", // Where the original message will be stored after it is detached from the signature.
                    $gobuy->getRoot()."app/where/to/store/cms_signature_data.pem", $flag ) ) // Where the signature is stored after it is ditached from the original message.
{
    $gobuy->output( "CMS VERIfied", "Verified!!" );
} else {
    $gobuy->output( "CMS Not VERIfied ". openssl_error_string(), "Not Verified!!" );
    $gobuy->showAnyError();
}
@endphp
    </body>

```

Remember: the directory containing CA certificates does not always need to be hashed, like in `$gobuy->caInfo` above. However, using a hashed directory structure can optimize lookup and verification processes, particularly when dealing with a large number of CA certificates. There are specific ways to hash these files, so we recommend those ways or using our `hashCa` API provided.

```php
$gobuy->hashCA( $root."path/to/CA/", $root."path/to/save/hashed/CA/" );
```
Above returns an array of your hashed CAs with their original file names as key.
```php
$gobuy->caInfo = $gobuy->prepareCAInfo( $root.'app/path/to/CA' ); // Generate array of the CA certificate and the dir name.
$gobuy->caInfo = $gobuy->prepareCAInfoFromHashed( $root.'path/to/hashed/CA' ); // Generate array of the hashed CA certificate and the dir name from the hashed directory
```
You could use our API to help prepare your caInfo with ease. Unless you have your own method. Please do not add the contents of the CA certificate directly into the `ca_info` array. It most times ends up in failure.

```php

// public function cmsVerify( string $decryptedData, string $output,
//                                 string|null $sigfile = null,
//                                 array $caInfo = [],
//                                 string|null $untrustedCertificatesFilename = null,
//                                 string|null $content = null,
//                                 string|null $pk7 = null,
//                                 int $encoding = OPENSSL_ENCODING_SMIME ): bool | int {

```

The second argument of `cmsVerify` shows the original content (the human-readable message) before signature was signed, that is after the signature is detached. The third argument is a file that holds the detached signature.

You could just push the encrypted data through Laravel's view method as below:
```php
return view('welcome', [ "encrypted" => $gobuy->getCMSEncrypted() ]);
```
```php
  //Blade
  {{ $encrypted }}
```

## Using PKCS7 System

```php

// Set the input filename for the data to be signed using PKCS7
$gobuy->setInputFilename("path/to/data.txt"); // Holds just plain text.

// Set the output filename where the PKCS7 signed data will be saved
$gobuy->setPKCS7SignedOutputFilename("./path/to/pkcs7_signed_data.cms");

// Set the path to the sender's certificate for PKCS7 signing
$gobuy->setSenderCertPath("path/to/sender/certificate.pem");

// Set the path to the sender's private key for PKCS7 signing
$gobuy->setSenderPrivateKeyPath("path/to/sender/private_key.pem");

// Optional: Set email headers for the S/MIME message for PKCS7
$gobuy->setHeader([
    "From" => "sender@example.com",
    "To" => "recipient@example.com",
    "Subject" => "Signed Data"
]);


// Sign the data using PKCS7
if ($gobuy->pkcs7Sign( $endEntityCert )) {
    // Set the output filename where the PKCS7 encrypted data will be saved
    $gobuy->setPKCS7EncryptedOutputFilename("./path/to/pkcs7_encrypted_data.cms");

    // Set the path to the recipient's certificate for PKCS7 encryption
    $gobuy->setRecipientCertPath("path/to/recipient/certificate.pem");

    // Generate recipient credentials for PKCS7 encryption
    // $gobuy->generateRecipientCredentials();

    // Encrypt the signed data using PKCS7
    if ($gobuy->pkcs7Encrypt()) {
        // Rest of your code
        $encrypted = $gobuy->getPKCS7EncryptedOutput(); // Get contents of encrypted outputfile.
    }
}

```
Same as above
```php
@php
// Set the output filename where the PKCS7 decrypted data will be saved
$gobuy->setPKCS7DecryptedOutputFilename("./path/to/pkcs7_decrypted_data.cms");

// Set the path to the recipient's certificate for PKCS7 decryption
$gobuy->setRecipientCertPath("path/to/recipient/certificate.pem");

// Set the path to the recipient's private key for PKCS7 decryption
$gobuy->setRecipientPrivateKey("path/to/recipient/private_key.pem");

// Decrypt the PKCS7 encrypted data
if ($gobuy->pkcs7Decrypt($gobuy->getPKCS7EncryptedOutputFilename())) {
    // Set the output filename where the PKCS7 original message will be saved
    $gobuy->setPKCS7RawDataOutput( "./path/to/data_pkcs7_content.txt" );

    // Set the path where the detached signature will be saved.
    $gobuy->setPKCS7SignatureOutput( "./path/to/data_pkcs7_signature.pem" );

    $gobuy->caInfo = [ "file" => "path/to/ca.crt", "dir" => "path/to/CA/dir" ];
    // Verify the PKCS7 decrypted data
    $gobuy->pkcs7Verify($gobuy->getPKCS7DecryptedOutputFilename());
}

@endphp
```
Notice how we re-assigned `$gobuy->caInfo`. In most cases trying to use the hashed directory may lead to errors. Specify the original CA certificate when verifying with `pkcs7Verify`.  

## Alternative Certificate Generation
In the context of the class you're working with, the methods `generateRecipientCredentials()` and `generateSenderCredentials()` can be designed to simplify the process of generating credentials. When invoked, these methods can internally create a certificate and a private key for the recipient and sender, respectively. This feature is particularly useful if you prefer not to manually create and manage certificate files and private key files on the filesystem.

Here's an example of how to invoke these methods:

```php
      ...

    list( $senderRawCert, $senderPrivateKey ) = $gobuy->generateSenderCredentials( $config, $dn, $expiresIn  );
           
    
```
In most cases, the receiver is the server that will decrypt and authenticate user data.
```php
  @php
    list( $recipientRawCert, $recipientPrivateKey ) = $gobuy->generateRecipientCredentials( $config, $dn, $expiresIn  );
  @endphp
```
```php 
 //Where 
        $config = array(
            "digest_alg" => "sha512", // Digest algorithm for the certificate signature
            "private_key_bits" => 4096, // Number of bits for the private key
            "private_key_type" => OPENSSL_KEYTYPE_RSA, // Type of private key to create
        )

        $dn = array(
            "countryName" => "AU", // Country name
            "stateOrProvinceName" => "...", // State or province name
            "localityName" => "...", // Locality name
            "organizationName" => "...", // Organization name
            "organizationalUnitName" => "...", // Organizational unit name
            "commonName" => "www.", // Common name, usually the domain name
            "emailAddress" => "..." // Email address
        ),
        $expiresIn = 365

```

When using these methods, you don't need to worry about file paths or handling certificate files directly. The method takes care of generating the necessary credentials and using them in subsequent cryptographic operations. This makes the process more streamlined and user-friendly, especially for those who may not be familiar with the details of certificate and key management.


These methods are designed to be flexible, allowing you to specify different configurations and distinguished names for the sender and recipient. The `$config` array allows you to define the cryptographic parameters for the certificate and private key generation, while the `$dn` array contains the information that will be included in the subject field of the certificate. The `$expiresIn` parameter sets the validity period of the certificate in days. These methods abstract away the complexity of generating and managing cryptographic credentials, making it easier to implement secure communication in your application.

For a quicker CMS encryption, consider the below:
```php
$encrypted = $gobuy->encryptCMS( "path/to/data.txt", "path/to/save/encrypted_data.cms", "path/to/save/user_certificate.pem" );
```
The above can be used for many types of encoded data, including certificates and keys. It's more generic and simpler in terms of structure compared to the `cmsEncrypt` (S/MIME) counterpart.

```php
$same = $gobuy->checkIfCertKeyMatch( "path/to/certificate.pem", "path/to/private_key.pem" );
```
Check that the certificate and key files correspond to the same entity. You can verify this with the above API. Returns `true` if it is a match otherwise `false`.

## Use these for you convenience:

```php
$gobuy->viewCertificate( sprintf( "%sapp/Output/root_cert.pem", $root ) );
```
The above will return something like below; 

```mathematica
Certificate: Data: Version: 3 (0x2) Serial Number: 3b:49:c4:c9:f6:b2:4b:96:7e:aa:88:ac:13:ed:09:40:10:91:f3:5a Signature Algorithm: sha256WithRSAEncryption Issuer: C=DE, ST=Hessen, L=Frankfurt, O=GoBuy, OU=Tech Team, CN=www.gobuy.cheap, emailAddress=info@gobuy.cheap Validity Not Before: Jul 16 13:39:05 2024 GMT Not After : Jul 16 13:39:05 2025 GMT Subject: C=DE, ST=Hessen, L=Frankfurt, O=GoBuy, OU=Tech Team, CN=www.gobuy.cheap, emailAddress=info@gobuy.cheap Subject Public Key Info: Public Key Algorithm: rsaEncryption Public-Key: (2048 bit) Modulus: 00:c1:a4:af:05:4b:42:0a:fd:59:32:bc:07:7e:2c: aa:5a:85:c4:c7:aa:f5:57:bf:db:40:60:db:f9:7c: 19:df:37:e0:37:5d:91:d2:f6:1a:75:f3:ed:57:07: f8:25:c9:e1:af:96:20:c0:d6:9a:e2:65:84:63:53: 9b:ca:de:7b:c1:49:7b:e2:63:9c:cb:43:8b:59:95: 4f:f2:23:2c:52:7a:84:d2:cf:e8:67:4c:4a:76:25: 2c:16:79:47:30:18:11:68:e1:6a:b5:2e:49:35:33: f1:f5:24:0c:36:d2:ae:5e:9f:e1:d8:81:0b:7a:61: 26:f6:46:66:84:85:19:f7:cf:8f:3d:30:3f:86:64: a1:9f:46:e0:6f:db:50:90:13:7b:d5:d5:7d:0a:28: 38:97:29:08:20:95:00:38:54:b4:08:c1:62:1a:bf: 28:8a:b9:3a:fe:b9:97:e9:ae:3b:f2:1d:89:fc:6a: 50:93:9b:1a:7e:07:5d:31:a8:bf:af:8c:28:a2:ce: 0e:6d:97:61:e5:42:13:33:ad:19:27:c1:ce:51:a8: ec:3d:1b:07:c3:f2:18:40:cc:6a:12:3b:7e:69:d4: 6d:1a:e3:a4:a0:53:d2:3a:c8:7c:92:59:3b:72:67: f8:83:c6:73:cb:9b:68:a2:6d:8f:b3:09:8e:b1:0b: 80:25 Exponent: 65537 (0x10001) X509v3 extensions: X509v3 Subject Alternative Name: DNS:example.com, DNS:www.example.com X509v3 Subject Key Identifier: A4:BC:EE:31:90:A4:B0:A7:D0:5F:B9:C6:DA:47:A8:70:2A:01:1C:0D Signature Algorithm: sha256WithRSAEncryption Signature Value: a3:ea:fa:29:cc:75:0a:e3:c6:6b:1b:a2:22:67:f4:8e:b4:56: 70:f6:d3:24:7f:7e:21:eb:01:d8:8f:de:39:61:8e:8e:d5:c4: 4c:6a:8c:d1:d5:4f:c5:3a:ca:6e:ac:64:c5:29:c7:66:96:63: df:14:ba:c7:3d:9a:c9:87:d9:fd:7e:44:30:f6:fb:2a:ef:d7: f9:98:a0:94:3c:50:47:df:af:85:f4:24:75:e6:2f:4a:91:ae: c2:31:c6:dc:db:52:9a:3c:51:49:c4:68:2b:6c:79:30:6e:f0: a4:5b:ec:a3:48:82:fd:57:5e:9e:48:02:e6:61:8b:69:4e:03: 69:ae:1f:3c:76:2a:15:90:4c:83:af:f2:b1:65:de:ef:f6:d4: 5b:0e:3f:5e:66:f5:79:ca:bf:b0:9f:a8:f6:55:e7:77:8a:cb: fa:62:cc:96:fe:9a:77:02:8f:61:5b:28:da:01:41:de:ce:88: 1a:92:c5:e0:4d:13:5b:44:52:88:79:35:b8:fd:e2:78:c9:b0: 7d:6a:96:7f:3d:67:d0:f7:38:03:08:3d:20:98:0c:4c:8b:da: 1b:a3:cf:83:18:2e:b1:94:18:dc:f1:2d:ed:1e:dd:36:3e:ec: 73:da:c2:2a:76:d4:a1:18:d7:79:d4:6f:e0:f0:31:8a:ea:85: ff:8a:25:60
```
```php
$gobuy->convertPEMtoDER( sprintf( "%sapp/Output/root_cert.pem", $root ), sprintf( "%sapp/Output/root_cert_der.der", $root ) );
```
Convert PEM to DER.
```php
$gobuy->convertDERtoPEM( sprintf( "%sapp/Output/root_cert_der.der", $root ), sprintf( "%sapp/Output/root_cert_pem.pem", $root ) );
```
Convert DER to PEM.

```php
echo $gobuy->verifyCertWithCA( sprintf( "%sCA/ca.crt", $root ),
                                         sprintf( "%sapp/CMS/concatenated_cert.pem", $root ) );
```
Returns the below if 'OK', otherwise throws an error. Where `concatenated_cert.pem` is the file holding the cascaded intermediate files generated from the API [cascadeUntrustedCertificate](#cascading-intermediate-certificate). We recommend you play around with this API and see which certificate fails and which doesn't with your specified CA certificate.
```bash
C:\xampp\htdocs\...\app/CMS/concatenated_cert.pem: OK
```
```php
$gobuy->encryptFile(sprintf( "%sapp/Output/data.txt", $root ), 
        sprintf( "%sapp/Output/encr_data.pem", $root ), 'password');
```
Encrypt data. Returns file contents
```php
$gobuy->decryptFile(sprintf( "%sapp/Output/encr_data.pem", $root ), 
    sprintf( "%sapp/Output/decr_data.pem", $root ), 'password');
```
decrypt data. Returns file contents
```php
echo $gobuy->createPKCS12(sprintf( "%sapp/CMS/user_certificate.pem", $root ), 
        sprintf( "%sapp/CMS/user_private_key.pem", $root ),
        sprintf( "%sCA/ca.crt", $root ),
    sprintf( "%sapp/Output/p12_cert.p12", $root ), "password" );
```
Create a PKCS12 file. `CA/ca.crt` is the CA certificate file. This is optional but often included to complete the chain of trust.
```php
 $gobuy->extractCertFromPKCS12(sprintf( "%sapp/Output/p12_cert.p12", $root ), 
        sprintf( "%sapp/Output/extracted_cert_from_pkcs12.pem", $root ),
            "password" );
```
You should get an output similar to below:
```vbnet
Bag Attributes
    localKeyID: 5E 35 0F B6 83 B5 D4 6D E6 88 2B 6B BD 88 80 FF FF 61 8B 49 
subject=C=DD, ST=EE, L=RR, O=DD, OU=SS, CN=TT, emailAddress=DD
issuer=C=DD, ST=EE, L=RR, O=DD, OU=SS, CN=TT, emailAddress=DD
-----BEGIN CERTIFICATE-----
MIIDozCCAougAwIBAgIUb+GFUKMJXObxtUV8K5PqJ7RQB90wDQYJKoZIhvcNAQEL
BQAwYTELMAkGA1UEBhMCREQxCzAJBgNVBAgMAkVFMQswCQYDVQQHDAJSUjELMAkG
A1UECgwCREQxCzAJBgNVBAsMAlNTMQswCQYDVQQDDAJUVDERMA8GCSqGSIb3DQEJ
ARYCREQwHhcNMjQwNzE1MTgzMjQ5WhcNMjUwNzE1MTgzMjQ5WjBhMQswCQYDVQQG
EwJERDELMAkGA1UECAwCRUUxCzAJBgNVBAcMAlJSMQswCQYDVQQKDAJERDELMAkG
A1UECwwCU1MxCzAJBgNVBAMMAlRUMREwDwYJKoZIhvcNAQkBFgJERDCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAO88NIOcEhxTsIfRIJm44w7L+4yEo5wS
iMY5e7KyTSQTthZIZfN1hehSP7nAzzFMkmSzQIimouN9dOdpW7QSRnxtslBMtG2O
s28q6WM0O1YipRMQaoaZlF7oi7BqSSqcxO8HmdGOIK0TYZCkFpFQo31+7u2dgyE6
...
-----END CERTIFICATE-----
Bag Attributes: <No Attributes>
subject=CN=My CA, C=AU, ST=Some-State, O=Internet Widgits Pty Ltd
issuer=CN=My CA, C=AU, ST=Some-State, O=Internet Widgits Pty Ltd
-----BEGIN CERTIFICATE-----
MIIDeDCCAmCgAwIBAgIBADANBgkqhkiG9w0BAQsFADBVMQ4wDAYDVQQDDAVNeSBD
QTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDA3MTYxOTAzMzZaFw0yNTA3MTYx
OTAzMzZaMFUxDjAMBgNVBAMMBU15IENBMQswCQYDVQQGEwJBVTETMBEGA1UECAwK
U29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuXLTFqGOZCz+kMcJd/ctpmGn
mmUJkOLacaB20u7UiNgJ7LWOsxDgtSX0Kozusu0ZX5CBk/0wEXV40HoUaRalsY9+
rrbu+EU17obzInVRcp5xBI+BcuSnngRpaH+LIOONJDVD8jVAj8+h6voEIpssDcvh
 ...
-----END CERTIFICATE-----
```
```php
echo $gobuy->extractKeyFromPKCS12(sprintf( "%sapp/Output/p12_cert.p12", $root ), 
        sprintf( "%sapp/Output/extracted_key_from_pkcs12.pem", $root ),
            "12345" );
```
```vbnet
Bag Attributes
    localKeyID: 5E 35 0F B6 83 B5 D4 6D E6 88 2B 6B BD 88 80 FF FF 61 8B 49 
Key Attributes: <No Attributes>
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQxGMCE0aNJBO9Yjsn
aCuF4AICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEJc3wEJNlTW+gYbt
....
-----END ENCRYPTED PRIVATE KEY-----
```
### Explanation
1. Bag Attributes provide metadata about keys and certificates.
2. localKeyID uniquely identifies the key within the PKCS#12 file.
3. Key Attributes may contain additional metadata or be empty.
4. The Encrypted Private Key section contains the actual key data in an encrypted format.
   
```php
$serialCreated =  $gobuy->serialFileCreated( sprintf( "%sCA/", $root ), "serial.srl");
if ( $serialCreated ) {

$gobuy->signCSRWithCA(sprintf( "%sapp/CMS/csr.pem", $root ), 
            sprintf( "%sCA/ca.crt", $root ), 
            sprintf( "%sCA/ca.key", $root ),
            sprintf( "%sapp/Output/new_server_cert.pem", $root ), 365, 
            sprintf( "%sCA/serial.srl", $root ));    

}
```
With the above you can easily creeate a new PEM certificate, signed with a CA certificate you need to specify.

```php
echo $gobuy->checkPrivateKey( sprintf( "%sapp/Output/private_key.pem", $root ) );
```
Checks whether private key is okay. 
```php
RSA key ok -----BEGIN PRIVATE KEY----- MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDBpK8FS0IK/Vky vAd+LKpahcTHqvVXv9tAYNv5fBnfN+A3XZHS9hp18+1XB/glyeGvliDA1priZYRj U5vK3nvBSXviY5zLQ4tZlU/yIyxSeoTSz+hnTEp2JSwWeUcwGBFo4Wq1Lkk1M/H1 JAw20q5en+HYgQt6YSb2RmaEhRn3z489MD+GZKGfRuBv21CQE3vV1X0KKDiXKQgg lQA4VLQIwWIavyiKuTr+uZfprjvyHYn8alCTmxp+B10xqL+vjCiizg5tl2HlQhMz rRknwc5RqOw9GwfD8hhAzGoSO35p1G0a46SgU9I6yHySWTtyZ/iDxnPLm2iibY+z CY6xC4AlAgMBAAECggEAPh94KsmfEWl/0T/zY24u5MWfgLL+7LzXOQsZ5ysCHdOO MhTpsHVVvduYm+Apou3mYm9WaKcwn0sUMs1i4K2JpFPP06xDZA5ySTYWpMbV9Evs Crm6hFE8XjTEtR0JUouWIkCW/DMyN0hH6m4EHIHghq1gtK5BDHU1GGW524ulEpcZ7AoGAXHlEy6W7sjtdrA7KvP6S o20E1+eHs1VUupEftr+DhNegnqaT8E9ZIkvcp40N9A3+TyQNvOu+244kugnKWh/K nUv3MVXcLQ6+PcATV0EdGcvFZnYA5JBH6fnb1IZRFOUJz7aWnF/i3Em1kieDwTuq /ftE92dTEmze2b3yX16y8F8= -----END PRIVATE KEY-----
```
```php
echo $gobuy->checkCSR( sprintf( "%sapp/CMS/csr.pem", $root ) );
```
Get information about your CSR file. The output will look something like below:
```php
Certificate Request: Data: Version: 1 (0x0) Subject: C=DE, ST=EFF, L=SSS, O=AAA, OU=DD, CN=FFF, emailAddress=WEE Subject Public Key Info: Public Key Algorithm: rsaEncryption Public-Key: (2048 bit) Modulus: 00:a3:a9:4d:4c:31:41:51:9a:39:9e:cb:79:45:25: 02:5d:d2:cc:54:9f:0f:f8:53:b6:96:1f:9f:6f:d6: 73:73:a4:f9:3b:00:4e:a7:18:77:d6:6c:13:47:7d: 81:d2:5e:85:36:82:44:67:bb:c9:a3:49:6d:ea:b2: c9:71:dd:f8:fa:27:5e:8a:d1:b4:4e:fa:d9:d3:89: 1e:7b:77:9f:d7:43:1d:70:bc:a8:b6:be:70:77:c3: db:a8:30:a6:bc:b0:4f:6a:68:f7:5d:87:06:01:7a: dd:22:78:9c:7c:41:a4:03:a9:02:c5:96:d2:bc:43: d1:b8:8e:74:56:4c:9b:42:6b:a6:18:33:ca:02:21: d1:a0:88:a3:6b:c2:7f:01:75:14:f9:63:c1:02:e7: 28:90:37:a1:46:39:0f:f3:74:f3:25:01:b3:0f:2e: f7:d9:ac:7a:f2:b2:64:55:bb:3f:e1:9c:94:b9:76: 0b:40:e1:7f:5b:cd:06:8f:59:ff:85:61:a9:27:aa: 88:d5:ab:06:3f:d6:ee:08:9b:6c:12:18:8e:0b:b6: e7:38:bd:f0:82:55:a1:1a:0f:c6:aa:a9:a6:04:07: d3:23:ec:03:af:72:f8:fa:3f:e3:51:49:eb:d2:ef: 7c:31:79:ed:56:a3:0b:d8:51:e9:02:a7:cc:66:dc: 07:39 Exponent: 65537 (0x10001) Attributes: (none) Requested Extensions: Signature Algorithm: sha256WithRSAEncryption Signature Value: 0a:e9:ec:3f:c4:ba:9e:a0:17:5b:0c:08:4f:fe:96:65:8e:39: a7:2d:20:7b:62:27:89:8f:41:94:5a:ee:bd:37:06:d1:ec:6a: 02:a7:72:52:33:23:87:ef:8e:f0:df:4d:4b:1d:e8:41:8c:08: c6:a1:9b:89:87:56:a0:19:6d:50:19:ce:6b:af:4c:6f:35:f4: 79:2a:6e:88:6b:b8:91:eb:b7:e3:c8:15:43:90:65:1e:13:fa: 15:42:2e:c5:d3:40:a9:ef:a9:16:22:39:89:ad:94:fc:b0:f7: 42:b5:f7:0f:a7:45:f7:7f:33:fa:c0:9d:3b:65:12:7f:fa:a9: 01:6c:29:a9:18:92:09:27:14:64:c9:25:23:88:62:17:2b:5c: d0:c8:ad:3d:b4:6f:71:3e:6a:90:cb:c6:3f:80:1f:97:69:35: fa:9c:2c:de:24:b7:d7:e9:1f:a9:24:45:b4:c1:e0:13:1e:e3: 0c:1e:85:a6:88:8a:33:4d:53:48:5f:0f:2d:c0:03:94:17:d9: 4c:de:79:c9:20:f0:02:59:f9:b6:66:4a:99:ed:83:dd:a9:aa: fb:56:ff:24:3d:32:13:52:4a:59:d7:46:9d:52:19:0b:2e:6e: 41:41:d4:f3:b7:6d:b1:6e:0c:06:c2:94:69:f5:42:77:58:99: 8f:a7:ca:89
```
```php
echo $gobuy->base64EncodeFile( sprintf( "%sapp/CMS/data.txt", $root ),
                sprintf( "%sapp/Output/encoded.txt", $root ) );
```
The output will look something like below:
```php
UGxlYXNlIE5vdGU6IFRoaXMgY29udGFjdCBmb3JtIGlzIGZvciBhZHZlcnRpc2Vy
cyANCndobyBoYXZlIGEgYnVzaW5lc3MgYWNjb3VudCBhbmQgbmVlZCBoZWxwIHdp
dGggQWRzDQogTWFuYWdlci4gVG8gZ2V0IGhlbHAgd2l0aCB0aGUgYXBwLCBvciBh
IHBlcnNvbmFsDQogIFNuYXBjaGF0IGFjY291bnQsIHBsZWFzZSByZWFjaCBvdXQg
dG8gU25hcGNoYXQgU3VwcG9ydCBoZXJlLg==
```

```php
<?php
try {
 
    // Base64 encode file
    base64EncodeFile('plaintext.txt', 'encoded.txt');
    echo "File Base64 encoded successfully.\n";
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}

?>


```

# Diffie-Hellman
In our encryption class, we firmly believe in incorporating the Diffie-Hellman authentication stage as a crucial step before decryption begins or generation of keys from the secret for other tasks. This authentication process, which involves you and your users, plays a vital role in ensuring the security and integrity of the encrypted communication. Here's why we consider it necessary:
1. **Mutual Authentication**:
With Diffie-Hellman authentication stage we facilitate mutual authentication between you and your users. By verifying each other's identities, you can establish trust and confidence before proceeding with the decryption process or generation of keys from the shared secret. This mutual authentication helps prevent unauthorized access and protects against man-in-the-middle attacks. Refer to our book on "Encryption" to learn more on this kind of attack, where we discussed it with the sufficient examples.

1. **Protection against Replay Attacks**:
Including Diffie-Hellman authentication protects against replay attacks. With authentication in place, each communication session generates a unique session key that is used exclusively for that session. This prevents replay attacks, where an adversary intercepts and replays previously captured encrypted data, as the session key changes for each session.

1. **Defense against Impersonation**:
By incorporating the Diffie-Hellman authentication stage, we mitigate the risk of impersonation attacks. Through the authentication process, both you and your users verify your respective identities, ensuring that the encryption and decryption operations take place between the intended parties. This protects against malicious individuals attempting to impersonate either you or the user.




## Blade Template Code

```html
<body class="antialiased">
    @inject('gobuy', 'App\Services\GoBuy')

    @php
        $base = $gobuy->generateLargeBase();
        $prime = $gobuy->generateLargePrime();
       
        $dh = $gobuy->getDH( $prime, $base );
            
        list($privateKey, $publicKey) = $dh->generateClientKeys();
    @endphp
</body>
```

#### Explanation

1. **HTML Body Tag with Class**:
    ```html
    <body class="antialiased">
    ```
    - This defines the body of the HTML document with the class `antialiased` for improved text rendering.

2. **Service Injection**:
    ```blade
    @inject('gobuy', 'App\Services\GoBuy')
    ```
    - The `@inject` directive is used to inject an instance of the `GoBuy` service into the Blade template. This allows access to the service's methods within the template. `GoBuy` class inherits directly from `GoBuyEncryption` internal class. This is one of the ways to bring our object to your view.

```php

<?php

namespace App\Services;
use GoBuy\Encryption\GoBuyEncryption;
class GoBuy extends GoBuyEncryption{
   
    }

```



1. **PHP Block**:
    ```blade
    @php
        $base = $gobuy->generateLargeBase();
        $prime = $gobuy->generateLargePrime();
       
        $dh = new GoBuy\Encryption\DiffieHellman($base, $prime);
            
        list($privateKey, $publicKey) = $dh->generateClientKeys();
    @endphp
    ```
    - **Generate Large Base and Prime**:
        ```php
        $base = $gobuy->generateLargeBase();
        $prime = $gobuy->generateLargePrime();
        ```
        - Calls methods from the `GoBuy` service to generate a large base and a large prime number for the Diffie-Hellman key exchange.

    - **Initialize Diffie-Hellman**:
        ```php
        $dh = $gobuy->getDH($base, $prime);
        
        ```
        - Get a new instance of the `DiffieHellman` class, initialized with the generated base and prime.

    - **Generate Client Keys**:
        ```php
        list($privateKey, $publicKey) = $dh->generateClientKeys();
        ```
        - Calls the `generateClientKeys` method of the `DiffieHellman` class to generate a pair of client keys (private and public).

This code sets up the necessary values and objects for a Diffie-Hellman key exchange within a Laravel Blade template, leveraging the custom `GoBuy` service and `DiffieHellman` encryption class.


Sure, here is the provided HTML snippet explained in Markdown format:


### HTML Div Element for Diffie-Hellman Key Exchange Data

This example demonstrates an HTML `<div>` element used to store and display Diffie-Hellman key exchange data. The data attributes within the `<div>` store various key exchange values such as the public key, base, prime, and private key.

#### HTML Code

```php
//Blade
@php
        $base = $gobuy->generateLargeBase();
        $prime = $gobuy->generateLargePrime();
       
        $dh = new GoBuy\Encryption\DiffieHellman($base, $prime);
            
        list($privateKey, $publicKey) = $dh->generateClientKeys();
@endphp
<div id="response" public-key-data="{{$publicKey}}" base-data="{{$base}}" prime-data="{{$prime}}" private-key-data="{{$privateKey}}">
</div>
```

#### Explanation


1. **Public Key Data Attribute**:
    ```html
    public-key-data="{{$publicKey}}"
    ```
    - The `public-key-data` attribute stores the public key generated during the Diffie-Hellman key exchange. The value `{{$publicKey}}` is a Blade template expression that outputs the public key value.

2. **Base Data Attribute**:
    ```html
    base-data="{{$base}}"
    ```
    - The `base-data` attribute stores the base value used in the Diffie-Hellman key exchange. The value `{{$base}}` is a Blade template expression that outputs the base value.

3. **Prime Data Attribute**:
    ```html
    prime-data="{{$prime}}"
    ```
    - The `prime-data` attribute stores the prime number used in the Diffie-Hellman key exchange. The value `{{$prime}}` is a Blade template expression that outputs the prime value.

4. **Private Key Data Attribute**:
    ```html
    private-key-data="{{$privateKey}}"
    ```
    - The `private-key-data` attribute stores the private key generated during the Diffie-Hellman key exchange. The value `{{$privateKey}}` is a Blade template expression that outputs the private key value.


This `<div>` element serves as a container for storing and displaying Diffie-Hellman key exchange data. By using custom data attributes (`public-key-data`, `base-data`, `prime-data`, `private-key-data`), the element encapsulates all necessary values for the key exchange process. The Blade template expressions (`{{$publicKey}}`, `{{$base}}`, `{{$prime}}`, `{{$privateKey}}`) dynamically insert the corresponding values into the attributes. There are more ways to extract these values. It now depends on the method you desire the most.

```js

var clientPublicKey = $( "#response" ).attr( "public-key-data" );
var clientPrivateKey = $( "#response" ).attr( "private-key-data" );
var base = $( "#response" ).attr( "base-data" );
var prime = $( "#response" ).attr( "prime-data" );

var obj = {
                "clientPublicKey" : clientPublicKey,
                "clientPrivateKey" : clientPrivateKey,
                "base" : base,
                "prime" : prime
          }
     
       $.ajax({

              url: "/send_client_dets",
              type: "post",
              data: obj,
              success: function ( res ) {
                     console.log( res )
                     var clientSharedSecret = modExp( res[ "serverPublicKey" ], clientPrivateKey, prime)                     
                     if ( clientSharedSecret===res[ "seversharedSecret" ] ) {
                            // Use the shared secret here ...
                     }
                  

              }, 
              error: function ( err ) {
                      if ( err ) console.error( err.responseText );
              }

     })

```
We are using jQuery to speed things up. You may use any method you find desirable.


```javascript
// Function to perform modular exponentiation
function modExp(base, exponent, modulus) {
    // Convert input values to BigInt for handling large integers
    base = BigInt(base);
    exponent = BigInt(exponent);
    modulus = BigInt(modulus);

    // If modulus is 1, the result is always 0
    if (modulus === 1n) return 0n;

    // Initialize result to 1n (BigInt 1)
    let result = 1n;

    // Compute base % modulus
    base = base % modulus;

    // Loop while exponent is greater than 0
    while (exponent > 0) {
        // If the current exponent is odd, multiply result by base and take modulus
        if (exponent % 2n === 1n) {
            result = (result * base) % modulus;
        }
        // Right shift the exponent by 1 (equivalent to dividing by 2)
        exponent = exponent >> 1n;
        // Square the base and take modulus
        base = (base * base) % modulus;
    }

    // Return the computed result
    return result;
}
```

### Detailed Explanation

1. **Function Definition**:
    ```javascript
    function modExp(base, exponent, modulus) {
    ```
    - Defines a function named `modExp` that takes three parameters: `base`, `exponent`, and `modulus`.

2. **Convert Input Values to BigInt**:
    ```javascript
    base = BigInt(base);
    exponent = BigInt(exponent);
    modulus = BigInt(modulus);
    ```
    - Converts the `base`, `exponent`, and `modulus` parameters to BigInt to handle large integer calculations that exceed the precision of regular JavaScript numbers.

3. **Check if Modulus is 1**:
    ```javascript
    if (modulus === 1n) return 0n;
    ```
    - If the `modulus` is `1`, the function returns `0` immediately because any number modulo `1` is `0`.

4. **Initialize Result**:
    ```javascript
    let result = 1n;
    ```
    - Initializes a variable `result` to `1n` (BigInt 1). This will store the final result of the modular exponentiation.

5. **Compute Initial Base Modulus**:
    ```javascript
    base = base % modulus;
    ```
    - Computes `base % modulus` and updates the `base` variable with this value.

6. **Main Loop**:
    ```javascript
    while (exponent > 0) {
    ```
    - A loop that continues as long as `exponent` is greater than `0`.

7. **Check if Exponent is Odd**:
    ```javascript
    if (exponent % 2n === 1n) {
        result = (result * base) % modulus;
    }
    ```
    - If `exponent` is odd (`exponent % 2n === 1n`), it multiplies `result` by `base` and then takes the modulus to update `result`.

8. **Right Shift Exponent**:
    ```javascript
    exponent = exponent >> 1n;
    ```
    - Right shifts the `exponent` by `1`, which is equivalent to dividing the `exponent` by `2` (using integer division).

9. **Square the Base**:
    ```javascript
    base = (base * base) % modulus;
    ```
    - Squares the `base` and then takes the modulus to update `base`.

10. **Return Result**:
    ```javascript
    return result;
    ```
    - Returns the final computed `result`.
    - 

This function `modExp` implements the modular exponentiation algorithm, which efficiently computes `(base^exponent) % modulus`. It handles large integers using BigInt and uses the method of exponentiation by squaring to ensure the computation is performed efficiently even for large exponent values. 

```php
Route::post('/send_client_dets', '\App\Http\Controllers\UserController@sendClientDets');
```
Next is to target an endpoint, just like above or choose a different URI. Below is the controller method:

## Controller method

```php
public function sendClientDets(Request $request, GoBuyEncryption $gobuy)
{
    // Retrieve the client's public key from the request
    $clientPulicKey = $request["clientPublicKey"];

    // Retrieve the base value from the request
    $base = $request["base"];

    // Retrieve the prime value from the request
    $prime = $request["prime"];

    // Initialize the Diffie-Hellman object with the base and prime values using the GoBuyEncryption service
    $dh = $gobuy->getDH($base, $prime);

    // Generate the server's public and private keys using the Diffie-Hellman object
    list($serverPublicKey, $serverPrivateKey) = $dh->getServerKeys();

    // Compute the shared secret using the client's public key, server's private key, and prime value
    $sharedSecret = $dh->computeSharedSecret($clientPulicKey, $serverPrivateKey, $prime);

    // Return an array containing the server's shared secret and public key
    return [
        "seversharedSecret" => $sharedSecret,
        "serverPublicKey" => $serverPublicKey
    ];
}
```

### Detailed Explanation

1. **Function Definition**:
    ```php
    public function sendClientDets(Request $request, GoBuyEncryption $gobuy)
    ```
    - This defines a public function named `sendClientDets` that accepts two parameters: an HTTP request object `$request` and an instance of the `GoBuyEncryption` service `$gobuy`.

2. **Retrieve Client's Public Key**:
    ```php
    $clientPulicKey = $request["clientPublicKey"];
    ```
    - Extracts the client's public key from the request data and stores it in the `$clientPulicKey` variable.

3. **Retrieve Base Value**:
    ```php
    $base = $request["base"];
    ```
    - Extracts the base value used in the Diffie-Hellman calculation from the request data and stores it in the `$base` variable.

4. **Retrieve Prime Value**:
    ```php
    $prime = $request["prime"];
    ```
    - Extracts the prime value used in the Diffie-Hellman calculation from the request data and stores it in the `$prime` variable.

5. **Initialize Diffie-Hellman Object**:
    ```php
    $dh = $gobuy->getDH($base, $prime);
    ```
    - Uses the `GoBuyEncryption` service to create a new Diffie-Hellman object with the provided base and prime values.

6. **Generate Server Keys**:
    ```php
    list($serverPublicKey, $serverPrivateKey) = $dh->getServerKeys();
    ```
    - Calls the `getServerKeys` method on the Diffie-Hellman object to generate and retrieve the server's public and private keys. These keys are stored in the `$serverPublicKey` and `$serverPrivateKey` variables, respectively.

7. **Compute Shared Secret**:
    ```php
    $sharedSecret = $dh->computeSharedSecret($clientPulicKey, $serverPrivateKey, $prime);
    ```
    - Computes the shared secret using the client's public key, the server's private key, and the prime value. The result is stored in the `$sharedSecret` variable.

8. **Return Response**:
    ```php
    return [
        "seversharedSecret" => $sharedSecret,
        "serverPublicKey" => $serverPublicKey
    ];
    ```
    - Returns an associative array containing the computed shared secret (`"seversharedSecret"`) and the server's public key (`"serverPublicKey"`). This data is typically sent back to the client as a response.

This function performs a Diffie-Hellman key exchange, generating and returning the server's public key and the shared secret derived from the client's public key and the server's private key.

## Alternatively on Diffie-Hellman's 

You may place a PHP script on the client side to execute using CMD prompt.
```php

php artisan make:command Encryption

```
```php
<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;

class Encryption extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'exec:encryption';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Command description';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        // Include the external PHP script, "script3.php". Place in public folder where CSS and JS folders normally are. 
        include public_path( "client3.php" );
    }
}

```
Include our object as below in `client3.php`. This works perfectly well. 
```php

<?php 
require "../vendor/autoload.php";

use GoBuy\Encryption\GoBuyEncryption;
use GoBuy\Encryption\DiffieHellman;
$gobuy = new GoBuyEncryption();

$base = $gobuy->generateLargeBase();
$prime = $gobuy->generateLargePrime();

$dh = $gobuy->getDH( $prime, $base );
    
list($privateKey, $publicKey) = $dh->generateClientKeys(  );

// We need a public key from the server if secret MUST be derived.
$serverUrl = 'http://127.0.0.1:8000';
$queryBuilder = [ "prime"=>$prime, "base" => $base];
$serverPublicKey = $dh->getServerPublicKey( $serverUrl."/get-server-public-key",
                         $queryBuilder )["publicKey"];
```

```php
//web.php - route page
Route::post('/get-server-public-key', [UserController::class, 'getServerPublicKey']);
```

```php
//UserController.php
   public function getServerPublicKey( GoBuyEncryption $gobuy )
    {

        $prime = $request->input( "prime" );
        $base = $request->input( "base" );
        $dh = $gobuy->getDH( $prime, $base );
        list($privateKey, $publicKey) = $dh->generateServerKeys( );
        
        // Store sever's private key on the server for the next request. Do not send this key down to the user. Must be protected carefully.
        Session::put( "serverPrivateKey", (string)$privateKey );

        return response()->json(['publicKey' => $publicKey]);

    }
```
The method within `UserController` class will look like above. Now the client has to send it's public key to the server for the server to generate it's own shared secret. Do not send the client's private key to the server, please. It is a security breach. 
```php
//client3.php

//...
$clientShareSecret = $dh->computeClientSharedSecret( $clientPrivateKey, $serverPublicKey );
$dh->sendClientPublicKey( $serverUrl . '/compute-shared-secret', [
                                        'clientPublicKey' =>            $clientPublicKey ] );
```
```php
// web.php - route page
Route::post('/compute-shared-secret', [UserController::class, 'computeSharedSecret']);
```
```php
    //UserController.php
    public function computeSharedSecret(Request $request, GoBuyEncryption $gobuy )
    {
        $clientPublicKey = $request->input('clientPublicKey');
        $serverPrivateKey = Session::get( "serverPrivateKey" ); 
        $prime = Session::get( "prime" ); 
        $base = Session::get( "base" ); 
 
        $dh = $gobuy->getDH( $prime, $base );

        $serverSharedSecret = $dh->computeSharedSecret( $clientPublicKey, $serverPrivateKey );
        
        return response()->json(['sharedSecret' => $serverSharedSecret]);

    }

```
If `Session::get` does not work for you, consider the following:
```php
        $path = $gobuy->saveData( $privateKey ); 
```
Call this to save server's private key in a secret temp file on your device. This file is deleted immediately after every cycle. So you may wish to save your keys to a location you believe works best for you.
```php
 public function getServerPublicKey( Request $request,  GoBuyEncryption $gobuy )
    {
        $prime = $request->input( "prime" );
        $base = $request->input( "base" );
        $dh = $gobuy->getDH( $prime, $base );

        list($privateKey, $publicKey) = $dh->generateServerKeys( );
     
        $path = $gobuy->saveData( $privateKey ); // Call this to save server's private key.

        return response()->json(['publicKey' => $publicKey,  
                                    'path' => bin2hex($gobuy->harden( $path ))
                                ]);
    }
```
Call `saveData` and pass server's private key for the next stage of this system. We encourage you to `harden` or damage the path by calling `damageThis` on the path before transit; or have it `veil`ed like we have demonstrated. This is a temp path on your system, not the key. DO NOT MOVE THE SERVER's PRIVATE KEY TO THE CLIENT!! 
Then after:

```php
    public function computeSharedSecret(Request $request, GoBuyEncryption $gobuy )
    {
        $clientPublicKey = $request->input('clientPublicKey');
        $path = $gobuy->ease(hex2bin($request->input('path')));

        $serverPrivateKey = $gobuy->getData( $path ); 

        $serverSharedSecret = $dh->computeSharedSecret( $clientPublicKey, $serverPrivateKey );
        return response()->json(['sharedSecret' => $serverSharedSecret]);

    }
```
You want to `ease` the path as we have done above to return to a more human-readable form. The `getData` will return the private key of the server. HANDLE WITH CARE!! We didn't take the key to the client, rather the path to the key was saved on device after hardening it.  
For `$serverPrivateKey`, you should get an output like below if everything goes well:
```output
string(77) "812830422017873248489061593359984273276395722610085745773184591622547259
03466"
```
For the `$serverSharedSecret`, you should get:
```output

{"sharedSecret":"5782213232589419880823134809815678942388436899052383613472946840659
030813339951250867629747368940293046782968831914815037838351722320804215751475560783
7480603217065611487812391300266927278132489371633944691283404075838398607516532"}

```
If e verything goes well, you should have a secret.
```php
if ( $clientShareSecret === $serverSharedSecret ) {
    // Use secret here.

    $symmetricKey = $gobuy->getSymmKey( $clientSharedSecret, "sha256" );
    $gobuy->cipher( "Data to encrypt", $symmetricKey );

}
```
## Symmetric Key Generation
After the DH key exchange, both parties have a common shared secret. This shared secret can be used to derive a symmetric encryption key. Symmetric encryption algorithms (e.g., AES like we showed above) can then use this key to encrypt and decrypt messages, ensuring that only parties with the shared secret can read the encrypted communication.

```php
if ( $clientShareSecret === $serverSharedSecret ) {
    echo "Successful!!!";
    $gobuy->hmac( "Data to hash", $clientSharedSecret, "sha256" );

}
```
## Message Authentication Codes (MACs)

The shared secret can be used to generate a Message Authentication Code (MAC) for each message. A MAC ensures the integrity and authenticity of the message, indicating that the message has not been altered during transit and confirming the identity of the sender.
```php
if ( $clientShareSecret === $serverSharedSecret ) {

    list( $symmetricKey, $macKey ) = $gobuy->deriveKey( $clientSharedSecret);

}
```
## Key Derivation
In our system, the shared secret can be used as an input to a key derivation function (KDF) to generate multiple keys for different cryptographic purposes, such as encryption keys, MAC keys, and initialization vectors (IVs).

## Forward Secrecy
Each session can use a unique shared secret generated through a new DH key exchange, providing forward secrecy. If long-term keys are compromised, past communications remain secure because the session keys derived from the shared secrets cannot be retroactively decrypted.

```php
if ( $clientShareSecret === $serverSharedSecret ) {

    $digitalSignature = $gobuy->signThis( $clientSharedSecret, 'file://path/to/private/key.pem');

}
```
## Secure Authentication
Although DH key exchange by itself does not provide authentication, combining the shared secret with digital signatures or certificates can authenticate the parties involved. The shared secret ensures that only parties with knowledge of the corresponding private keys can derive the same secret.

# Certificate Info
You may use the following at your convinience to fetch information about a particular certificate

```php
$gobuy->certSubject( "path/to/certificate.crt" ); // Fetch the owner of the certificate. 

```
In the context of certificate signing, the **subject** refers to the entity whose public key is associated with the certificate. It is essentially the "owner" of the certificate. The subject field in a certificate identifies this entity and may include attributes such as a distinguished name (DN), which can contain information like country, organization, common name, etc. The subject is crucial for establishing trust in digital communications, as it allows others to verify that a public key belongs to a specific individual or organization.

```php
$gobuy->extractCrlDistributionPoints( "path/to/certificate.crt" ); // Helps you fetch the CRL needed to check if a certificate has been revoked. 

```
A CRL Distribution Point (CDP) in a certificate is an extension that specifies the location where a Certificate Revocation List (CRL) can be found. The CRL is a list of certificates that have been revoked by the issuing Certificate Authority (CA) before their scheduled expiration date, and it's used to ensure that these certificates are not trusted anymore. The CDP helps in the distribution of this list to parties that need to verify the revocation status of certificates.
```php
$gobuy->extractSerialNumber( "path/to/certificate.crt" ); // 

```
A certificate serial number is a unique identifier assigned by a Certificate Authority (CA) to each SSL certificate. It's an alphanumeric string that distinguishes one certificate from another, ensuring that each certificate can be individually identified and verified. With us, you can easily fetch this number for the security and integrity of your digital communications, as it helps prevent fraud and misuse of certificates. 

```php
$gobuy->certVersion( "path/to/certificate.crt" );  

```
The **version field** in a digital certificate indicates the iteration of the X.509 standard used to construct the certificate. Each version may introduce new features, fields, or security enhancements. For example, newer versions might support stronger cryptographic algorithms or provide improved mechanisms for certificate revocation and management. 

Here's a brief overview of the versions:
- **Version 1 (v1)**: Follows the initial X.509 standard for certificates.
- **Version 2 (v2)**: Adds two fields to the fields included in Version 1.
- **Version 3 (v3)**: Represents the current version of the X.509 standard and adds support for certificate extensions.

The version field is crucial as it helps software and systems understand how to correctly interpret and process the certificate's data.

```php
$gobuy->certSigAlgo( "path/to/certificate.crt" ); 

```
The **Signature Algorithm** field in a digital certificate specifies the algorithm used to sign the certificate. This includes both the hash function and the digital signature algorithm. For example, "sha256RSA" indicates that the SHA-256 hash function is used along with the RSA digital signature algorithm.

This field is crucial because it ensures the integrity and authenticity of the certificate. When a certificate is issued, the issuing Certificate Authority (CA) uses this algorithm to create a digital signature on the certificate. This signature can then be verified by others to confirm that the certificate is indeed issued by the CA and has not been tampered with.

```php
$gobuy->certIssuer( "path/to/certificate.crt" );  
```
The issuer in a digital certificate is known as a **Certificate Authority (CA)**. It is a trusted entity that issues digital certificates for websites and other entities. The CA validates the domain and, depending on the type of certificate, may also verify the ownership of the website. After validation, the CA issues TLS/SSL certificates that are trusted by web browsers like Chrome, Safari, and Firefox. This process helps ensure secure communications over the internet by verifying the legitimacy of websites and other entities¹.

```php
$gobuy->certValidity( "path/to/certificate.crt" ); 
```
The field validity in a digital certificate refers to the **validity period** of the certificate, which is the time frame during which the certificate is considered trustworthy. It is defined by two key dates:

- **Not Before**: This date indicates when the certificate can be considered valid. It may be set in advance of the actual issuance date².
- **Not After**: This date contains the time when the certificate expires and is no longer valid.

During this validity period, the certificate can be used to establish secure communications and verify the identity of entities such as users, devices, or websites. Once the certificate expires, it must be renewed or replaced to maintain security.

```php
$gobuy->certSubjectPKI( "path/to/certificate.crt" ); 
```
The **Subject Public Key Info** in a digital certificate is a crucial part that contains the public key and information about it. It's defined in the X.509 standard as a sequence that includes an algorithm identifier and the subject's public key, which is represented as a bit string¹. 

Here's a simplified explanation:
- **Algorithm Identifier**: Specifies the type of public key algorithm used, such as RSA, ECDSA, etc.
- **Subject's Public Key**: The actual public key that corresponds to the private key held by the subject of the certificate.

This information is used to verify signatures and establish secure communications. The Subject Public Key Info ensures that when you receive a digital certificate, you can trust that the public key it contains is indeed associated with the entity named in the certificate's subject field.

```php
$gobuy->certPKA( "path/to/certificate.crt" ); 
```
The **Public Key Algorithm** in a digital certificate is a cryptographic algorithm used to generate a pair of keys: a **public key** and a **private key**. These keys are used for encrypting and decrypting data, as well as for creating and verifying digital signatures. Common public key algorithms include **RSA (Rivest–Shamir–Adleman)** and **Elliptic Curve Cryptography (ECC)**. The security of these algorithms relies on the computational difficulty of certain mathematical problems, making it infeasible to derive the private key from the public key.

```php
$gobuy->certBitSize( "path/to/certificate.crt" ); 
```
This fetches the size of the RSA key used for encryption. The number displayed indicates the length of the key in bits, which is a measure of its strength and security. A 2048-bit key is considered strong and is widely used for securing communications over the internet.

In the context of SSL/TLS certificates, the 2048-bit RSA key is used to encrypt a randomly generated 256-bit symmetric key during the SSL handshake process. This symmetric key is then used for the bulk encryption of data transmitted between the client and server. The RSA key ensures that only the intended recipient can decrypt the symmetric key and thus secure the communication. The output you are expecting.
```mathematica
00:98:69:57:4c:b2:eb:2e:3b:2d:f8:80:86:9b:c2:
2d:83:e6:2d:a1:db:5e:65:82:e1:87:d8:52:d7:a8:
0d:af:ed:81:17:92:3b:7f:ab:d0:f0:89:db:61:0e:
3a:eb:73:bb:1c:9b:bc:a2:6e:3e:8e:ea:53:ab:4a:
3f:ef:4a:c3:a4:e8:d4:6d:4b:0f:98:b9:14:56:eb:
77:61:7e:0c:2e:13:50:52:f6:d9:a5:28:48:07:e6:
3b:fa:57:3c:44:dd:91:13:c5:7b:36:98:fb:8d:47:
0d:ec:27:57:0d:1a:49:29:01:49:06:db:05:6b:71:
02:43:c3:e2:d9:9e:3d:51:74:01:9c:f7:ca:58:90:
f2:ad:42:19:33:df:ad:be:3d:e6:bc:00:2c:af:25:
f1:98:cc:90:a6:93:51:20:02:b2:e9:1a:be:f2:9c:
53:f1:37:ff:0d:d0:76:c9:b4:c0:50:71:95:11:f2:
85:cf:e6:5f:f0:d3:e4:a1:95:ae:2d:9f:58:26:66:
50:b3:3a:ee:1d:7a:34:f6:72:6b:35:a3:fc:fe:d4:
94:81:cb:59:14:e3:02:74:4f:7e:aa:98:9f:3c:57:
02:fc:27:11:e6:de:c4:95:60:f1:e7:b1:8a:03:ca:
19:b7:01:a5:c5:ad:c3:cb:43:b4:ba:42:8a:9f:31:
a5:d9
```
```php
$gobuy->certExponent( "path/to/certificate.crt" )
```
This exponent is commonly used as the public key exponent in RSA encryption. It's a prime number that is chosen because it has certain mathematical properties that make it efficient for encryption and decryption processes. Specifically, it's a small prime number with only two bits set, which makes modular exponentiation in software fast enough. This efficiency is crucial for the performance of cryptographic operations. May return:  `65537` (0x10001). The use of `65537` as the public key exponent is a standard practice in RSA cryptography.

```php
$gobuy->certX509v3Ext( "path/to/certificate.crt" ); 
```
X.509v3 extensions are a key feature of the X.509 standard for digital certificates, allowing for the inclusion of additional information beyond the basic certificate fields. These extensions can specify various attributes such as alternative subject names, usage restrictions, and more. They are used to enhance the functionality and flexibility of certificates, making them suitable for a wide range of applications

```php
$gobuy->certX509v3SKI( "path/to/certificate.crt" ); 
```
The X509v3 Subject Key Identifier (SKI) is an extension in an X.509 digital certificate that provides a unique identifier for the public key contained within the certificate. This identifier is used to associate a certificate with a particular public key, which can be useful for tracking and managing keys, especially in environments where a certificate authority (CA) issues multiple certificates with the same subject name but different keys.

```php
$gobuy->certX509v3AKI( "path/to/certificate.crt" ); 
```
The **X509v3 Authority Key Identifier** is an extension used in digital certificates to identify the public key that corresponds to the private key used to sign the certificate. This identifier can be based on either the **key identifier** (the subject key identifier in the certificate signer's certificate) or the **issuer name and serial number**.

It serves as a way to link a certificate to its issuing authority, which is particularly useful for certificate revocation lists (CRLs) and for establishing trust in a Public Key Infrastructure (PKI). By providing a clear reference to the authority's public key, it helps ensure that the certificate can be properly validated and trusted.

```php
$gobuy->certX509v3BC( "path/to/certificate.crt" ); 
```
The X509v3 Basic Constraints extension in a digital certificate is used to indicate whether the certificate holder is a Certificate Authority (CA) and, if so, the depth of the certification path. This extension specifies if the subject of the certificate is a CA that is allowed to issue child certificates. It also defines the maximum depth of valid certification chains, which is particularly important for ensuring that a certificate chain does not exceed a certain length. In the context of X.509 digital certificates, the Basic Constraints extension with the `critical` flag indicates that the certificate is a Certificate Authority (CA) and that it is allowed to issue other certificates, known as child certificates
```php
$gobuy->certCA( "path/to/certificate.crt" ); 
```
In the context of digital certificates, `CA:TRUE` indicates that the certificate is issued by a Certificate Authority (CA) and is considered trustworthy. This is part of the Basic Constraints extension in X.509 certificates, which specifies whether the certificate can be used to sign other certificates (keyCertSign) and whether it is a root certificate (CA). When `CA:TRUE` is set, it means the certificate is a CA certificate and can be used to sign other certificates, establishing a chain of trust.

```php
$gobuy->certSigVal( "path/to/certificate.crt" ); 
```
The Signature Value in a digital certificate is a digital signature computed upon the ASN.1 DER encoded Certificate. This signature is created using the private key of the certificate issuer and is used to verify the authenticity and integrity of the certificate. The Signature Value ensures that the certificate has not been tampered with and that it was indeed issued by the claimed CA.

# Fetching a Certificate Revocation List (CRL)
```php

$crlFile = $gobuy->fetchCRL(  "path/to/where/you/will/store/crl_file.crl",  "http://crl.godaddy.com/gdig2s1-23.crl" );
$gobuy->decryptCRL( "path/to/where/you/will/store/crl_file.crl", "path/to/decrypted/server_crl_decr.pem" );

```
For the `fetchCRL` method, you could simply invoke the method without the second argument, then GoDaddy endpoint will be your default url. See below:
```php
$crlFile = $gobuy->fetchCRL(  "path/to/where/you/will/store/crl_file.crl" );

```

# Exception Handling

The CMS Signer throws exceptions if there are issues with file signing. Make sure to handle these exceptions in your application.

# Initial Work

The CMS Signer Library was created to provide developers with an easy-to-use solution for signing files using Cryptographic Message Syntax (CMS). It simplifies the process of ensuring data integrity and authenticity in PHP applications. The initial release includes core signing features, comprehensive error handling, and integration with Monolog for logging.


# Contributing

Contributions are welcome. Please submit pull requests to the repository.


# License

This library is open-sourced under the MIT license. See the LICENSE file for details.

# Support

For support, please open an issue in the GitHub repository.

# Author

- Victory J.M. Uzochukwu - Creator and Lead Developer - [codingdrips1on1](https://github.com/codingdrips1on1/GoBuyEncryption/tree/main)

Main Contributors: [GoBuy.cheap](https://www.gobuy.cheap) and  [CodingDrips.eu](https://www.codingdrips.eu) 

# Books for your information.
____________
You may proceed to get a copy [here](https://www.gobuy.cheap/developer-blog)
____________
![Integrated Web Dev.](web.png)
____________
____________
Coming soon!
____________
![Cryptograph - PHP](crypt.png)