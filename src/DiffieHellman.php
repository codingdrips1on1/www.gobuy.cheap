<?php
namespace GoBuy\Encryption;
class DiffieHellman {

    // use MyChainOfTrust {}

    private $privateKey;
    private $publicKey;

    private $prime;
    private $base;
    public function __construct( string $base, string $prime ) {

        $this->base = $base;
        $this->prime = $prime;
       
    }

    function sendClientPublicKey($serverUrl, array $buildQuery )
    {
        // echo "\nGGG: " . $serverPrivateKey;

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $serverUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, 
        http_build_query( $buildQuery ));
        // curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        $response = curl_exec($ch);
        curl_close($ch);
        // die( $response );
        $data = json_decode($response, true);
        return gmp_strval($data['sharedSecret']);

    }


    public function generateServerKeys( )
    {
        $privateKey = gmp_random_bits(256);
        $publicKey = gmp_powm($this->base, $privateKey, $this->prime);

        return [ gmp_strval($privateKey), gmp_strval($publicKey)];
    }

    function computeClientSharedSecret($clientPrivateKey, $serverPublicKey )
    {
        // echo "prime3: " .$this->prime. "; base: " . $this->base;
        return gmp_strval(gmp_powm($serverPublicKey, $clientPrivateKey, $this->prime));
    }


    public function getServerPublicKey($serverUrl, array $buildQuery )
    {
        // die ($serverUrl);
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $serverUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, 
        http_build_query( $buildQuery ));

        $response = curl_exec($ch);
        curl_close($ch);
        // die ( $response );
        $data = json_decode($response, true);
        
        return $data;
    }

    function generateClientKeys()
    {
        $privateKey = gmp_random_bits(256);
        $publicKey = gmp_powm($this->base, $privateKey, $this->prime);
        return [
            gmp_strval($privateKey),
             gmp_strval($publicKey),
        ];
    }

  

    public function getServerKeys( ): array
    {   
            $privateKey = gmp_random_bits(256);
            $publicKey = gmp_powm($this->base, $privateKey, $this->prime);
        return [ gmp_strval($publicKey), gmp_strval($privateKey)];
    }

    public function computeSharedSecret( string $clientPublicKey, string $serverPrivateKey ): string
    {
       
        $sharedSecret = gmp_powm(gmp_init($clientPublicKey), $serverPrivateKey, $this->prime);
        $sharedSecretStr = gmp_strval($sharedSecret);
        return $sharedSecretStr;

    }

}
