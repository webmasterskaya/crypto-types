<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class ECDSAAITest extends TestCase
{
    public function testSupportsKeyAlgorithm()
    {
        $sig_algo = new ECDSAWithSHA1AlgorithmIdentifier();
        $key_algo = new ECPublicKeyAlgorithmIdentifier(
            ECPublicKeyAlgorithmIdentifier::CURVE_PRIME192V1);
        $this->assertTrue($sig_algo->supportsKeyAlgorithm($key_algo));
    }

    public function testDoesntSupportsKeyAlgorithm()
    {
        $sig_algo = new ECDSAWithSHA1AlgorithmIdentifier();
        $key_algo = new RSAEncryptionAlgorithmIdentifier();
        $this->assertFalse($sig_algo->supportsKeyAlgorithm($key_algo));
    }
}
