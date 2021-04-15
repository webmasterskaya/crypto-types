<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Feature\AsymmetricCryptoAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Feature\HashAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Hash\MD5AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Hash\SHA1AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Hash\SHA224AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Hash\SHA256AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Hash\SHA384AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Hash\SHA512AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA224AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA384AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA512AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\MD5WithRSAEncryptionAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\SHA224WithRSAEncryptionAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\SHA384WithRSAEncryptionAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\SHA512WithRSAEncryptionAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\SignatureAlgorithmIdentifierFactory;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class SignatureFactoryTest extends TestCase
{
    /**
     * @dataProvider provideAlgoForAsymmetricCrypto
     *
     * @param AsymmetricCryptoAlgorithmIdentifier $crypto_algo
     * @param HashAlgorithmIdentifier             $hash_algo
     * @param string                              $expected_class
     */
    public function testAlgoForAsymmetricCrypto($crypto_algo, $hash_algo,
        $expected_class)
    {
        $algo = SignatureAlgorithmIdentifierFactory::algoForAsymmetricCrypto(
            $crypto_algo, $hash_algo);
        $this->assertInstanceOf($expected_class, $algo);
    }

    /**
     * @return array
     */
    public function provideAlgoForAsymmetricCrypto()
    {
        $rsa = new RSAEncryptionAlgorithmIdentifier();
        $ec = new ECPublicKeyAlgorithmIdentifier(
            ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1);
        $md5 = new MD5AlgorithmIdentifier();
        $sha1 = new SHA1AlgorithmIdentifier();
        $sha224 = new SHA224AlgorithmIdentifier();
        $sha256 = new SHA256AlgorithmIdentifier();
        $sha384 = new SHA384AlgorithmIdentifier();
        $sha512 = new SHA512AlgorithmIdentifier();
        return [
            [$rsa, $md5, MD5WithRSAEncryptionAlgorithmIdentifier::class],
            [$rsa, $sha1, SHA1WithRSAEncryptionAlgorithmIdentifier::class],
            [$rsa, $sha224, SHA224WithRSAEncryptionAlgorithmIdentifier::class],
            [$rsa, $sha256, SHA256WithRSAEncryptionAlgorithmIdentifier::class],
            [$rsa, $sha384, SHA384WithRSAEncryptionAlgorithmIdentifier::class],
            [$rsa, $sha512, SHA512WithRSAEncryptionAlgorithmIdentifier::class],
            [$ec, $sha1, ECDSAWithSHA1AlgorithmIdentifier::class],
            [$ec, $sha224, ECDSAWithSHA224AlgorithmIdentifier::class],
            [$ec, $sha256, ECDSAWithSHA256AlgorithmIdentifier::class],
            [$ec, $sha384, ECDSAWithSHA384AlgorithmIdentifier::class],
            [$ec, $sha512, ECDSAWithSHA512AlgorithmIdentifier::class],
        ];
    }

    public function testInvalidCryptoAlgo()
    {
        $crypto_algo = new SignatureFactoryTest_InvalidCryptoAlgo();
        $hash_algo = new MD5AlgorithmIdentifier();
        $this->expectException(\UnexpectedValueException::class);
        SignatureAlgorithmIdentifierFactory::algoForAsymmetricCrypto(
            $crypto_algo, $hash_algo);
    }

    public function testInvalidRSAHashAlgo()
    {
        $crypto_algo = new RSAEncryptionAlgorithmIdentifier();
        $hash_algo = new SignatureFactoryTest_InvalidHashAlgo();
        $this->expectException(\UnexpectedValueException::class);
        SignatureAlgorithmIdentifierFactory::algoForAsymmetricCrypto(
            $crypto_algo, $hash_algo);
    }

    public function testInvalidECHashAlgo()
    {
        $crypto_algo = new ECPublicKeyAlgorithmIdentifier(
            ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1);
        $hash_algo = new SignatureFactoryTest_InvalidHashAlgo();
        $this->expectException(\UnexpectedValueException::class);
        SignatureAlgorithmIdentifierFactory::algoForAsymmetricCrypto(
            $crypto_algo, $hash_algo);
    }
}

class SignatureFactoryTest_InvalidCryptoAlgo extends SpecificAlgorithmIdentifier implements AsymmetricCryptoAlgorithmIdentifier
{
    public function __construct()
    {
        $this->_oid = '1.3.6.1.3';
    }

    public function name(): string
    {
        return 'test';
    }

    protected function _paramsASN1(): ?Element
    {
        return null;
    }
}

class SignatureFactoryTest_InvalidHashAlgo extends SpecificAlgorithmIdentifier implements HashAlgorithmIdentifier
{
    public function __construct()
    {
        $this->_oid = '1.3.6.1.3';
    }

    public function name(): string
    {
        return 'test';
    }

    protected function _paramsASN1(): ?Element
    {
        return null;
    }
}
