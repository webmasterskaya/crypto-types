<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\CryptoEncoding\PEM;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\Asymmetric\EC\ECPublicKey;
use Webmasterskaya\CryptoTypes\Asymmetric\PublicKeyInfo;
use Webmasterskaya\CryptoTypes\Asymmetric\RSA\RSAPublicKey;

/**
 * @group asn1
 * @group publickey
 *
 * @internal
 */
class PublicKeyInfoTest extends TestCase
{
    /**
     * @return PublicKeyInfo
     */
    public function testDecodeRSA()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        $pki = PublicKeyInfo::fromDER($pem->data());
        $this->assertInstanceOf(PublicKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends testDecodeRSA
     *
     * @param PublicKeyInfo $pki
     */
    public function testAlgoObj(PublicKeyInfo $pki)
    {
        $ref = new RSAEncryptionAlgorithmIdentifier();
        $algo = $pki->algorithmIdentifier();
        $this->assertEquals($ref, $algo);
        return $algo;
    }

    /**
     * @depends testAlgoObj
     *
     * @param AlgorithmIdentifier $algo
     */
    public function testAlgoOID(AlgorithmIdentifier $algo)
    {
        $this->assertEquals(AlgorithmIdentifier::OID_RSA_ENCRYPTION,
            $algo->oid());
    }

    /**
     * @depends testDecodeRSA
     *
     * @param PublicKeyInfo $pki
     */
    public function testGetRSAPublicKey(PublicKeyInfo $pki)
    {
        $pk = $pki->publicKey();
        $this->assertInstanceOf(RSAPublicKey::class, $pk);
    }

    /**
     * @return PublicKeyInfo
     */
    public function testDecodeEC()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/ec/public_key.pem');
        $pki = PublicKeyInfo::fromDER($pem->data());
        $this->assertInstanceOf(PublicKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends testDecodeEC
     *
     * @param PublicKeyInfo $pki
     */
    public function testGetECPublicKey(PublicKeyInfo $pki)
    {
        $pk = $pki->publicKey();
        $this->assertInstanceOf(ECPublicKey::class, $pk);
    }

    /**
     * @return PublicKeyInfo
     */
    public function testFromRSAPEM()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        $pki = PublicKeyInfo::fromPEM($pem);
        $this->assertInstanceOf(PublicKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends testFromRSAPEM
     *
     * @param PublicKeyInfo $pki
     */
    public function testToPEM(PublicKeyInfo $pki)
    {
        $pem = $pki->toPEM();
        $this->assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    /**
     * @depends testToPEM
     *
     * @param PEM $pem
     */
    public function testRecodedPEM(PEM $pem)
    {
        $ref = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem');
        $this->assertEquals($ref, $pem);
    }

    public function testDecodeFromRSAPublicKey()
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/rsa/rsa_public_key.pem');
        $pki = PublicKeyInfo::fromPEM($pem);
        $this->assertInstanceOf(PublicKeyInfo::class, $pki);
    }

    /**
     * @depends testDecodeRSA
     *
     * @param PublicKeyInfo $pki
     */
    public function testKeyIdentifier(PublicKeyInfo $pki)
    {
        $id = $pki->keyIdentifier();
        $this->assertEquals(160, strlen($id) * 8);
    }

    /**
     * @depends testDecodeRSA
     *
     * @param PublicKeyInfo $pki
     */
    public function testKeyIdentifier64(PublicKeyInfo $pki)
    {
        $id = $pki->keyIdentifier64();
        $this->assertEquals(64, strlen($id) * 8);
    }

    public function testInvalidPEMType()
    {
        $pem = new PEM('nope', '');
        $this->expectException(\UnexpectedValueException::class);
        PublicKeyInfo::fromPEM($pem);
    }

    /**
     * @depends testDecodeRSA
     *
     * @param PublicKeyInfo $pki
     */
    public function testInvalidAI(PublicKeyInfo $pki)
    {
        $seq = $pki->toASN1();
        $ai = $seq->at(0)->asSequence()
            ->withReplaced(0, new ObjectIdentifier('1.3.6.1.3'));
        $seq = $seq->withReplaced(0, $ai);
        $this->expectException(\RuntimeException::class);
        PublicKeyInfo::fromASN1($seq)->publicKey();
    }

    public function testInvalidECAlgoFail()
    {
        $pki = new PublicKeyInfo(new PubliceKeyInfoTest_InvalidECAlgo(), '');
        $this->expectException(\UnexpectedValueException::class);
        $pki->publicKey();
    }
}

class PubliceKeyInfoTest_InvalidECAlgo extends SpecificAlgorithmIdentifier
{
    public function __construct()
    {
        $this->_oid = self::OID_EC_PUBLIC_KEY;
    }

    public function name(): string
    {
        return '';
    }

    protected function _paramsASN1(): ?Element
    {
        return null;
    }
}
