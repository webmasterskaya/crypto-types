<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\BitString;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\Signature\GenericSignature;

/**
 * @group signature
 *
 * @internal
 */
class GenericSignatureTest extends TestCase
{
    /**
     * @return GenericSignature
     */
    public function testCreate()
    {
        $sig = new GenericSignature(new BitString('test'),
            new SHA1WithRSAEncryptionAlgorithmIdentifier());
        $this->assertInstanceOf(GenericSignature::class, $sig);
        return $sig;
    }

    /**
     * @depends testCreate
     *
     * @param GenericSignature $sig
     */
    public function testBitString(GenericSignature $sig)
    {
        $this->assertInstanceOf(BitString::class, $sig->bitString());
    }

    /**
     * @depends testCreate
     *
     * @param GenericSignature $sig
     */
    public function testSignatureAlgorithm(GenericSignature $sig)
    {
        $this->assertInstanceOf(AlgorithmIdentifier::class,
            $sig->signatureAlgorithm());
    }
}
