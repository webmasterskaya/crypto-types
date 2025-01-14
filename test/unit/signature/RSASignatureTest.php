<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Primitive\BitString;
use Webmasterskaya\CryptoTypes\Signature\RSASignature;

/**
 * @group signature
 *
 * @internal
 */
class RSASignatureTest extends TestCase
{
    /**
     * @return RSASignature
     */
    public function testFromSignatureString()
    {
        $sig = RSASignature::fromSignatureString('test');
        $this->assertInstanceOf(RSASignature::class, $sig);
        return $sig;
    }

    /**
     * @depends testFromSignatureString
     *
     * @param RSASignature $sig
     */
    public function testBitString(RSASignature $sig)
    {
        $this->assertInstanceOf(BitString::class, $sig->bitString());
    }
}
