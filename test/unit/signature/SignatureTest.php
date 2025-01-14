<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA1AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\Signature\ECSignature;
use Webmasterskaya\CryptoTypes\Signature\GenericSignature;
use Webmasterskaya\CryptoTypes\Signature\RSASignature;
use Webmasterskaya\CryptoTypes\Signature\Signature;

/**
 * @group signature
 *
 * @internal
 */
class SignatureTest extends TestCase
{
    public function testFromRSAAlgo()
    {
        $sig = Signature::fromSignatureData('test',
            new SHA1WithRSAEncryptionAlgorithmIdentifier());
        $this->assertInstanceOf(RSASignature::class, $sig);
    }

    public function testFromECAlgo()
    {
        $seq = new Sequence(new Integer(1), new Integer(2));
        $sig = Signature::fromSignatureData($seq->toDER(),
            new ECDSAWithSHA1AlgorithmIdentifier());
        $this->assertInstanceOf(ECSignature::class, $sig);
    }

    public function testFromUnknownAlgo()
    {
        $sig = Signature::fromSignatureData('',
            new GenericAlgorithmIdentifier('1.3.6.1.3'));
        $this->assertInstanceOf(GenericSignature::class, $sig);
    }
}
