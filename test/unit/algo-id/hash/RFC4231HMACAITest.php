<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Boolean;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA256AlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class RFC4231HMACAITest extends TestCase
{
    public function testDecodeWithParams()
    {
        $seq = new Sequence(
            new ObjectIdentifier(AlgorithmIdentifier::OID_HMAC_WITH_SHA256),
            new NullType());
        $ai = AlgorithmIdentifier::fromASN1($seq);
        $this->assertInstanceOf(HMACWithSHA256AlgorithmIdentifier::class, $ai);
    }

    public function testDecodeWithInvalidParamsFail()
    {
        $seq = new Sequence(
            new ObjectIdentifier(AlgorithmIdentifier::OID_HMAC_WITH_SHA256),
            new Boolean(true));
        $this->expectException(\UnexpectedValueException::class);
        AlgorithmIdentifier::fromASN1($seq);
    }
}
