<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\NullType;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Hash\SHA224AlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class SHA224AITest extends TestCase
{
    /**
     * @return Sequence
     */
    public function testEncode()
    {
        $ai = new SHA224AlgorithmIdentifier();
        $seq = $ai->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq;
    }

    /**
     * @depends testEncode
     *
     * @param Sequence $seq
     */
    public function testDecode(Sequence $seq)
    {
        $ai = AlgorithmIdentifier::fromASN1($seq);
        $this->assertInstanceOf(SHA224AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends testEncode
     *
     * @param Sequence $seq
     */
    public function testDecodeWithParams(Sequence $seq)
    {
        $seq = $seq->withInserted(1, new NullType());
        $ai = AlgorithmIdentifier::fromASN1($seq);
        $this->assertInstanceOf(SHA224AlgorithmIdentifier::class, $ai);
    }

    /**
     * @depends testDecode
     *
     * @param AlgorithmIdentifier $algo
     */
    public function testName(AlgorithmIdentifier $algo)
    {
        $this->assertIsString($algo->name());
    }
}
