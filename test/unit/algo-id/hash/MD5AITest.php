<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Hash\MD5AlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class MD5AITest extends TestCase
{
    /**
     * @return Sequence
     */
    public function testEncode()
    {
        $ai = new MD5AlgorithmIdentifier();
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
        $this->assertInstanceOf(MD5AlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends testEncode
     *
     * @param Sequence $seq
     */
    public function testDecodeWithoutParams(Sequence $seq)
    {
        $seq = $seq->withoutElement(1);
        $ai = AlgorithmIdentifier::fromASN1($seq);
        $this->assertInstanceOf(MD5AlgorithmIdentifier::class, $ai);
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
