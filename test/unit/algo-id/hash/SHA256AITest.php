<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Hash\SHA256AlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class SHA256AITest extends TestCase
{
    /**
     * @return Sequence
     */
    public function testEncode()
    {
        $ai = new SHA256AlgorithmIdentifier();
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
        $this->assertInstanceOf(SHA256AlgorithmIdentifier::class, $ai);
        return $ai;
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
