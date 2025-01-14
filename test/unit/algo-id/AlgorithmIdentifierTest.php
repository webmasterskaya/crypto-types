<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;

/**
 * @group asn1
 * @group algo-id
 *
 * @internal
 */
class AlgorithmIdentifierTest extends TestCase
{
    private static $_unknownASN1;

    public static function setUpBeforeClass(): void
    {
        self::$_unknownASN1 = new Sequence(
            new ObjectIdentifier('1.3.6.1.3', new NullType()));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_unknownASN1 = null;
    }

    /**
     * @return AlgorithmIdentifier
     */
    public function testFromUnknownASN1()
    {
        $ai = AlgorithmIdentifier::fromASN1(self::$_unknownASN1);
        $this->assertInstanceOf(GenericAlgorithmIdentifier::class, $ai);
        return $ai;
    }

    /**
     * @depends testFromUnknownASN1
     *
     * @param GenericAlgorithmIdentifier $ai
     */
    public function testEncodeUnknown(GenericAlgorithmIdentifier $ai)
    {
        $seq = $ai->toASN1();
        $this->assertEquals(self::$_unknownASN1, $seq);
    }

    public function testSpecificAlgoBadCall()
    {
        $this->expectException(\BadMethodCallException::class);
        SpecificAlgorithmIdentifier::fromASN1Params();
    }

    /**
     * @depends testFromUnknownASN1
     *
     * @param AlgorithmIdentifier $algo
     */
    public function testName(AlgorithmIdentifier $algo)
    {
        $this->assertIsString($algo->name());
    }
}
