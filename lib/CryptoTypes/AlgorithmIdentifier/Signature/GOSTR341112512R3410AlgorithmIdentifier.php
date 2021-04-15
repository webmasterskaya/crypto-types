<?php

declare(strict_types = 1);

namespace Sop\CryptoTypes\AlgorithmIdentifier\Signature;

/**
 * RSA with GOSTR3411_2012_512 signature algorithm identifier.
 *
 * @see https://tools.ietf.org/html/rfc7836#section-4
 */
class GOSTR341112512R3410AlgorithmIdentifier extends RFC7836RSASignatureAlgorithmIdentifier
{
    /**
     * Constructor.
     */
    public function __construct()
    {
        parent::__construct();
        $this->_oid = self::OID_CP_GOST_R3411_12_512_R3410;
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'GOST_R3411_12_512_R3410';
    }
}
