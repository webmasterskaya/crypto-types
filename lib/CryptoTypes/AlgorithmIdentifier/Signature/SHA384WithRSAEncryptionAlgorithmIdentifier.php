<?php

namespace Sop\CryptoTypes\AlgorithmIdentifier\Signature;

/**
 * RSA with SHA-384 signature algorithm identifier.
 *
 * @link https://tools.ietf.org/html/rfc4055#section-5
 */
class SHA384WithRSAEncryptionAlgorithmIdentifier extends RFC4055RSASignatureAlgorithmIdentifier
{
    /**
     * Constructor.
     */
    public function __construct()
    {
        parent::__construct();
        $this->_oid = self::OID_SHA384_WITH_RSA_ENCRYPTION;
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function name()
    {
        return "sha384WithRSAEncryption";
    }
}