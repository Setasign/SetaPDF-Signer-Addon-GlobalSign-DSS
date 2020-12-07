<?php

/**
 * @copyright Copyright (c) 2019 Setasign - Jan Slabon (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Dss;

/**
 * Class representing an identity
 */
class Identity
{
    /**
     * @var string
     */
    protected $id;

    /**
     * @var string
     */
    protected $signingCert;

    /**
     * @var string
     */
    protected $ocspResponse;

    /**
     * Identity constructor.
     *
     * @param string $id
     * @param string $signingCert
     * @param string $ocspResponse
     */
    public function __construct($id, $signingCert, $ocspResponse)
    {
        $this->id = $id;
        $this->signingCert = $signingCert;
        $this->ocspResponse = $ocspResponse;
    }

    /**
     * Get the id of the created identity.
     *
     * @return string
     */
    public function getId(): string
    {
        return $this->id;
    }

    /**
     * Get the PEM encoded X509 signing certificate.
     *
     * @return string
     */
    public function getSigningCertificate(): string
    {
        return $this->signingCert;
    }

    /**
     * Get the base64 encoded DER representation of the OCSP response for signing certificate.
     *
     * @return string
     */
    public function getOcspResponse(): string
    {
        return $this->ocspResponse;
    }
}
