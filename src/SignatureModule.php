<?php

/**
 * @copyright Copyright (c) 2026 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Dss;

use Psr\Http\Client\ClientExceptionInterface;
use setasign\SetaPDF2\Core\Reader\FilePath;
use setasign\SetaPDF2\Core\Type\PdfHexString;
use setasign\SetaPDF2\Signer\Asn1\Exception;
use setasign\SetaPDF2\Signer\Ocsp\Response as OcspResponse;
use setasign\SetaPDF2\Signer\Signature\Module\DictionaryInterface;
use setasign\SetaPDF2\Signer\Signature\Module\DocumentInterface;
use setasign\SetaPDF2\Signer\Signature\Module\ModuleInterface;
use setasign\SetaPDF2\Signer\Signature\Module\PadesProxyTrait;
use setasign\SetaPDF2\Signer\Signer;
use setasign\SetaPDF2\Signer\ValidationRelatedInfo\CertificateResult;
use setasign\SetaPDF2\Signer\ValidationRelatedInfo\Result;
use setasign\SetaPDF2\Signer\X509\Certificate;

/**
 * The signature module for the SetaPDF-Signer component
 */
class SignatureModule implements
    ModuleInterface,
    DictionaryInterface,
    DocumentInterface
{
    use PadesProxyTrait;

    protected Client $client;
    protected Identity $identity;
    protected bool $addRevocationInfo = true;

    /**
     * @var string[]
     */
    protected array $trustchain = [];

    /**
     * @var string[]
     */
    protected array $ocspResponses = [];

    /**
     * The constructor.
     *
     * @param Signer $signer The main signer instance (used to disable the automatic change of the signature
     *                                length)
     * @param Client $client A REST client instance
     * @param Identity $identity The identity object
     */
    public function __construct(
        Signer $signer,
        Client $client,
        Identity $identity
    ) {
        $signer->setAllowSignatureContentLengthChange(false);

        $this->client = $client;
        $this->identity = $identity;
    }

    /**
     * @return string
     */
    public function getCertificate(): string
    {
        return $this->identity->getSigningCertificate();
    }

    /**
     * Define whether to add revocation information to the CMS container or not (default = true).
     *
     * @param bool $addRevocationInfo
     */
    public function setAddRevocationInfo(bool $addRevocationInfo)
    {
        $this->addRevocationInfo = $addRevocationInfo;
    }

    /**
     * @return string[]
     */
    public function getTrustchain(): array
    {
        return $this->trustchain;
    }

    /**
     * @return string[]
     */
    public function getOcspResponses(): array
    {
        return $this->ocspResponses;
    }

    /**
     * Get a complete VRI result object for further passing to the Document Security Store.
     *
     * @return Result
     * @throws Exception
     * @throws \setasign\SetaPDF2\Signer\Exception
     */
    public function getVerificationRelatedInformation(): Result
    {
        $result = new Result();

        $certificates = [$this->getCertificate()];
        foreach ($this->getTrustchain() as $certificate) {
            $certificates[] = $certificate;
        }
        $ocspResponses = $this->getOcspResponses();

        foreach ($certificates as $no => $certificate) {
            $certificate = new Certificate($certificate);
            $ocspResponse = null;
            if (isset($ocspResponses[$no])) {
                $ocspResponse = new OcspResponse($ocspResponses[$no]);
                foreach ($ocspResponse->getCertificates()->getAll() as $ocspCertificate) {
                    $result->add(new CertificateResult($ocspCertificate));
                }
            }

            $result->add(new CertificateResult($certificate, $ocspResponse));
        }

        return $result;
    }

    /**
     * Create a signature for the file in the given $tmpPath.
     *
     * @param FilePath $tmpPath
     * @return string
     * @throws ClientExceptionInterface
     * @throws Exception
     * @throws \setasign\SetaPDF2\Signer\Exception
     */
    public function createSignature(FilePath $tmpPath): string
    {
        $this->setCertificate($this->identity->getSigningCertificate());
        $trustchainResponse = $this->client->getTrustchain();
        $this->trustchain = $trustchainResponse['trustchain'];
        $this->setExtraCertificates($trustchainResponse['trustchain']);

        $this->ocspResponses = [
            \base64_decode($this->identity->getOcspResponse())
        ];
        foreach ($trustchainResponse['ocsp_revocation_info'] as $ocspRevocationInfo) {
            $this->ocspResponses[] = \base64_decode($ocspRevocationInfo);
        }

        if ($this->addRevocationInfo) {
            foreach ($this->ocspResponses as $ocspResponse) {
                $this->addOcspResponse($ocspResponse);
            }
        }

        $padesModule = $this->_getPadesModule();
        $hash = \hash('sha256', $padesModule->getDataToSign($tmpPath));
        $signature = $this->client->sign($this->identity, $hash);

        $padesModule->setSignatureValue(PdfHexString::hex2str($signature));

        return (string) $this->getCms();
    }
}
