<?php

/**
 * @copyright Copyright (c) 2026 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Dss;

use Psr\Http\Client\ClientExceptionInterface;
use setasign\SetaPDF2\Core\Document;
use setasign\SetaPDF2\Core\Reader\FilePath;
use setasign\SetaPDF2\Core\Type\PdfDictionary;
use setasign\SetaPDF2\Core\Type\PdfHexString;
use setasign\SetaPDF2\Signer\Asn1\Exception;
use setasign\SetaPDF2\Signer\Signature\Module\Cms;
use setasign\SetaPDF2\Signer\Signature\Module\DictionaryInterface;
use setasign\SetaPDF2\Signer\Signature\Module\DocumentInterface;
use setasign\SetaPDF2\Signer\Signature\Module\ModuleInterface;
use setasign\SetaPDF2\Signer\Signer;

/**
 * The signature module for the SetaPDF-Signer component
 */
class SignatureModule implements
    ModuleInterface,
    DictionaryInterface,
    DocumentInterface
{
    /**
     * @var Client
     */
    protected $client;

    /**
     * @var Cms
     */
    protected $module;

    /**
     * @var Identity
     */
    protected $identity;

    /**
     * @var bool
     */
    protected $addRevocationInfo = true;

    /**
     * @var null|string[]
     */
    protected $trustchain;

    /**
     * @var null|string[]
     */
    protected $ocspResponses;

    /**
     * The constructor.
     *
     * @param Signer $signer The main signer instance (used to disable the automatic change of the signature
     *                                length)
     * @param Client $client A REST client instance
     * @param Identity $identity The identity object
     * @param Cms $module An outer signature module instance which is used for CMS
     *                    creation while the signature value is created and set by this
     *                    class.
     */
    public function __construct(
        Signer $signer,
        Client $client,
        Identity $identity,
        Cms $module
    ) {
        $signer->setAllowSignatureContentLengthChange(false);

        $this->client = $client;
        $this->identity = $identity;
        $this->module = $module;
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

    public function getTrustchain(): array
    {
        return $this->trustchain;
    }

    public function getOcspResponses(): array
    {
        return $this->ocspResponses;
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
        $this->module->setCertificate($this->identity->getSigningCertificate());
        $trustchainResponse = $this->client->getTrustchain();
        $this->trustchain = $trustchainResponse['trustchain'];
        $this->module->setExtraCertificates($trustchainResponse['trustchain']);

        $this->ocspResponses = [
            \base64_decode($this->identity->getOcspResponse())
        ];
        foreach ($trustchainResponse['ocsp_revocation_info'] as $ocspRevocationInfo) {
            $this->ocspResponses[] = \base64_decode($ocspRevocationInfo);
        }

        if ($this->addRevocationInfo) {
            foreach ($this->ocspResponses as $ocspResponse) {
                $this->module->addOcspResponse($ocspResponse);
            }
        }

        $hash = \hash('sha256', $this->module->getDataToSign($tmpPath));
        $signature = $this->client->sign($this->identity, $hash);

        $this->module->setSignatureValue(PdfHexString::hex2str($signature));

        return (string) $this->module->getCms();
    }

    /**
     * Method to update the signature dictionary.
     *
     * @param PdfDictionary $dictionary
     */
    public function updateSignatureDictionary(PdfDictionary $dictionary)
    {
        if ($this->module instanceof DictionaryInterface) {
            $this->module->updateSignatureDictionary($dictionary);
        }
    }

    /**
     * Method to allow updates onto the document instance.
     *
     * @param Document $document
     */
    public function updateDocument(Document $document)
    {
        if ($this->module instanceof DocumentInterface) {
            $this->module->updateDocument($document);
        }
    }
}
