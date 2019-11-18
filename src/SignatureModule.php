<?php
/**
 * @copyright Copyright (c) 2019 Setasign - Jan Slabon (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Dss;

/**
 * The signature module for the SetaPDF-Signer component
 */
class SignatureModule implements
    \SetaPDF_Signer_Signature_Module_ModuleInterface,
    \SetaPDF_Signer_Signature_DictionaryInterface,
    \SetaPDF_Signer_Signature_DocumentInterface
{
    /**
     * @var Client
     */
    protected $client;

    /**
     * @var \SetaPDF_Signer_Signature_Module_Cms
     */
    protected $module;

    /**
     * @var Identity
     */
    protected $identity;

    /**
     * The constructor.
     *
     * @param \SetaPDF_Signer $signer The main signer instance (used to disable the automatic change of the signature
     *                                length)
     * @param Client $client A REST client instance
     * @param Identity $identity The identity object
     * @param \SetaPDF_Signer_Signature_Module_Cms $module An outer signature module instance which is used for CMS
     *                                                     creation while the signature value is created and set by this
     *                                                     class.
     */
    public function __construct(
        \SetaPDF_Signer $signer,
        Client $client,
        Identity $identity,
        \SetaPDF_Signer_Signature_Module_Cms $module)
    {
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
     * Create a signature for the file in the given $tmpPath.
     *
     * @param \SetaPDF_Core_Reader_FilePath $tmpPath
     * @return string
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \SetaPDF_Signer_Exception
     */
    public function createSignature(\SetaPDF_Core_Reader_FilePath $tmpPath): string
    {
        $this->module->setCertificate($this->identity->getSigningCertificate());
        $trustChain = $this->client->getTrustchain();
        $this->module->setExtraCertificates($trustChain->trustchain);

        $this->module->addOcspResponse(\base64_decode($this->identity->getOcspResponse()));
        foreach ($trustChain->ocsp_revocation_info as $ocspRevocationInfo) {
            $this->module->addOcspResponse(\base64_decode($ocspRevocationInfo));
        }

        $hash = \hash('sha256', $this->module->getDataToSign($tmpPath));
        $signature = $this->client->sign($this->identity, $hash);

        $this->module->setSignatureValue(\SetaPDF_Core_Type_HexString::hex2str($signature));

        return (string)$this->module->getCms();
    }

    /**
     * Method to update the signature dictionary.
     *
     * @param \SetaPDF_Core_Type_Dictionary $dictionary
     */
    public function updateSignatureDictionary(\SetaPDF_Core_Type_Dictionary $dictionary)
    {
        if ($this->module instanceof \SetaPDF_Signer_Signature_DictionaryInterface) {
            $this->module->updateSignatureDictionary($dictionary);
        }
    }

    /**
     * Method to allow updates onto the document instance.
     *
     * @param \SetaPDF_Core_Document $document
     */
    public function updateDocument(\SetaPDF_Core_Document $document)
    {
        if ($this->module instanceof \SetaPDF_Signer_Signature_DocumentInterface) {
            $this->module->updateDocument($document);
        }
    }
}