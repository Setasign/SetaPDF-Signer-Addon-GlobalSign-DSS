<?php
/**
 * @copyright Copyright (c) 2018 Setasign - Jan Slabon (https://www.setasign.com)
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
    public function getCertificate()
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
        $this->module->setExtraCertificates([$this->client->getCertificatePath()]);

        // For backwards compatibility
        if (method_exists($this->module, 'setOcspResponse')) {
            $this->module->setOcspResponse($this->identity->getOcspResponse());
        } else {
            $this->addOcspResponse();
        }

        $hash = \hash('sha256', $this->module->getDataToSign($tmpPath));
        $signature = $this->client->sign($this->identity, $hash);

        $this->module->setSignatureValue(\SetaPDF_Core_Type_HexString::hex2str($signature));

        return (string)$this->module->getCms();
    }

    /**
     * Adds the OCSP response as a signed attribute in the CMS container.
     */
    protected function addOcspResponse(): void
    {
        $cms = $this->module->getCms();
        $signerInfos = \SetaPDF_Signer_Asn1_Element::findByPath('1/0/4', $cms);
        if (($signerInfos->getIdent() & "\xA1") === "\xA1") {
            $signerInfos = \SetaPDF_Signer_Asn1_Element::findByPath('1/0/5', $cms);
        }

        $signedAttributes = \SetaPDF_Signer_Asn1_Element::findByPath('0/3', $signerInfos);
        $signedAttributes->addChild(new \SetaPDF_Signer_Asn1_Element(
            \SetaPDF_Signer_Asn1_Element::SEQUENCE | \SetaPDF_Signer_Asn1_Element::IS_CONSTRUCTED, '',
            array(
                new \SetaPDF_Signer_Asn1_Element(
                    \SetaPDF_Signer_Asn1_Element::OBJECT_IDENTIFIER,
                    \SetaPDF_Signer_Asn1_Oid::encode('1.2.840.113583.1.1.8')
                ),
                new \SetaPDF_Signer_Asn1_Element(
                    \SetaPDF_Signer_Asn1_Element::SET | \SetaPDF_Signer_Asn1_Element::IS_CONSTRUCTED, '',
                    array(
                        /**
                         * RevocationInfoArchival ::= SEQUENCE {
                         *   crl [0] EXPLICIT SEQUENCE of CRLs, OPTIONAL
                         *   ocsp [1] EXPLICIT SEQUENCE of OCSP Responses, OPTIONAL
                         *   otherRevInfo [2] EXPLICIT SEQUENCE of OtherRevInfo, OPTIONAL
                         * }
                         */
                        new \SetaPDF_Signer_Asn1_Element(
                            \SetaPDF_Signer_Asn1_Element::SEQUENCE | \SetaPDF_Signer_Asn1_Element::IS_CONSTRUCTED, '',
                            array(
                                new \SetaPDF_Signer_Asn1_Element(
                                    \SetaPDF_Signer_Asn1_Element::TAG_CLASS_CONTEXT_SPECIFIC | \SetaPDF_Signer_Asn1_Element::IS_CONSTRUCTED | "\x01", '',
                                    array(
                                        new \SetaPDF_Signer_Asn1_Element(
                                            \SetaPDF_Signer_Asn1_Element::SEQUENCE | \SetaPDF_Signer_Asn1_Element::IS_CONSTRUCTED, '',
                                            array(
                                                \SetaPDF_Signer_Asn1_Element::parse(
                                                    \base64_decode($this->identity->getOcspResponse())
                                                )
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        ));
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