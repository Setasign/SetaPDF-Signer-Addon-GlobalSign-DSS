<?php

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Dss\tests\functional;

use PHPUnit\Framework\AssertionFailedError;
use setasign\SetaPDF\Signer\Module\GlobalSign\Dss\SignatureModule;
use setasign\SetaPDF\Signer\Module\GlobalSign\Dss\TimestampModule;

class SignatureModuleTest extends TestHelper
{
    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \SetaPDF_Signer_Exception
     */
    public function testSimpleSignature()
    {
        $writer = new \SetaPDF_Core_Writer_TempFile();
        $document = \SetaPDF_Core_Document::loadByFilename(__DIR__ . '/../_files/Laboratory-Report.pdf', $writer);

        $signer = new \SetaPDF_Signer($document);
        $signer->setSignatureContentLength(14000);
        $field = $signer->getSignatureField();

        $client = $this->getClientInstance();
        $identity = $client->getIdentity();
        $pades = new \SetaPDF_Signer_Signature_Module_Pades();
        $module = new SignatureModule($signer, $client, $identity, $pades);

        $signer->sign($module);

//        copy($writer->getPath(), 'signed.pdf');

        $this->assertTrue(
            $this->validate($writer->getPath(), $field->getQualifiedName(), $identity->getSigningCertificate())
        );
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \SetaPDF_Signer_Exception
     */
    public function testSignatureIncudingTimestamp()
    {
        $writer = new \SetaPDF_Core_Writer_TempFile();
        $document = \SetaPDF_Core_Document::loadByFilename(__DIR__ . '/../_files/Laboratory-Report.pdf', $writer);

        $signer = new \SetaPDF_Signer($document);
        $signer->setSignatureContentLength(15000);
        $field = $signer->getSignatureField();

        $client = $this->getClientInstance();

        $module = new TimestampModule($client);
        $signer->setTimestampModule($module);

        $identity = $client->getIdentity();
        $pades = new \SetaPDF_Signer_Signature_Module_Pades();
        $module = new SignatureModule($signer, $client, $identity, $pades);

        $signer->sign($module);

//        copy($writer->getPath(), 'signed-and-timestamped.pdf');

        $this->assertTrue(
            $this->validate($writer->getPath(), $field->getQualifiedName(), $identity->getSigningCertificate())
        );
    }

    public function testVisibleSignature()
    {
        $writer = new \SetaPDF_Core_Writer_TempFile();
        $document = \SetaPDF_Core_Document::loadByFilename(__DIR__ . '/../_files/Laboratory-Report.pdf', $writer);

        $signer = new \SetaPDF_Signer($document);
        $signer->setSignatureContentLength(15000);

        $client = $this->getClientInstance();
        $identity = $client->getIdentity();

        $pades = new \SetaPDF_Signer_Signature_Module_Pades();
        $module = new SignatureModule($signer, $client, $identity, $pades);

        $appearance = new \SetaPDF_Signer_Signature_Appearance_Dynamic($module);
        $signer->setAppearance($appearance);

        $field = $signer->addSignatureField(
            'Signature',
            1,
            \SetaPDF_Signer_SignatureField::POSITION_LEFT_TOP,
            ['x' => 10, 'y' => -10],
            150,
            60
        );
        $signer->setSignatureFieldName($field->getQualifiedName());

        $signer->sign($module);

//        copy($writer->getPath(), 'visible-signature.pdf');

        $this->assertTrue(
            $this->validate($writer->getPath(), $field->getQualifiedName(), $identity->getSigningCertificate())
        );

        $document = \SetaPDF_Core_Document::loadByFilename($writer->getPath());

        $field = \SetaPDF_Signer_SignatureField::get($document, 'Signature', false);
        $this->assertInstanceOf(\SetaPDF_Signer_SignatureField::class, $field);

        $dict = $field->getDictionary();
        /** @var \SetaPDF_Core_Type_Stream $n2 */
        $n2 = $dict->getValue('AP')->getValue('N')->ensure()->getValue()->getValue('Resources')->getValue('XObject')
            ->getValue('FRM')->ensure()->getValue()->getValue('Resources')->getValue('XObject')->getValue('n2')
            ->ensure();

        $this->assertNotFalse(strpos($n2->getStream(), 'Digitally signed by'));
    }

    protected function getSignatureDetails($path, $signatureFieldName)
    {
        $signatureFieldName = \SetaPDF_Core_Encoding::convertPdfString($signatureFieldName);
        $reader = new \SetaPDF_Core_Reader_File($path);
        $document = \SetaPDF_Core_Document::load($reader);

        $terminalFields = $document->getCatalog()->getAcroForm()->getTerminalFieldsObjects();

        $found = false;
        foreach ($terminalFields AS $fieldData) {
            /** @var \SetaPDF_Core_Type_Dictionary $fieldData */
            $fieldData = $fieldData->ensure();
            $ft = \SetaPDF_Core_Type_Dictionary_Helper::resolveAttribute($fieldData, 'FT');
            if (!$ft || $ft->getValue() !== 'Sig') {
                continue;
            }

            $name = \SetaPDF_Core_Document_Catalog_AcroForm::resolveFieldName($fieldData);
            $name = \SetaPDF_Core_Encoding::convertPdfString($name);

            if ($name === $signatureFieldName) {
                $found = true;
                break;
            }
        }

        if (!$found) {
            throw new AssertionFailedError('No field with name "' . $signatureFieldName . '" found.');
        }

        $v = \SetaPDF_Core_Type_Dictionary_Helper::resolveAttribute($fieldData, 'V');
        if (!$v || !$v->ensure() instanceof \SetaPDF_Core_Type_Dictionary) {
            throw new AssertionFailedError('The field "' . $signatureFieldName . '" is not signed.');
        }

        /** @var \SetaPDF_Core_Type_Dictionary $v */
        $v = $v->ensure();

        $byteRange = $v->offsetGet('ByteRange')->ensure()->toPhp();

        $tmpFile = new \SetaPDF_Core_Writer_TempFile();
        $tmpFile->start();
        $reader->reset($byteRange[0], $byteRange[1]);
        $tmpFile->write($reader->readBytes($byteRange[1]));
        $reader->reset($byteRange[2], $byteRange[3]);
        $tmpFile->write($reader->readBytes($byteRange[3]));
        $tmpFile->finish();

        $content = $v->offsetGet('Contents')->ensure()->getValue();
        $asn1 = \SetaPDF_Signer_Asn1_Element::parse($content);

        return array(
            $tmpFile,
            $asn1,
            $v,
            $document
        );
    }

    protected function validate($path, $signatureFieldName, $certificate)
    {
        list($tmpFile, $asn1) = $this->getSignatureDetails($path, $signatureFieldName);

        $contentType = $asn1->getChild(0)->getValue();
        $contentType = \SetaPDF_Signer_Asn1_Oid::decode($contentType);
        $this->assertEquals('1.2.840.113549.1.7.2', $contentType);

        /** @var \SetaPDF_Signer_Asn1_Element $content */
        $content = $asn1->getChild(1);
        $signedData = $content->getChild(0);

        $digestAlgorithms = $signedData->getChild(1);
        $hashes = array();
        foreach ($digestAlgorithms->getChildren() AS $algorithm) {
            $algorithmOid = \SetaPDF_Signer_Asn1_Oid::decode($algorithm->getChild(0)->getValue());
            $digest = \SetaPDF_Signer_Digest::getByOid($algorithmOid);
            $hashes[$digest] = hash_file($digest, $tmpFile->getPath(), true);
        }

        // ensure that no eContent is used
        $encapContentInfo = $signedData->getChild(2);
        $this->assertEquals(1, $encapContentInfo->getChildCount());

        $signerInfos = $signedData->getChild($signedData->getChildCount() - 1);
        // only one SignerInfo
        $this->assertEquals(1, $signerInfos->getChildCount());
        $signerInfo = $signerInfos->getChild(0);
        // get digest algo and check if it was defined in digestAlgorithms
        $digestAlgorithmOid = \SetaPDF_Signer_Asn1_Oid::decode($signerInfo->getChild(2)->getChild(0)->getValue());
        $digest = \SetaPDF_Signer_Digest::getByOid($digestAlgorithmOid);
        $this->assertTrue(isset($hashes[$digest]));

        // Check for signed attributes
        if ($signerInfo->getChild(3)->getIdent() === "\xA0") { // [0] IMPLICIT
            $_signedAttributes = $signerInfo->getChild(3)->getChildren();
            $signedAttributes = array();
            foreach ($_signedAttributes AS $attribute) {
                $attrType = $attribute->getChild(0)->getValue();
                $attrTypeOid = \SetaPDF_Signer_Asn1_Oid::decode($attrType);
                $signedAttributes[$attrTypeOid] = $attribute->getChild(1);
            }

            // check for mandatory attributes
            $this->assertTrue(isset($signedAttributes['1.2.840.113549.1.9.3'])); // content-type
            $this->assertTrue(isset($signedAttributes['1.2.840.113549.1.9.4'])); // message-digest

            // hashes match?
            $this->assertEquals($hashes[$digest], $signedAttributes['1.2.840.113549.1.9.4']->getChild(0)->getValue());

            $data = $signerInfo->getChild(3)->__toString();
            $data[0] = \SetaPDF_Signer_Asn1_Element::SET | \SetaPDF_Signer_Asn1_Element::IS_CONSTRUCTED;
            $signatureValue = $signerInfo->getChild(5)->getValue();

        } else {
            $data = file_get_contents($tmpFile->getPath());
            $signatureValue = $signerInfo->getChild(4)->getValue();
        }

        while (\openssl_error_string());

        $pkey = \openssl_pkey_get_public($certificate);
        $res = \openssl_verify($data, $signatureValue, $pkey, \SetaPDF_Signer_Digest::getOpenSslInt($digest));
        $this->assertEquals(1, $res, openssl_error_string());

        return true;
    }
}