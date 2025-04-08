<?php

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Dss\tests\functional;

use PHPUnit\Framework\AssertionFailedError;
use setasign\SetaPDF\Signer\Module\GlobalSign\Dss\SignatureModule;
use setasign\SetaPDF\Signer\Module\GlobalSign\Dss\TimestampModule;

class SignatureModuleTest extends TestHelper
{
    /**
     * @throws \Throwable
     */
    public function testSimpleSignature()
    {
        $writer = new \SetaPDF_Core_Writer_TempFile();
        $document = \SetaPDF_Core_Document::loadByFilename(__DIR__ . '/../_files/Laboratory-Report.pdf', $writer);

        $signer = new \SetaPDF_Signer($document);
        $signer->setSignatureContentLength(25000);
        $field = $signer->getSignatureField();

        $client = $this->getClientInstance();
        $identity = $client->getIdentity([
            'subject_dn' => [
                'common_name' => "Test"
            ]
        ]);
        $pades = new \SetaPDF_Signer_Signature_Module_Pades();
        $module = new SignatureModule($signer, $client, $identity, $pades);

        $signer->sign($module);

//        copy($writer->getPath(), 'signed.pdf');

        $this->assertTrue(
            $this->validate($writer->getPath(), $field->getQualifiedName(), $identity->getSigningCertificate())
        );
    }

    /**
     * @throws \Throwable
     */
    public function testSignatureIncudingTimestamp()
    {
        $writer = new \SetaPDF_Core_Writer_TempFile();
        $document = \SetaPDF_Core_Document::loadByFilename(__DIR__ . '/../_files/Laboratory-Report.pdf', $writer);

        $signer = new \SetaPDF_Signer($document);
        $signer->setSignatureContentLength(30000);
        $field = $signer->getSignatureField();

        $client = $this->getClientInstance();

        $module = new TimestampModule($client);
        $signer->setTimestampModule($module);

        $identity = $client->getIdentity([
            'subject_dn' => [
                'common_name' => "Test"
            ]
        ]);
        $pades = new \SetaPDF_Signer_Signature_Module_Pades();
        $module = new SignatureModule($signer, $client, $identity, $pades);

        $signer->sign($module);

        copy($writer->getPath(), 'signed-and-timestamped.pdf');

        $this->assertTrue(
            $this->validate($writer->getPath(), $field->getQualifiedName(), $identity->getSigningCertificate())
        );
    }

    /**
     * @throws \Throwable
     */
    public function testVisibleSignature()
    {
        $writer = new \SetaPDF_Core_Writer_TempFile();
        $document = \SetaPDF_Core_Document::loadByFilename(__DIR__ . '/../_files/Laboratory-Report.pdf', $writer);

        $signer = new \SetaPDF_Signer($document);
        $signer->setSignatureContentLength(25000);

        $client = $this->getClientInstance();
        $identity = $client->getIdentity([
            'subject_dn' => [
                'common_name' => "Test"
            ]
        ]);

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

        return [
            $tmpFile,
            $asn1,
            $v,
            $document
        ];
    }

    protected function validate($path, $signatureFieldName, $certificate)
    {
        $document = \SetaPDF_Core_Document::loadByFilename($path);

        $integrityResult = \SetaPDF_Signer_ValidationRelatedInfo_IntegrityResult::create($document, $signatureFieldName);

        $signingCert = $integrityResult->getSignedData()->getSigningCertificate();

        return $integrityResult->isValid() &&
            (new \SetaPDF_Signer_X509_Certificate($certificate))->get() === $signingCert->get();
    }
}
