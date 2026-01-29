<?php

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Dss\tests\functional;

use PHPUnit\Framework\AssertionFailedError;
use setasign\SetaPDF\Signer\Module\GlobalSign\Dss\SignatureModule;
use setasign\SetaPDF\Signer\Module\GlobalSign\Dss\TimestampModule;
use setasign\SetaPDF2\Core\Document;
use setasign\SetaPDF2\Core\Encoding\Encoding;
use setasign\SetaPDF2\Core\Reader\FileReader;
use setasign\SetaPDF2\Core\Type\Dictionary\DictionaryHelper;
use setasign\SetaPDF2\Core\Type\PdfArray;
use setasign\SetaPDF2\Core\Type\PdfDictionary;
use setasign\SetaPDF2\Core\Type\PdfStream;
use setasign\SetaPDF2\Core\Writer\TempFileWriter;
use setasign\SetaPDF2\Signer\Asn1\Element as Asn1Element;
use setasign\SetaPDF2\Signer\Signature\Appearance\Dynamic as DynamicAppearance;
use setasign\SetaPDF2\Signer\Signature\Module\Pades;
use setasign\SetaPDF2\Signer\SignatureField;
use setasign\SetaPDF2\Signer\Signer;
use setasign\SetaPDF2\Signer\ValidationRelatedInfo\IntegrityResult;
use setasign\SetaPDF2\Signer\X509\Certificate;

class SignatureModuleTest extends TestHelper
{
    /**
     * @throws \Throwable
     */
    public function testSimpleSignature()
    {
        $writer = new TempFileWriter();
        $document = Document::loadByFilename(__DIR__ . '/../_files/Laboratory-Report.pdf', $writer);

        $signer = new Signer($document);
        $signer->setSignatureContentLength(25000);
        $field = $signer->getSignatureField();

        $client = $this->getClientInstance();
        $identity = $client->getIdentity([
            'subject_dn' => [
                'common_name' => "Test"
            ]
        ]);
        $pades = new Pades();
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
        $writer = new TempFileWriter();
        $document = Document::loadByFilename(__DIR__ . '/../_files/Laboratory-Report.pdf', $writer);

        $signer = new Signer($document);
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
        $pades = new Pades();
        $module = new SignatureModule($signer, $client, $identity, $pades);

        $signer->sign($module);

//        \copy($writer->getPath(), 'signed-and-timestamped.pdf');

        $this->assertTrue(
            $this->validate($writer->getPath(), $field->getQualifiedName(), $identity->getSigningCertificate())
        );
    }

    /**
     * @throws \Throwable
     */
    public function testVisibleSignature()
    {
        $writer = new TempFileWriter();
        $document = Document::loadByFilename(__DIR__ . '/../_files/Laboratory-Report.pdf', $writer);

        $signer = new Signer($document);
        $signer->setSignatureContentLength(25000);

        $client = $this->getClientInstance();
        $identity = $client->getIdentity([
            'subject_dn' => [
                'common_name' => "Test"
            ]
        ]);

        $pades = new Pades();
        $module = new SignatureModule($signer, $client, $identity, $pades);

        $appearance = new DynamicAppearance($module);
        $signer->setAppearance($appearance);

        $field = $signer->addSignatureField(
            'Signature',
            1,
            SignatureField::POSITION_LEFT_TOP,
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

        $document = Document::loadByFilename($writer->getPath());

        $field = SignatureField::get($document, 'Signature', false);
        $this->assertInstanceOf(SignatureField::class, $field);

        $dict = $field->getDictionary();
        $n2 = PdfStream::ensureType(
            $dict->getValue('AP')->getValue('N')->ensure()->getValue()->getValue('Resources')->getValue('XObject')
            ->getValue('FRM')->ensure()->getValue()->getValue('Resources')->getValue('XObject')->getValue('n2')
        );

        $this->assertNotFalse(\strpos($n2->getStream(), 'Digitally signed by'));
    }

    protected function validate($path, $signatureFieldName, $certificate)
    {
        $document = Document::loadByFilename($path);

        $integrityResult = IntegrityResult::create($document, $signatureFieldName);

        $signingCert = $integrityResult->getSignedData()->getSigningCertificate();

        return $integrityResult->isValid() &&
            (new Certificate($certificate))->get() === $signingCert->get();
    }
}
