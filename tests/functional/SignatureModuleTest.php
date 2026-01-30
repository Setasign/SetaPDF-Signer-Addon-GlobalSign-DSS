<?php

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Dss\tests\functional;

use setasign\SetaPDF\Signer\Module\GlobalSign\Dss\SignatureModule;
use setasign\SetaPDF\Signer\Module\GlobalSign\Dss\TimestampModule;
use setasign\SetaPDF2\Core\Document;
use setasign\SetaPDF2\Core\Type\PdfStream;
use setasign\SetaPDF2\Core\Writer\TempFileWriter;
use setasign\SetaPDF2\Signer\DocumentSecurityStore;
use setasign\SetaPDF2\Signer\Ocsp\CertId;
use setasign\SetaPDF2\Signer\Ocsp\Response;
use setasign\SetaPDF2\Signer\Ocsp\SingleResponse;
use setasign\SetaPDF2\Signer\Signature\Appearance\Dynamic as DynamicAppearance;
use setasign\SetaPDF2\Signer\Signature\Module\Pades;
use setasign\SetaPDF2\Signer\SignatureField;
use setasign\SetaPDF2\Signer\Signer;
use setasign\SetaPDF2\Signer\ValidationRelatedInfo\IntegrityResult;
use setasign\SetaPDF2\Signer\X509\Certificate;
use setasign\SetaPDF2\Signer\X509\Collection;

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

        $module = new SignatureModule($signer, $client, $identity);

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

        $module = new SignatureModule($signer, $client, $identity);

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

        $module = new SignatureModule($signer, $client, $identity);

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

    public function testGetVerificationRelatedInformation()
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

        $module = new SignatureModule($signer, $client, $identity);

        $result = $module->getVerificationRelatedInformation();
        $this->assertCount(1, $result->getCertificates());
        $this->assertEmpty($result->getOcspResponses());
        $this->assertEmpty($result->getCrls());

        $signer->sign($module);

        $result = $module->getVerificationRelatedInformation();
        $this->assertCount(7, $result->getCertificates());
        $this->assertCount(3, $result->getOcspResponses());
        $this->assertCount(0, $result->getCrls());

        $certificates = $result->getCertificates();
        $certificatesCollection = new Collection($certificates);

        // let's ensure that the Ocsp information match the certificates in the
        // $result object.
        foreach ($certificates as $certificate) {
            $issuer = $certificate->getIssuer($certificatesCollection);
            $certId = CertId::create($certificate, $issuer);

            $certResult = $result->getValidationRelatedInfoByCertificate($certificate);
            $ocsp = $certResult->getOcspResponse();

            if ($ocsp instanceof Response) {
                $this->assertInstanceOf(SingleResponse::class, $ocsp->getSingleResponse($certId));
            }
        }

//        copy($writer->getPath(), 'signed.pdf');

        $this->assertTrue(
            $this->validate($writer->getPath(), $field->getQualifiedName(), $identity->getSigningCertificate())
        );
    }

    public function testAddDssOnly()
    {
        $writer = new TempFileWriter();
        $document = Document::loadByFilename(__DIR__ . '/../_files/Laboratory-Report.pdf', $writer);

        $signer = new Signer($document);
        $signer->setSignatureContentLength(15000);
        $field = $signer->getSignatureField();

        $client = $this->getClientInstance();
        $identity = $client->getIdentity([
            'subject_dn' => [
                'common_name' => "Test"
            ]
        ]);

        $module = new SignatureModule($signer, $client, $identity);
        $module->setAddRevocationInfo(false);

        $signer->sign($module);

        $vri = $module->getVerificationRelatedInformation();

        $writer2 = new TempFileWriter();
        $document = Document::loadByFilename($writer->getPath(), $writer2);

        $dss = new DocumentSecurityStore($document);

        $crls = $vri->getCrls();
        $this->assertCount(0, $crls);
        $ocsps = $vri->getOcspResponses();
        $this->assertCount(3, $ocsps);
        $certs = $vri->getCertificates();
        $this->assertCount(7, $certs); // chain (3) + signing (1) + ocsp responders (3)

        $dss->addValidationRelatedInfoByFieldName(
            $field->getQualifiedName(),
            $crls,
            $ocsps,
            $certs
        );

        $integrityResult = IntegrityResult::create($document, $field->getQualifiedName());
        $this->assertCount(4, $integrityResult->getSignedData()->getCertificates());
        $this->assertFalse($integrityResult->getSignedData()->getSignedAttribute('1.2.840.113583.1.1.8'));

        $document->save()->finish();

//        copy($writer2->getPath(), 'signed-ltv.pdf');
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
