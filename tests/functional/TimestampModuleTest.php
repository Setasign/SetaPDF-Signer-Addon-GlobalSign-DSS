<?php

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Dss\tests\functional;

use PHPUnit\Framework\AssertionFailedError;
use setasign\SetaPDF\Signer\Module\GlobalSign\Dss\SignatureModule;
use setasign\SetaPDF\Signer\Module\GlobalSign\Dss\TimestampModule;

class TimestampModuleTest extends TestHelper
{
    /**
     * @throws \Throwable
     */
    public function testSimpleTimestamp()
    {
        $writer = new \SetaPDF_Core_Writer_TempFile();
        $document = \SetaPDF_Core_Document::loadByFilename(__DIR__ . '/../_files/Laboratory-Report.pdf', $writer);

        $signer = new \SetaPDF_Signer($document);
        $signer->setSignatureContentLength(15000);

        $client = $this->getClientInstance();

        $module = new TimestampModule($client);
        $signer->setTimestampModule($module);

        $signer->timestamp();

//        copy($writer->getPath(), 'timestamp-signature.pdf');

        $document = \SetaPDF_Core_Document::loadByFilename($writer->getPath());

        $field = \SetaPDF_Signer_SignatureField::get($document, 'Signature', false);
        $this->assertInstanceOf(\SetaPDF_Signer_SignatureField::class, $field);

        $value = $field->getValue();
        $this->assertSame('DocTimeStamp', $value->getValue('Type')->getValue());
        $this->assertSame('ETSI.RFC3161', $value->getValue('SubFilter')->getValue());
        $this->assertNotEmpty($value->getValue('Contents')->getValue());
    }
}
