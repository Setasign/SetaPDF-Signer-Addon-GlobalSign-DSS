<?php

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Dss\tests\functional;

use setasign\SetaPDF\Signer\Module\GlobalSign\Dss\TimestampModule;
use setasign\SetaPDF2\Core\Document;
use setasign\SetaPDF2\Core\Writer\TempFileWriter;
use setasign\SetaPDF2\Signer\SignatureField;
use setasign\SetaPDF2\Signer\Signer;

class TimestampModuleTest extends TestHelper
{
    /**
     * @throws \Throwable
     */
    public function testSimpleTimestamp()
    {
        $writer = new TempFileWriter();
        $document = Document::loadByFilename(__DIR__ . '/../_files/Laboratory-Report.pdf', $writer);

        $signer = new Signer($document);
        $signer->setSignatureContentLength(15000);

        $client = $this->getClientInstance();

        $module = new TimestampModule($client);
        $signer->setTimestampModule($module);

        $signer->timestamp();

//        copy($writer->getPath(), 'timestamp-signature.pdf');

        $document = Document::loadByFilename($writer->getPath());

        $field = SignatureField::get($document, 'Signature', false);
        $this->assertInstanceOf(SignatureField::class, $field);

        $value = $field->getValue();
        $this->assertSame('DocTimeStamp', $value->getValue('Type')->getValue());
        $this->assertSame('ETSI.RFC3161', $value->getValue('SubFilter')->getValue());
        $this->assertNotEmpty($value->getValue('Contents')->getValue());
    }
}
