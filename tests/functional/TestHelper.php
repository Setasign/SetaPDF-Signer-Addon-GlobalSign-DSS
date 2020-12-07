<?php

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Dss\tests\functional;

use PHPUnit\Framework\TestCase;
use setasign\SetaPDF\Signer\Module\GlobalSign\Dss\Client;

class TestHelper extends TestCase
{
    protected function getClientInstance(array $options = null, $apiKey = null, $apiSecret = null)
    {
        $privateFolder = __DIR__ . '/../../private';
        $credentialsFile = $privateFolder . '/credentials.php';
        if (!file_exists($credentialsFile)) {
            $this->markTestSkipped('No credentials known.');
            return;
        }

        $credentials = require($credentialsFile);
        if (!isset($apiKey, $apiSecret)) {
            $apiKey = $credentials['apiKey'];
            $apiSecret = $credentials['apiSecret'];
        }

        $options = $options ?? [
            'cert' => $credentials['cert'],
            'ssl_key' => $credentials['privateKey']
        ];

        return new Client($options, $apiKey, $apiSecret);
    }
}
