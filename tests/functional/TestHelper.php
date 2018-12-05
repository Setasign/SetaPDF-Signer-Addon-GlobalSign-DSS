<?php

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Dss\tests\functional;

use PHPUnit\Framework\TestCase;
use setasign\SetaPDF\Signer\Module\GlobalSign\Dss\Client;


class TestHelper extends TestCase
{
    protected function getClientInstance(array $options = null, $apiKey = null, $apiSecret = null)
    {
        $privateFolder = __DIR__ . '/../../private';
        $credentials = $privateFolder . '/credentials.php';
        if (!file_exists($credentials)) {
            $this->markTestSkipped('No credentials known.');
            return;
        }

        // load the credentials
        if (!isset($apiKey, $apiSecret)) {
            ['apiKey' => $apiKey, 'apiSecret' => $apiSecret] = require($credentials);
        }

        $options = $options ?? [
            'cert' => \realpath($privateFolder . '/tls-cert.pem'),
            'ssl_key' => \realpath($privateFolder . '/globalsign-private.pem')
        ];

        return new Client($options, $apiKey, $apiSecret);
    }
}