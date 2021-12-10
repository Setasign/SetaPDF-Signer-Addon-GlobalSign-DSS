<?php

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Dss\tests\functional;

use Http\Factory\Guzzle\RequestFactory;
use Http\Factory\Guzzle\StreamFactory;
use PHPUnit\Framework\TestCase;
use setasign\SetaPDF\Signer\Module\GlobalSign\Dss\Client;

class TestHelper extends TestCase
{
    protected function getClientInstance(
        $apiKey = null,
        $apiSecret = null
    ): Client {
        $privateFolder = __DIR__ . '/../../private';
        $credentialsFile = $privateFolder . '/credentials.php';
        if (!file_exists($credentialsFile)) {
            $this->markTestSkipped('No credentials known.');
        }

        $credentials = require($credentialsFile);
        if (!isset($apiKey, $apiSecret)) {
            $apiKey = $credentials['apiKey'];
            $apiSecret = $credentials['apiSecret'];
        }

        $httpClient = new \GuzzleHttp\Client([
            'http_errors' => false,
            'cert' => $credentials['cert'],
            'ssl_key' => $credentials['privateKey']
        ]);
        $httpClient = new \Mjelamanov\GuzzlePsr18\Client($httpClient);

        return new Client($httpClient, new RequestFactory(), new StreamFactory(), $apiKey, $apiSecret);
    }
}
