<?php

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Dss\tests\functional;

use Http\Factory\Guzzle\RequestFactory;
use Http\Factory\Guzzle\StreamFactory;
use PHPUnit\Framework\Constraint\IsType;
use Psr\Http\Client\ClientExceptionInterface;
use setasign\SetaPDF\Signer\Module\GlobalSign\Dss\Client;
use setasign\SetaPDF\Signer\Module\GlobalSign\Dss\Exception;
use setasign\SetaPDF\Signer\Module\GlobalSign\Dss\Identity;

class ClientTest extends TestHelper
{
    public function testWithoutNoClientCertificates(): void
    {
        $httpClient = new \GuzzleHttp\Client([
            'http_errors' => false,
        ]);
        $httpClient = new \Mjelamanov\GuzzlePsr18\Client($httpClient);

        $module = new Client(
            $httpClient,
            new RequestFactory(),
            new StreamFactory(),
            '',
            ''
        );
        $this->expectException(ClientExceptionInterface::class);
        $module->login();
    }

    public function testFailedLogin()
    {
        $client = $this->getClientInstance('anything', 'but valid');
        $this->expectException(Exception::class);
        $client->login();
    }

    /**
     * @return Client|void
     */
    public function testLogin(): Client
    {
        $client = $this->getClientInstance();
        $accessToken = $client->login();

        $this->assertNotEmpty($accessToken);

        $accessToken2 = $client->login();

        $this->assertSame($accessToken, $accessToken2);

        return $client;
    }

    /**
     * @param Client $client
     * @depends testLogin
     * @return Client
     */
    public function testForceLogin(Client $client): Client
    {
        $accessToken = $client->login();
        $accessToken2 = $client->login(true);

        $this->assertNotSame($accessToken, $accessToken2);

        return $client;
    }

    /**
     * @param Client $client
     * @depends testForceLogin
     * @return Client
     */
    public function testGetQuotaForSignatures(Client $client): Client
    {
        $this->assertNotEquals(0, $client->getQuota(Client::TYPE_SIGNATURES));
        return $client;
    }

    /**
     * @param Client $client
     * @depends testGetQuotaForSignatures
     * @return Client
     */
    public function testGetQuotaForTimestamps(Client $client): Client
    {
        $this->assertNotEquals(0, $client->getQuota(Client::TYPE_TIMESTAMPS));
        return $client;
    }

    /**
     * @param Client $client
     * @depends testGetQuotaForTimestamps
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function testGetQuotaWithInvalidType(Client $client)
    {
        $this->expectException(\InvalidArgumentException::class);
        $client->getQuota('anything');
    }

    /**
     * @param Client $client
     * @depends testForceLogin
     * @return Client
     */
    public function testGetCountForSignatures(Client $client): Client
    {
        $count = $client->getCount(Client::TYPE_SIGNATURES);
        $this->assertTrue($count > 0);
        return $client;
    }

    /**
     * @param Client $client
     * @depends testGetCountForSignatures
     * @return Client
     */
    public function testGetCountForTimestamps(Client $client): Client
    {
        $count = $client->getCount(Client::TYPE_TIMESTAMPS);
        $this->assertTrue($count > 0);
        return $client;
    }

    /**
     * @param Client $client
     * @depends testGetCountForTimestamps
     * @return Client
     */
    public function testGetCountForIdentities(Client $client): Client
    {
        $this->assertNotEquals(0, $client->getCount(Client::TYPE_IDENTITIES));
        return $client;
    }

    /**
     * @param Client $client
     * @depends testGetCountForIdentities
     */
    public function testGetCountWithInvalidType(Client $client): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $client->getCount('anything');
    }

    /**
     * @param Client $client
     * @depends testForceLogin
     */
    public function testGetCertificatePath(Client $client): void
    {
        $this->assertStringStartsWith('-----BEGIN CER', $client->getCertificatePath());
    }

    /**
     * @param Client $client
     * @depends testForceLogin
     */
    public function testGetValidationPolicy(Client $client): void
    {
        $validationPolicy = $client->getValidationPolicy();

        $this->assertNotEmpty($validationPolicy);
    }

    /**
     * @param Client $client
     * @depends testForceLogin
     */
    public function testGetIdentityWithInvalidData(Client $client): void
    {
        $this->expectException(Exception::class);
        $client->getIdentity(['testing' => 123]);
    }

    /**
     * @param Client $client
     * @return array
     * @depends testForceLogin
     */
    public function testGetIdentityWithoutArguments(Client $client)
    {
        $identity = $client->getIdentity();
        $this->assertInstanceOf(Identity::class, $identity);
        $this->assertNotEmpty($identity->getId());
        $this->assertNotEmpty($identity->getSigningCertificate());
        $this->assertNotEmpty($identity->getOcspResponse());

        return [$client, $identity];
    }

    /**
     * @depends testGetIdentityWithoutArguments
     */
    public function testSignWithInvalidHash(array $data)
    {
        /** @var Client $client */
        [$client, $identity] = $data;

        $this->expectException(Exception::class);
        $client->sign($identity, 'abc');
    }

    /**
     * @param array $data
     * @depends testGetIdentityWithoutArguments
     */
    public function testSign(array $data)
    {
        /** @var Client $client */
        [$client, $identity] = $data;

        $signature = $client->sign($identity, \hash_file('sha256', __FILE__));
        $this->assertSame(\strlen($signature), 512);
    }

    /**
     * @param Client $client
     * @depends testForceLogin
     */
    public function testTimestampWithInvalidHash(Client $client)
    {
        $this->expectException(Exception::class);
        $client->timestamp('abc');
    }

    /**
     * @param Client $client
     * @depends testForceLogin
     */
    public function testTimestamp(Client $client)
    {
        $timestamp = $client->timestamp(\hash_file('sha256', __FILE__));
        $this->assertSame(\strlen($timestamp), 2788);
    }

    /**
     * @param Client $client
     * @depends testForceLogin
     */
    public function testGetTrustchain(Client $client)
    {
        $trustChain = $client->getTrustchain();

        $this->assertTrue(isset($trustChain['trustchain']));
        $this->assertTrue(isset($trustChain['ocsp_revocation_info']));
    }
}
