<?php

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Dss\tests\functional;

use PHPUnit\Framework\Constraint\IsType;
use setasign\SetaPDF\Signer\Module\GlobalSign\Dss\Client;
use setasign\SetaPDF\Signer\Module\GlobalSign\Dss\Identity;

class ClientTest extends TestHelper
{
    /**
     * @expectedException \GuzzleHttp\Exception\ConnectException
     * @expectedExceptionMessage cURL error 35
     */
    public function testWithoutNoClientCertificates(): void
    {
        $module = new Client([], '', '');
        $module->login();
    }

    /**
     * @expectedException \GuzzleHttp\Exception\ClientException
     * @expectedExceptionMessage 422 Unprocessable Entity
     */
    public function testFailedLogin()
    {
        $client = $this->getClientInstance(null, 'anything', 'but valid');
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
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function testGetQuotaForSignatures(Client $client): Client
    {
        $this->assertInternalType(IsType::TYPE_INT, $client->getQuota(Client::TYPE_SIGNATURES));
        return $client;
    }

    /**
     * @param Client $client
     * @depends testGetQuotaForSignatures
     * @return Client
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function testGetQuotaForTimestamps(Client $client): Client
    {
        $this->assertInternalType(IsType::TYPE_INT, $client->getQuota(Client::TYPE_TIMESTAMPS));
        return $client;
    }

    /**
     * @param Client $client
     * @depends testGetQuotaForTimestamps
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unknow quota type
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function testGetQuotaWithInvalidType(Client $client)
    {
        $client->getQuota('anything');
    }

    /**
     * @param Client $client
     * @depends testForceLogin
     * @return Client
     * @throws \GuzzleHttp\Exception\GuzzleException
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
     * @throws \GuzzleHttp\Exception\GuzzleException
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
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function testGetCountForIdentities(Client $client): Client
    {
        $this->assertInternalType(IsType::TYPE_INT, $client->getCount(Client::TYPE_IDENTITIES));
        return $client;
    }

    /**
     * @param Client $client
     * @depends testGetCountForIdentities
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unknow counter type
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function testGetCountWithInvalidType(Client $client): void
    {
        $client->getCount('anything');
    }

    /**
     * @param Client $client
     * @depends testForceLogin
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function testGetCertificatePath(Client $client): void
    {
        $this->assertStringStartsWith('-----BEGIN CER', $client->getCertificatePath());
    }

    /**
     * @param Client $client
     * @depends testForceLogin
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function testGetValidationPolicy(Client $client): void
    {
        $validationPolicy = $client->getValidationPolicy();

        $this->assertInstanceOf(\stdClass::class, $validationPolicy);
    }

    /**
     * @param Client $client
     * @depends testForceLogin
     * @expectedException \GuzzleHttp\Exception\ClientException
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function testGetIdentityWithInvalidData(Client $client): void
    {
        $client->getIdentity(['testing' => 123]);
    }

    /**
     * @param Client $client
     * @return array
     * @throws \GuzzleHttp\Exception\GuzzleException
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
     * @param Client $client
     * @param $identity
     * @depends testGetIdentityWithoutArguments
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @expectedException \GuzzleHttp\Exception\ClientException
     * @expectedExceptionMessage Malformed digest
     */
    public function testSignWithInvalidHash(array $data)
    {
        [$client, $identity] = $data;

        /** @var Client $client */
        $client->sign($identity, 'abc');
    }

    /**
     * @param array $data
     * @depends testGetIdentityWithoutArguments
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function testSign(array $data)
    {
        [$client, $identity] = $data;

        /** @var Client $client */
        $signature = $client->sign($identity, \hash_file('sha256', __FILE__));
        $this->assertSame(\strlen($signature), 512);
    }

    /**
     * @param Client $client
     * @depends testForceLogin
     * @expectedException \GuzzleHttp\Exception\ClientException
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function testTimestampWithInvalidHash(Client $client)
    {
        $client->timestamp('abc');
    }

    /**
     * @param Client $client
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @depends testForceLogin
     */
    public function testTimestamp(Client $client)
    {
        $timestamp = $client->timestamp(\hash_file('sha256', __FILE__));
        $this->assertSame(\strlen($timestamp), 2788);
    }
}