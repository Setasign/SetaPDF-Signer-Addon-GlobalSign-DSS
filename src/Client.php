<?php

/**
 * @copyright Copyright (c) 2021 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Dss;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * A client class for the GlobalSign Digital Signing Service
 *
 * It wrapps the REST API (https://downloads.globalsign.com/acton/media/2674/digital-signing-service-api-documentation)
 * into this class.
 */
class Client
{
    public const TYPE_SIGNATURES = 'signatures';
    public const TYPE_TIMESTAMPS = 'timestamps';
    public const TYPE_IDENTITIES = 'identities';

    /**
     * @var ClientInterface PSR-18 HTTP Client implementation.
     */
    protected $httpClient;

    /**
     * @var RequestFactoryInterface PSR-17 HTTP Factory implementation.
     */
    protected $requestFactory;

    /**
     * @var StreamFactoryInterface PSR-17 HTTP Factory implementation.
     */
    protected $streamFactory;

    /**
     * @var string
     */
    protected $apiKey;

    /**
     * @var string
     */
    protected $apiSecret;

    /**
     * @var string
     */
    protected $endPoint;

    /**
     * @var string
     */
    protected $accessToken;

    /**
     * Client constructor.
     *
     * @param ClientInterface $httpClient PSR-18 HTTP Client implementation.
     * @param RequestFactoryInterface $requestFactory PSR-17 HTTP Factory implementation.
     * @param StreamFactoryInterface $streamFactory PSR-17 HTTP Factory implementation.
     * @param string $apiKey
     * @param string $apiSecret
     * @param string $endpoint
     */
    public function __construct(
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        StreamFactoryInterface $streamFactory,
        string $apiKey,
        string $apiSecret,
        string $endpoint = 'https://emea.api.dss.globalsign.com:8443/v2'
    ) {
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->streamFactory = $streamFactory;
        $this->apiKey = $apiKey;
        $this->apiSecret = $apiSecret;
        $this->endPoint = rtrim($endpoint, '/');
    }

    /**
     * Helper method to handle errors in json_decode
     *
     * @param string $json
     * @param bool $assoc
     * @param int $depth
     * @param int $options
     * @return mixed
     * @throws Exception
     */
    protected function json_decode(string $json, bool $assoc = true, int $depth = 512, int $options = 0)
    {
        // Clear json_last_error()
        \json_encode(null);

        $data = @\json_decode($json, $assoc, $depth, $options);

        if (\json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception(\sprintf(
                'Unable to decode JSON: %s',
                \json_last_error_msg()
            ));
        }

        return $data;
    }

    /**
     * Login method.
     *
     * This method login to obtain a JWT token for authentication on further requests.
     * The access token is cached by the instance.
     *
     * @param bool $force
     * @return string
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws Exception If the login fails.
     */
    public function login(bool $force = false): string
    {
        if ($this->accessToken === null || $force) {
            $request = (
                $this->requestFactory->createRequest('POST', $this->endPoint . '/login')
                ->withHeader('Content-Type', 'application/json;charset=utf-8')
                ->withBody($this->streamFactory->createStream(\json_encode([
                    'api_key' => $this->apiKey,
                    'api_secret' => $this->apiSecret
                ])))
            );

            $response = $this->httpClient->sendRequest($request);
            if ($response->getStatusCode() !== 200) {
                throw new Exception('Error on /login: ' . $response->getBody());
            }

            $result = $this->json_decode((string) $response->getBody());

            $this->accessToken = $result['access_token'];
        }

        return $this->accessToken;
    }

    /**
     * Query remaining quota of a specific type for the calling account.
     *
     * @param string $type
     * @return int
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws Exception
     */
    public function getQuota(string $type): int
    {
        if (!\in_array($type, [self::TYPE_SIGNATURES, self::TYPE_TIMESTAMPS], true)) {
            throw new \InvalidArgumentException(sprintf('Unknow quota type: "%s".', $type));
        }

        $request = (
            $this->requestFactory->createRequest('GET', $this->endPoint . '/quotas/' . $type)
            ->withHeader('Authorization', 'Bearer ' . $this->login())
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on getQuota(): ' . $response->getBody());
        }

        return (int) $this->json_decode((string) $response->getBody())['value'];
    }

    /**
     * Query the number of a specific type created by the calling account.
     *
     * @param string $type
     * @return int
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws Exception
     */
    public function getCount(string $type): int
    {
        if (!\in_array($type, [self::TYPE_SIGNATURES, self::TYPE_TIMESTAMPS, self::TYPE_IDENTITIES], true)) {
            throw new \InvalidArgumentException(sprintf('Unknow counter type: "%s".', $type));
        }

        $request = (
            $this->requestFactory->createRequest('GET', $this->endPoint . '/counters/' . $type)
            ->withHeader('Authorization', 'Bearer ' . $this->login())
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on getCount(): ' . $response->getBody());
        }

        return (int) $this->json_decode((string) $response->getBody())['value'];
    }

    /**
     * Retrieve the certificate used to sign the identity requests.
     *
     * @return string
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws Exception
     */
    public function getCertificatePath(): string
    {
        $request = (
            $this->requestFactory->createRequest('GET', $this->endPoint . '/certificate_path')
            ->withHeader('Authorization', 'Bearer ' . $this->login())
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on getCertificatePath(): ' . $response->getBody());
        }

        return $this->json_decode((string) $response->getBody())['path'];
    }

    /**
     * Retrieve the validation policy associated with the calling account.
     *
     * @return array
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws Exception
     */
    public function getValidationPolicy(): array
    {
        $request = (
            $this->requestFactory->createRequest('GET', $this->endPoint . '/validationpolicy')
            ->withHeader('Authorization', 'Bearer ' . $this->login())
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on getValidationPolicy(): ' . $response->getBody());
        }

        return $this->json_decode($response->getBody()->getContents());
    }

    /**
     * Submit a request for a signing identity.
     *
     * @param $identityData
     * @return Identity
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws Exception
     */
    public function getIdentity($identityData = null): Identity
    {
        $request = (
            $this->requestFactory->createRequest('POST', $this->endPoint . '/identity')
            ->withHeader('Authorization', 'Bearer ' . $this->login())
            ->withHeader('Content-Type', 'application/json;charset=utf-8')
            ->withBody($this->streamFactory->createStream(\json_encode($identityData)))
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on getIdentity(): ' . $response->getBody());
        }

        $data = $this->json_decode($response->getBody()->getContents());

        return new Identity($data['id'], $data['signing_cert'], $data['ocsp_response']);
    }

    /**
     * Retrieve a signature for a digest.
     *
     * @param Identity $identity
     * @param string $digest
     * @return string
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws Exception
     */
    public function sign(Identity $identity, string $digest): string
    {
        $request = (
            $this->requestFactory->createRequest(
                'GET',
                $this->endPoint . '/identity/' . $identity->getId() . '/sign/' . $digest
            )
            ->withHeader('Authorization', 'Bearer ' . $this->login())
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on sign(): ' . $response->getBody());
        }

        return $this->json_decode((string) $response->getBody())['signature'];
    }

    /**
     * Retrieve timestamp token for digest
     *
     * @param string $digest
     * @return string
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws Exception
     */
    public function timestamp(string $digest): string
    {
        $request = (
            $this->requestFactory->createRequest('GET', $this->endPoint . '/timestamp/' . $digest)
            ->withHeader('Authorization', 'Bearer ' . $this->login())
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on timestamp(): ' . $response->getBody());
        }

        return $this->json_decode((string) $response->getBody())['token'];
    }

    /**
     * Query the chain of trust for the certificates issued by the calling account and the revocation info for the
     * certificates in the chain
     *
     * @return array
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws Exception
     */
    public function getTrustchain(): array
    {
        $request = (
            $this->requestFactory->createRequest('GET', $this->endPoint . '/trustchain')
            ->withHeader('Authorization', 'Bearer ' . $this->login())
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on getTrustchain(): ' . $response->getBody());
        }

        return $this->json_decode((string) $response->getBody());
    }
}
