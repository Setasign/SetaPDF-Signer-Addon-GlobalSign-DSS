<?php
/**
 * @copyright Copyright (c) 2019 Setasign - Jan Slabon (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Dss;

use GuzzleHttp\Client as HttpClient;

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
     * @var HttpClient
     */
    protected $client;

    /**
     * @var array
     */
    protected $options;

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
     * @param array $options Request options forward to Guzzle (see {@link http://docs.guzzlephp.org/en/stable/request-options.html here} for more details).
     * @param string $apiKey
     * @param string $apiSecret
     * @param string $endpoint
     */
    public function __construct(
        $options,
        $apiKey,
        $apiSecret,
        $endpoint = 'https://emea.api.dss.globalsign.com:8443/v2'
    ) {
        $this->options = $options;
        $this->apiKey = $apiKey;
        $this->apiSecret = $apiSecret;
        $this->endPoint = $endpoint;

        $this->client = new HttpClient(['base_uri' => $this->endPoint]);
    }

    /**
     * Login method.
     *
     * This method login to obtain a JWT token for authentication on further requests.
     * The access token is cached by the instance.
     *
     * @param bool $force
     * @return string
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function login($force = false)
    {
        if ($this->accessToken === null || $force) {
            $options = $this->options;
            $options['headers'] = [
                'Content-Type' => 'application/json;charset=utf-8'
            ];

            $options['body'] = \json_encode([
                'api_key' => $this->apiKey,
                'api_secret' => $this->apiSecret
            ]);

            $response = $this->client->request('POST', '/login', $options);

            $result = \json_decode($response->getBody()->getContents());

            $this->accessToken = $result->access_token;
        }

        return $this->accessToken;
    }

    /**
     * Query remaining quota of a specific type for the calling account.
     *
     * @param $type
     * @return int
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getQuota($type): int
    {
        if (!\in_array($type, [self::TYPE_SIGNATURES, self::TYPE_TIMESTAMPS], true)) {
            throw new \InvalidArgumentException(sprintf('Unknow quota type: "%s".', $type));
        }

        $options = $this->options;
        $options['headers'] = ['Authorization' => 'Bearer ' . $this->login()];

        $response = $this->client->request('GET', '/quotas/' . $type, $options);
        return (int)\json_decode($response->getBody()->getContents())->value;
    }

    /**
     * Query the number of a specific type created by the calling account.
     *
     * @param $type
     * @return int
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getCount($type): int
    {
        if (!\in_array($type, [self::TYPE_SIGNATURES, self::TYPE_TIMESTAMPS, self::TYPE_IDENTITIES], true)) {
            throw new \InvalidArgumentException(sprintf('Unknow counter type: "%s".', $type));
        }

        $options = $this->options;
        $options['headers'] = ['Authorization' => 'Bearer ' . $this->login()];

        $response = $this->client->request('GET', '/counters/' . $type, $options);

        return (int)\json_decode($response->getBody()->getContents())->value;
    }

    /**
     * Retrieve the certificate used to sign the identity requests.
     *
     * @return string
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getCertificatePath(): string
    {
        $options = $this->options;
        $options['headers'] = ['Authorization' => 'Bearer ' . $this->login()];

        $response = $this->client->request('GET', '/certificate_path', $options);

        return \json_decode($response->getBody()->getContents())->path;
    }

    /**
     * Retrieve the validation policy associated with the calling account.
     *
     * @return \stdClass
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getValidationPolicy(): \stdClass
    {
        $options = $this->options;
        $options['headers'] = ['Authorization' => 'Bearer ' . $this->login()];

        $response = $this->client->request('GET', '/validationpolicy', $options);

        return \json_decode($response->getBody()->getContents());
    }

    /**
     * Submit a request for a signing identity.
     *
     * @param $identityData
     * @return Identity
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getIdentity($identityData = null): Identity
    {
        $options = $this->options;
        $options['headers'] = [
            'Content-Type' => 'application/json;charset=utf-8',
            'Authorization' => 'Bearer ' . $this->login()
        ];

        $options['body'] = \json_encode($identityData);

        $response = $this->client->request('POST', '/identity', $options);

        $data = \json_decode($response->getBody()->getContents());

        return new Identity($data->id, $data->signing_cert, $data->ocsp_response);
    }

    /**
     * Retrieve a signature for a digest.
     *
     * @param Identity $identity
     * @param string $digest
     * @return mixed
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function sign(Identity $identity, $digest)
    {
        $options = $this->options;
        $options['headers'] = [
            'Authorization' => 'Bearer ' . $this->login()
        ];

        $response = $this->client->request('GET', '/identity/' . $identity->getId() . '/sign/' . $digest, $options);

        return \json_decode($response->getBody()->getContents())->signature;
    }

    /**
     * Retrieve timestamp token for digest
     *
     * @param string $digest
     * @return mixed
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function timestamp($digest)
    {
        $options = $this->options;
        $options['headers'] = [
            'Authorization' => 'Bearer ' . $this->login()
        ];

        $response = $this->client->request('GET', '/timestamp/' . $digest, $options);

        return \json_decode($response->getBody()->getContents())->token;
    }
}
