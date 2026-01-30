<?php

/**
 * @copyright Copyright (c) 2026 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Dss;

use Psr\Http\Client\ClientExceptionInterface;
use setasign\SetaPDF2\Core\Reader\FilePath;
use setasign\SetaPDF2\Signer\Asn1\Element as Asn1Element;
use setasign\SetaPDF2\Signer\Asn1\Exception as Asn1Exception;
use setasign\SetaPDF2\Signer\Timestamp\Module\ModuleInterface;

/**
 * The timestamp module for the SetaPDF-Signer component
 */
class TimestampModule implements
    ModuleInterface
{
    protected Client $client;

    /**
     * @param Client $client
     */
    public function __construct(Client $client)
    {
        $this->client = $client;
    }

    /**
     * Create the timestamp signature.
     *
     * @param string|FilePath $data
     * @return string
     * @throws Exception
     * @throws ClientExceptionInterface
     * @throws Asn1Exception
     */
    public function createTimestamp($data): string
    {
        $timestamp = $this->client->timestamp($this->getHash($data));
        return (string) Asn1Element::parse(\base64_decode($timestamp));
    }

    /**
     * Get the hash that should be timestamped.
     *
     * @param string|FilePath $data The hash of the main signature
     * @return string
     */
    protected function getHash($data): string
    {
        if ($data instanceof FilePath) {
            return \hash_file('sha256', $data->getPath());
        }

        return \hash('sha256', $data);
    }
}
