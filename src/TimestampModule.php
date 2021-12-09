<?php

/**
 * @copyright Copyright (c) 2021 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Dss;

use Psr\Http\Client\ClientExceptionInterface;

/**
 * The timestamp module for the SetaPDF-Signer component
 */
class TimestampModule implements
    \SetaPDF_Signer_Timestamp_Module_ModuleInterface
{
    /**
     * @var Client
     */
    protected $client;

    /**
     * @var Identity
     */
    protected $identity;

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
     * @param string|\SetaPDF_Core_Reader_FilePath $data
     * @return string
     * @throws Exception
     * @throws ClientExceptionInterface
     * @throws \SetaPDF_Signer_Asn1_Exception
     */
    public function createTimestamp($data): string
    {
        $timestamp = $this->client->timestamp($this->getHash($data));

        return (string) \SetaPDF_Signer_Asn1_Element::parse(base64_decode($timestamp));
    }

    /**
     * Get the hash that should be timestamped.
     *
     * @param string|\SetaPDF_Core_Reader_FilePath $data The hash of the main signature
     * @return string
     */
    protected function getHash($data): string
    {
        if ($data instanceof \SetaPDF_Core_Reader_FilePath) {
            return \hash_file('sha256', $data->getPath());
        }

        return \hash('sha256', $data);
    }
}
