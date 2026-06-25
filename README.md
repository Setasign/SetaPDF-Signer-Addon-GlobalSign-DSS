# SetaPDF-Signer component modules for the GlobalSign Digital Signing Service.

This package offers modules for the [SetaPDF-Signer](https://www.setasign.com/signer) component that allow you 
to use the [Cloud-based Digital Signing Service](https://www.globalsign.com/en/digital-signing-service) by
[GlobalSign](https://www.globalsign.com) to **digital sign and timestamp PDF documents in pure PHP**.

## Requirements

To use this package you need credentials for the GlobalSign Digital Signing Service which are:

1. Your private key
2. Client certificate for mTLS connection to the API
3. Your API key and password

See "GlobalSign-Digital-Signing-Service-Guide 1.3.pdf" (or newer) for details. Ask a GlobalSign contact for this document. 

This package is developed and tested on PHP >= 7.4 up to PHP 8.5. Requirements of the [SetaPDF-Signer](https://www.setasign.com/signer) 
component can be found [here](https://manuals.setasign.com/setapdf-signer-manual/getting-started/#index-1).

We're using [PSR-17 (HTTP Factories)](https://www.php-fig.org/psr/psr-17/) and
[PSR-18 (HTTP Client)](https://www.php-fig.org/psr/psr-18/) for the requests. So you'll need an implementation of
these. We recommend using Guzzle:

```
    "require" : {
        "guzzlehttp/guzzle": "^7.0",
        "http-interop/http-factory-guzzle": "^1.0"
    }
```

## Installation
Add following to your composer.json:

```json
{
    "require": {
        "setasign/seta-pdf-signer-addon-global-sign-dss": "^3.0"
    },
    "repositories": [
        {
            "type": "composer",
            "url": "https://www.setasign.com/downloads/"
        }
    ]
}
```

and execute `composer update`. You need to define the `repository` to evaluate the dependency to the 
[SetaPDF-Signer](https://www.setasign.com/signer) component (see 
[here](https://getcomposer.org/doc/faqs/why-can%27t-composer-load-repositories-recursively.md) for more details).

## Usage

All classes in this package are located in the namespace `setasign\SetaPDF\Signer\Module\GlobalSign\Dss`.

### The `Client` class

There's a simple `Client` class which wraps the [REST API](https://downloads.globalsign.com/acton/media/2674/digital-signing-service-api-documentation) 
into  simple PHP methods. It handles the authentication, requests and responses internally.

The constructor of this class requires the following arguments: 

- `$httpClient` PSR-18 HTTP Client implementation.
- `$requestFactory` PSR-17 HTTP Factory implementation.
- `$streamFactory` PSR-17 HTTP Factory implementation.
- `$apiKey` is your API key received from GlobalSign.
- `$apiSecret` is the secret to your API key received from GlobalSign.

A common creation could look like:

```php
$options = [
    'http_errors' => false, // recommended for guzzle - because of PSR-18
    'cert' => 'path/to/tls-cert.pem',
    'ssl_key' => 'path/to/private/key.pem'  
];

$apiKey = 'xxxxxxxxxxxxxxxx';
$apiSecret = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';

$httpClient = new GuzzleHttp\Client($options);
$requestFactory = new Http\Factory\Guzzle\RequestFactory();
$streamFactory = new Http\Factory\Guzzle\StreamFactory();

$client = new Dss\Client($httpClient, $requestFactory, $streamFactory, $apiKey, $apiSecret);
```

You can use this instance to e.g. query general information:

```php
$remainingSignatures = $client->getQuota(Dss\Client::TYPE_SIGNATURES);
// or 
$signaturesCount = $client->getCount(Dss\Client::TYPE_SIGNATURES);
```

To create a digital signature you need to create a signing certificate first which can be done with the `getIdentity()`
method. The argument to this method can be an associative array as defined 
[here](https://downloads.globalsign.com/acton/media/2674/digital-signing-service-api-documentation#identity_post). 
The method will return an `Identity` instance which is nothing more than a data wrapper of the returned id, signing
certificate and OCSP response.

```php
$identity = $client->getIdentity();
```

This `Identity` needs to be forward to the signature module which internally passes it back to the `Dss\Client\sign()`
method to get the final signature. It is also possible to use this method individually (just for completion):

```php
$signature = $client->sign($identity, hash('sha256', $data));
```

### The `SignatureModule` class

This is the main signature module which can be used with the [SetaPDF-Signer](https://www.setasign.com/signer) component.
The module creates PAdES conforming CMS containers.
Its constructor requires these arguments:

- `$signer` is the instance of the `setasign\SetaPDF2\Signer\Signer` class to which the module is passed afterwards. Internally [`$signer->setAllowSignatureContentLengthChange(false)`](https://manuals.setasign.com/api-reference/setapdf/c/SetaPDF.Signer#method_setAllowSignatureContentLengthChange) is called to prohibit redundant signature requests.
- `$client` needs to be the `Dss\Client` instance.
- `$identity` a `Dss\Identity` instance.

A simple complete signature process would look like this:

```php
use Http\Factory\Guzzle\RequestFactory;
use Http\Factory\Guzzle\StreamFactory;
use setasign\SetaPDF2\Core\Document as Document;
use setasign\SetaPDF2\Core\Writer\FileWriter as FileWriter;
use setasign\SetaPDF2\Signer\Signature\Module\Pades as Pades;
use setasign\SetaPDF2\Signer\Signer as Signer;
use setasign\SetaPDF\Signer\Module\GlobalSign\Dss;

// set up the client and identity
$options = [
    'http_errors' => false,
    'cert' => 'path/to/tls-cert.pem',
    'ssl_key' => 'path/to/private/key.pem'  
];

$apiKey = 'xxxxxxxxxxxxxxxx';
$apiSecret = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';

$httpClient = new \GuzzleHttp\Client($options);

$client = new Dss\Client($httpClient, new RequestFactory(), new StreamFactory(), $apiKey, $apiSecret);
$identity = $client->getIdentity();

// now start the signature process
$writer = new FileWriter('signed.pdf');
$document = Document::loadByFilename('invoice.pdf', $writer);
 
$signer = new Signer($document);
$signer->setSignatureContentLength(15000);

$pades = new Pades();
$module = new Dss\SignatureModule($signer, $client, $identity, $pades);
 
$signer->sign($module);
```

### The `TimestampModule` class

This module can be used to add timestamps to the digital signature or to create document level timestamps. It's constructor simply requires a `Dss\Client` instance:

```php
use setasign\SetaPDF\Signer\Module\GlobalSign\Dss;

$tsmodule = new Dss\TimestampModule($client);
```

It doesn't require an identity as the signature module but can be passed as it is to the `Signer` instance:

```php
$signer->setTimestampModule($tsmodule);
// ...
$signer->sign($module);
```

or you can create a document level timestamp with it:

```php
$signer->setTimestampModule($tsmodule);
// ...
$signer->timestamp();
``` 

## Information about Tests

The test suite currently only comes with functional tests, which invoke **real service calls**! Keep in mind that these
calls are deducted from your signature contingent. You should not execute these tests in an automated environment!!

To execute the tests, you need to create a folder in the root of this package with the following file:

```
/private/
    credentials.php
``` 

The `credentials.php` file needs to return your credentials, certificate and private key:
```php
<?php
        
return [
    'apiKey' => '<YOUR API KEY>',
    'apiSecret' => '<YOUR API SECRET>',
    'cert' => '/path/to/your/mTLS/certificate.pem',
    'privateKey' => '/path/to/your/private/key.pem'
];
```

## License

This package is open-source software licensed under the [MIT license](https://opensource.org/licenses/MIT).
