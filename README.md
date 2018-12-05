# SetaPDF-Signer component modules for the GlobalSign Digital Signing Service.

This package offers modules for the [SetaPDF-Signer](https://www.setasign.com/signer) component that allow you to use the [Cloud-based Digital Signing Service](https://www.globalsign.com/en/digital-signatures/cloud/) by [GlobalSign](https://www.globalsign.com) to **digital sign and timestamp PDF documents in pure PHP**.

## Requirements

To use this package you need credentials for the GlobalSign Digital Signing Service which are:

1. Your private key
2. Client certificate for mTLS connection to the API
3. Your API key and password

See "GlobalSign-Digital-Signing-Service-Guide 1.3.pdf" (or newer) for details. Ask a GlobalSign contact for this document. 

This package is developed and tested on PHP >= 7.1. Requirements of the [SetaPDF-Signer](https://www.setasign.com/signer) component can be found [here](https://manuals.setasign.com/setapdf-signer-manual/getting-started/#index-1).

## Installation
Add following to your composer.json:

```json
{
    "repositories": [
        {
            "type": "composer",
            "url": "https://www.setasign.com/downloads/"
        }
    ],
    "require": {
        "setasign/seta-pdf-signer-addon-global-sign-dss": "^1.0"
    }
}
```

and call `composer update`. You need to define the `repository` to evaluate the dependency to the [SetaPDF-Signer](https://www.setasign.com/signer) component (see [here](https://getcomposer.org/doc/faqs/why-can%27t-composer-load-repositories-recursively.md) for more details).

### Evaluation version
By default this packages depends on a licensed version of the SetaPDF-Signer component. If you want to use it with an evaluation version please use following in your composer.json:

```json
{
    "repositories": [
        {
            "type": "composer",
            "url": "https://www.setasign.com/downloads/"
        }
    ],
    "require": {
        "setasign/seta-pdf-signer-addon-global-sign-dss": "dev-evaluation"
    }
}
```

### Without Composer

Make sure, that the [SetaPDF-Signer](https://www.setasign.com/signer) component is [installed](https://manuals.setasign.com/setapdf-core-manual/installation/#index-2) and its [autoloader is registered](https://manuals.setasign.com/setapdf-core-manual/getting-started/#index-1) correctly.

Then simply require the `src/autoload.php` file or register this package in your own PSR-4 compatible autoloader implementation:

```php
$loader = new \Example\Psr4AutoloaderClass;
$loader->register();
$loader->addNamespace('setasign\SetaPDF\Signer\Module\GlobalSign\Dss', 'path/to/src/');
```

## Usage

All classes in this package are located in the namespace `setasign\SetaPDF\Signer\Module\GlobalSign\Dss`.

### The `Client` class

There's a simple `Client` class which wraps the [REST API](https://downloads.globalsign.com/acton/media/2674/digital-signing-service-api-documentation) into  simple PHP methods. It handles the authentication, requests and responses internally. For the communication with the API it uses [Guzzle](http://guzzlephp.org/).

The constructor of this class requires 3 arguments: 

`$options` which are the [request options](http://docs.guzzlephp.org/en/stable/request-options.html) for Guzzle. To authenticate to the API endpoint it requires the `cert` (the client certificated issued by GlobalSign) and `ssl_key` (your private key) options. The `headers` and `body` options are set/overwritten internally.
 
`$apiKey` is your API key received from GlobalSign.
 
`$apiSecret` is the secret to your API key received from GlobalSign.

A common creation could look like:

```php
$options = [
    'cert' => 'path/to/tls-cert.pem',
    'ssl_key' => 'path/to/private/key.pem'  
];

$apiKey = 'xxxxxxxxxxxxxxxx';
$apiSecret = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';

$client = new Dss\Client($options, $apiKey, $apiSecret);
```

You can use this instance to e.g. query general information:

```php
$remainingSignatures = $client->getQuota(Dss\Client::TYPE_SIGNATURES);
// or 
$signaturesCount = $client->getCount(Dss\Client::TYPE_SIGNATURES);
```

To create a digital signature you need to create a signing certificate first which can be done with the `getIdentity()` method. The argument to this method can be an associative array as defined [here](https://downloads.globalsign.com/acton/media/2674/digital-signing-service-api-documentation#identity_post). The method will return an `Identity` instance which is nothing more than a data wrapper of the returned id, signing certificate and OCSP response.

```php
$identity = $client->getIdentity();
```

This `Identity` needs to be forward to the signature module which internally passes it back to the `Dss\Client\sign()` method to get the final signature. It is also possible to use this method individually (just for completion):

```php
$signature = $client->sign($identity, hash('sha256', $data));
```

### The `SignatureModule` class

This is the main signature module which can be used with the [SetaPDF-Signer](https://www.setasign.com/signer) component. Its constructor requires 3 arguments:

`$signer` is the instance of the `\SetaPDF_Signer` class to which the module is passed afterwards. Internally [`$signer->setAllowSignatureContentLengthChange(false)`](https://manuals.setasign.com/api-reference/setapdf/c/SetaPDF.Signer#method_setAllowSignatureContentLengthChange) is called to prohibit redundant signature requests.

`$client` needs to be the `Dss\Client` instance.

`$module` needs to be a [CMS](https://manuals.setasign.com/api-reference/setapdf/c/SetaPDF.Signer.Signature.Module.Cms) or [PAdES](https://manuals.setasign.com/api-reference/setapdf/c/SetaPDF.Signer.Signature.Module.Pades) signature module instance. It is used internally to create the CMS container.

The module additionally requires an `Identity` passed to the `setIdentity()` method before it is used with the `\SetaPDF_Signer` instance. A simple complete signature process would look like this:

```php
// setup the client and identity
$options = [
    'cert' => 'path/to/tls-cert.pem',
    'ssl_key' => 'path/to/private/key.pem'  
];

$apiKey = 'xxxxxxxxxxxxxxxx';
$apiSecret = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';

$client = new Dss\Client($options, $apiKey, $apiSecret);
$identity = $client->getIdentity();

// now start the signature process
$writer = new \SetaPDF_Core_Writer_File('signed.pdf');
$document = \SetaPDF_Core_Document::loadByFilename('invoice.pdf', $writer);
 
$signer = new \SetaPDF_Signer($document);
$signer->setSignatureContentLength(15000);

$pades = new \SetaPDF_Signer_Signature_Module_Pades();
$module = new Dss\SignatureModule($signer, $client, $pades);
$module->setIdentity($identity);
 
$signer->sign($module);
```

