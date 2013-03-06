<?php
/**
 * OAuth service factory.
 *
 * PHP version 5.4
 *
 * @category   OAuth
 * @author     David Desberg <david@daviddesberg.com>
 * @copyright  Copyright (c) 2013 The authors
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */
namespace OAuth;
use OAuth\Common\Service\ServiceInterface;

class ServiceFactory
{
    protected static $httpClientMap = [
        'stream' => '\\OAuth\\Common\\Http\\Client\\StreamClient',
    ];

    /** @var \OAuth\Common\Http\Client\ClientInterface */
    private $httpClient;

    public function __construct($httpClientType = 'stream')
    {
        if( !isset(static::$httpClientMap[$httpClientType] ) ) {
            throw new Common\Exception\Exception('Invalid http client type passed to OAuth\\ServiceFactory::__construct');
        }

        $this->httpClient = new static::$httpClientMap[$httpClientType];
    }

    /**
     * @param $serviceName string name of service to create
     * @param Common\Consumer\Credentials $credentials
     * @param Common\Storage\TokenStorageInterface $storage
     * @param array|null $scopes If creating an oauth2 service, array of scopes
     * @return ServiceInterface
     * @throws Common\Exception\Exception
     */
    public function createService($serviceName, Common\Consumer\Credentials $credentials, Common\Storage\TokenStorageInterface $storage, $scopes = [])
    {
        $serviceName = ucfirst($serviceName);
        $v2ClassName = "\\OAuth\\OAuth2\\Service\\$serviceName";
        $v1ClassName = "\\OAuth\\OAuth1\\Service\\$serviceName";

        // if an oauth2 version exists, prefer it
        if( class_exists($v2ClassName) ) {
            // resolve scopes
            $resolvedScopes = [];
            $reflClass = new \ReflectionClass($v2ClassName);
            $constants = $reflClass->getConstants();

            foreach($scopes as $scope)
            {
                $key = strtoupper('SCOPE_' . $scope);
                // try to find a class constant with this name
                if( array_key_exists( $key, $constants ) ) {
                    $resolvedScopes[] = $constants[$key];
                } else {
                    $resolvedScopes[] = $scope;
                }
            }

            return new $v2ClassName($credentials, $this->httpClient, $storage, $resolvedScopes);
        }

        if( class_exists($v1ClassName) ) {
            if(!empty($scopes)) {
                throw new Common\Exception\Exception('Scopes passed to ServiceFactory::createService but an OAuth1 service was requested.');
            }
            $signature = new OAuth1\Signature\Signature($credentials);
            return new $v1ClassName($credentials, $this->httpClient, $storage, $signature);
        }

        return null;
    }
}
