<?php

namespace OAuth\OAuth2\Service;

use OAuth\Common\Exception\Exception;
use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;

class Line extends AbstractService
{
    /**
     * Line www url - used to build dialog urls
     */
    const WWW_URL = 'https://access.line.me/';

    const SCOPE_NULL = 'null';
    const SCOPE_PROFILE = 'profile';

    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = array(),
        UriInterface $baseApiUri = null,
        $apiVersion = ""
    ) {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri, true, $apiVersion);

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://api.line.me'.$this->getApiVersionString().'/');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://access.line.me/dialog/oauth/weblogin');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://api.line.me'.$this->getApiVersionString().'/oauth/accessToken');
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        // Line gives us a query string ... Oh wait. JSON is too simple, understand ?
        $data = (array) json_decode($responseBody);

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);

        if (isset($data['expires_in'])) {
            $token->setLifeTime($data['expires_in']);
        }

        if (isset($data['refresh_token'])) {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }

        unset($data['access_token']);
        unset($data['expires_in']);

        $token->setExtraParams($data);

        return $token;
    }

    public function getDialogUri($dialogPath, array $parameters)
    {
        if (!isset($parameters['redirect_uri'])) {
            throw new Exception("Redirect uri is mandatory for this request");
        }
        $parameters['app_id'] = $this->credentials->getConsumerId();
        $baseUrl = self::WWW_URL .$this->getApiVersionString(). '/dialog/' . $dialogPath;
        $query = http_build_query($parameters);
        return new Uri($baseUrl . '?' . $query);
    }

    /**
     * {@inheritdoc}
     */
    protected function getApiVersionString()
    {
        return empty($this->apiVersion) ? '/v1' : '/v' . $this->apiVersion;
    }

    /**
     * {@inheritdoc}
     */
    protected function getScopesDelimiter()
    {
        return ',';
    }

}