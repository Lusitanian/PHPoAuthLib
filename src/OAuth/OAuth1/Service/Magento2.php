<?php

namespace OAuth\OAuth1\Service;

use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\OAuth1\Service\AbstractService;
use OAuth\OAuth1\Signature\SignatureInterface;
use OAuth\OAuth1\Token\StdOAuth1Token;
use OAuth\OAuth1\Token\TokenInterface;

class Magento2 extends AbstractService
{
    /** @var string|null */
    protected $oauthVerifier = null;

    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        SignatureInterface $signature,
        UriInterface $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $signature, $baseApiUri);
    }

    /**
     * {@inheritdoc}
     */
    public function getRequestTokenEndpoint()
    {
        $uri = clone $this->baseApiUri;
        $uri->setPath('/oauth/token/request');
        return $uri;
    }

    /**
     * Returns the authorization API endpoint.
     *
     * @throws \OAuth\Common\Exception\Exception
     */
    public function getAuthorizationEndpoint()
    {
        throw new \OAuth\Common\Exception\Exception(
            'Magento REST API is 2-legged. Current operation is not available.'
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        $uri = clone $this->baseApiUri;
        $uri->setPath('/oauth/token/access');
        return $uri;
    }

    /**
     * Parses the request token response and returns a TokenInterface.
     *
     * @param string $responseBody
     * @return TokenInterface
     * @throws TokenResponseException
     */
    protected function parseRequestTokenResponse($responseBody)
    {
        $data = $this->parseResponseBody($responseBody);
        if (isset($data['oauth_verifier'])) {
            $this->oauthVerifier = $data['oauth_verifier'];
        }
        return $this->parseToken($responseBody);
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        return $this->parseToken($responseBody);
    }

    /**
     * Parse response body and create oAuth token object based on parameters provided.
     *
     * @param string $responseBody
     * @return StdOAuth1Token
     * @throws TokenResponseException
     */
    protected function parseToken($responseBody)
    {
        $data = $this->parseResponseBody($responseBody);
        $token = new StdOAuth1Token();
        $token->setRequestToken($data['oauth_token']);
        $token->setRequestTokenSecret($data['oauth_token_secret']);
        $token->setAccessToken($data['oauth_token']);
        $token->setAccessTokenSecret($data['oauth_token_secret']);
        $token->setEndOfLife(StdOAuth1Token::EOL_NEVER_EXPIRES);
        unset($data['oauth_token'], $data['oauth_token_secret']);
        $token->setExtraParams($data);
        return $token;
    }

    /**
     * Parse response body and return data in array.
     *
     * @param string $responseBody
     * @return array
     * @throws TokenResponseException
     */
    protected function parseResponseBody($responseBody)
    {
        if (!is_string($responseBody)) {
            throw new TokenResponseException("Response body is expected to be a string.");
        }
        parse_str($responseBody, $data);
        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error'])) {
            throw new TokenResponseException("Error occurred: '{$data['error']}'");
        }
        return $data;
    }

    /**
     * Builds the authorization header for an authenticated API request
     *
     * This is changed from the parent to include $bodyParams in $authParameters.
     *
     * @param string         $method
     * @param UriInterface   $uri        The uri the request is headed
     * @param TokenInterface $token
     * @param array          $bodyParams Request body if applicable (key/value pairs)
     *
     * @return string
     */
    protected function buildAuthorizationHeaderForAPIRequest(
        $method,
        UriInterface $uri,
        TokenInterface $token,
        $bodyParams = null
    ) {
        $this->signature->setTokenSecret($token->getAccessTokenSecret());
        $authParameters = $this->getBasicAuthorizationHeaderInfo();
        if (isset($authParameters['oauth_callback'])) {
            unset($authParameters['oauth_callback']);
        }

        $authParameters = array_merge($authParameters, ['oauth_token' => $token->getAccessToken()]);
        if (is_array($bodyParams)) {
            $authParameters = array_merge($authParameters, $bodyParams);
        }
        $authParameters['oauth_signature'] = $this->signature->getSignature($uri, $authParameters, $method);

        $authorizationHeader = 'OAuth ';
        $delimiter = '';

        foreach ($authParameters as $key => $value) {
            $authorizationHeader .= $delimiter . rawurlencode($key) . '="' . rawurlencode($value) . '"';
            $delimiter = ', ';
        }

        return $authorizationHeader;
    }
}
