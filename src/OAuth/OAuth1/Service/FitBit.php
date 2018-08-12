<?php

namespace OAuth\OAuth1\Service;

use OAuth\OAuth1\Signature\SignatureInterface;
use OAuth\OAuth1\Token\StdOAuth1Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Client\ClientInterface;

class FitBit extends AbstractService
{
    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        SignatureInterface $signature,
        UriInterface $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $signature, $baseApiUri);

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://api.fitbit.com/1/');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getRequestTokenEndpoint()
    {
        return new Uri('https://api.fitbit.com/oauth/request_token');
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://www.fitbit.com/oauth/authorize');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://api.fitbit.com/oauth/access_token');
    }

    /**
     * {@inheritDoc}
     */
    public function requestAccessToken($token, $verifier, $tokenSecret = null)
    {
        if (is_null($tokenSecret)) {
            $storedRequestToken = $this->storage->retrieveAccessToken($this->service());
            $tokenSecret = $storedRequestToken->getRequestTokenSecret();
        }
        $this->signature->setTokenSecret($tokenSecret);

        $bodyParams = array(
            'oauth_verifier' => $verifier,
        );

        $authorizationHeader = array(
            'Authorization' => $this->buildAuthorizationHeaderForAPIRequest(
                'POST',
                $this->getAccessTokenEndpoint(),
                $this->storage->retrieveAccessToken($this->service()),
                $bodyParams
            )
        );

        $headers = array_merge($authorizationHeader, $this->getExtraOAuthHeaders());

        //Only change
        $responseBody = $this->httpClient->retrieveResponse($this->getAccessTokenEndpoint(), array(), $headers);

        $token = $this->parseAccessTokenResponse($responseBody);
        $this->storage->storeAccessToken($this->service(), $token);

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    protected function parseRequestTokenResponse($responseBody)
    {
        parse_str($responseBody, $data);

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (!isset($data['oauth_callback_confirmed']) || $data['oauth_callback_confirmed'] !== 'true') {
            throw new TokenResponseException('Error in retrieving token.');
        }

        return $this->parseAccessTokenResponse($responseBody);
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        parse_str($responseBody, $data);

        if (null === $data || !is_array($data) || !isset($data['oauth_token']) || !isset($data['oauth_token_secret'])) {
            if (isset($data['error'])) {
                throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
            }

            $data = json_decode($responseBody, true);

            if (isset($data['errors'])) {
                throw new TokenResponseException('Error in retrieving token: "' . $data['errors'][0]['message'] . '"');
            }

            throw new TokenResponseException('Unable to parse response.');
        }

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
}
