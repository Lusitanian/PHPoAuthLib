<?php

namespace OAuth\OAuth2\Service;

use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\OAuth2\Service\Exception\InvalidAccessTypeException;
use OAuth\Common\Http\Uri\Uri;

class Dataporten extends AbstractService
{
    /**
     * Defined scopes - More scopes are listed here:
     * https://developers.google.com/oauthplayground/
     *
     * Make a pull request if you need more scopes.
     */

    // Basic
    const SCOPE_EMAIL                       = 'email';
    const SCOPE_PROFILE                     = 'profile';

    public function setAccessType($accessType)
    {
        if (!in_array($accessType, array('online', 'offline'), true)) {
            throw new InvalidAccessTypeException('Invalid accessType, expected either online or offline');
        }
        $this->accessType = $accessType;
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://auth.dataporten.no/oauth/authorization');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://auth.dataporten.no/oauth/token');
    }

    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        $data = json_decode($responseBody, true);

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);
        $token->setLifetime($data['expires_in']);

        if (isset($data['refresh_token'])) {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }

        unset($data['access_token']);
        unset($data['expires_in']);

        $token->setExtraParams($data);

        return $token;
    }
}
