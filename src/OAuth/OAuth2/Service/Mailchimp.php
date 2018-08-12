<?php

namespace OAuth\OAuth2\Service;

use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;

class Mailchimp extends AbstractService
{
    /**
     * {@inheritdoc}
     */
    protected function init()
    {
        if (is_null($this->baseApiUri) && $this->getStorage()->hasAccessToken($this->service(), $this->account())) {
            $this->setBaseApiUri($this->getStorage()->retrieveAccessToken($this->service(), $this->account()));
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_QUERY_STRING_V3;
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://login.mailchimp.com/oauth2/authorize');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://login.mailchimp.com/oauth2/token');
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        // Parse JSON
        $data = json_decode($responseBody, true);

        // Do validation.
        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        // Create token object.
        $token = new StdOAuth2Token($data['access_token']);

        // Set the right API endpoint.
        $this->setBaseApiUri($token);

        // Mailchimp tokens evidently never expire...
        $token->setEndOfLife(StdOAuth2Token::EOL_NEVER_EXPIRES);

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    public function request($path, $method = 'GET', $body = null, array $extraHeaders = array())
    {
        if (is_null($this->baseApiUri)) {
            $this->setBaseApiUri($this->storage->retrieveAccessToken($this->service(), $this->account()));
        }

        return parent::request($path, $method, $body, $extraHeaders);
    }

    /**
     * Set the right base endpoint.
     *
     * @param StdOAuth2Token $token
     */
    protected function setBaseApiUri(StdOAuth2Token $token)
    {
        // Make request uri.
        $endpoint = 'https://login.mailchimp.com/oauth2/metadata?oauth_token='. $token->getAccessToken();

        // Grab meta data about the token.
        $response = $this->httpClient->retrieveResponse(new Uri($endpoint), array(), array(), 'GET');

        // Parse JSON.
        $meta = json_decode($response, true);

        // Set base api uri.
        $this->baseApiUri = new Uri('https://'. $meta['dc'] .'.api.mailchimp.com/2.0/');

        // Allow chaining.
        return $this;
    }
}
