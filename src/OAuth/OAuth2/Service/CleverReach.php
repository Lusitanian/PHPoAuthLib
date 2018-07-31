<?php

namespace OAuth\OAuth2\Service;

use OAuth\OAuth2\Service\AbstractService;
use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;

/**
 * CleverReach service.
 *
 * @author Moritz Beller <beller.moritz@googlemail.com>
 * @link https://rest.cleverreach.com/explorer/
 */
class CleverReach extends AbstractService
{
    /**
     * default scope
     */
    const SCOPE_BASIC = 'basic';

    /**
     * scope for read access
     */
    const SCOPE_READ = 'read';
    
    /**
     * scope for write access
     */
    const SCOPE_WRITE = 'write';

    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = array(),
        UriInterface $baseApiUri = null
    )
    {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);
        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://rest.cleverreach.com');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://rest.cleverreach.com/oauth/authorize.php');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint(){
        return new Uri('https://rest.cleverreach.com/oauth/token.php');
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }

    /**
     * Used to configure response type -- we want JSON, default is query string format
     *
     * @return array
     */
    protected function getExtraOAuthHeaders()
    {
        return array('Accept' => 'application/json');
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
        // CleverReach never expire...
        $token->setEndOfLife(StdOAuth2Token::EOL_NEVER_EXPIRES);
        unset($data['access_token']);
        $token->setExtraParams($data);
        return $token;
    }
}