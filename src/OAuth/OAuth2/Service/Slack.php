<?php

namespace OAuth\OAuth2\Service;

use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;

/**
 * Slack service.
 *
 * @author Christophe Garde <christophe.garde@gmail.com>
 * @link https://api.slack.com/#read_the_docs
 */
class Slack extends AbstractService
{
    // Basic
    const SCOPE_ID_EMAIL                       = 'identity.email';
    const SCOPE_ID_BASIC                       = 'identity.basic';
   
    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = array(),
        UriInterface $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri, $stateParameterInAutUrl = true);
      

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://slack.com/api/');
        }
    }
    
    
    /**
     * {@inheritdoc}
     */
    public function getAuthorizationUri(array $additionalParameters = array()){
        // replace scope by user_scope
        // this is a bit ugly, but still looks better than overriding the whole function :)
        return str_replace('&scope=','&scope=&user_scope=',parent::getAuthorizationUri($additionalParameters));
    }
    
    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://slack.com/oauth/v2/authorize');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://slack.com/api/oauth.v2.access');
    }

    /**
     * {@inheritdoc}
     */
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
        $token->setAccessToken($data['authed_user']['access_token']);
        $token->setEndOfLife(StdOAuth2Token::EOL_NEVER_EXPIRES);

        unset($data['authed_user']['access_token']);

        $token->setExtraParams(array($data['authed_user']));
        return $token;
    }

}
