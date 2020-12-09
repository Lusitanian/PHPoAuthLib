<?php
namespace OAuth\OAuth2\Service;

use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\Credentials;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;

class BattleNetBase extends AbstractService
{
    const SCOPE_WOW_PROFILE				= 'wow.profile';
    const SCOPE_SC2_PROFILE				= 'sc2.profile';

    /**
    * BattleNet Region
    *
    * @var \region
    */
    protected $region;

    public function __construct(Credentials $credentials, ClientInterface $httpClient, TokenStorageInterface $storage, $scopes = array(), UriInterface $baseApiUri = null)
    {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);
        if ( null === $baseApiUri ) {
    	    $this->baseApiUri = new Uri('https://' . $this->region . '.api.battle.net/');
    	}
    }

    /**
    * @return \OAuth\Common\Http\Uri\UriInterface
    */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://' . $this->region . '.battle.net/oauth/authorize');
   	}

    /**
     * @return \OAuth\Common\Http\Uri\UriInterface
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://' . $this->region . '.battle.net/oauth/token');
    }

   	/**
   	 * @param string $responseBody
   	 * @return \OAuth\Common\Token\TokenInterface|\OAuth\OAuth2\Token\StdOAuth2Token
   	 * @throws \OAuth\Common\Http\Exception\TokenResponseException
   	 */
   	protected function parseAccessTokenResponse($responseBody)
   	{
   	    $data = json_decode( $responseBody, true );

   	    if( null === $data || !is_array($data) ) {
   	        throw new TokenResponseException('Unable to parse response.');
   	    } elseif( isset($data['error'] ) ) {
   	        throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
   	    }

   	    $token = new StdOAuth2Token();

   	    $token->setAccessToken( $data['access_token'] );
   	    // I'm invincible!!!
   	    $token->setEndOfLife(StdOAuth2Token::EOL_NEVER_EXPIRES);
   	    unset( $data['access_token'] );
   	    $token->setExtraParams( $data );

   	    return $token;
   	}

   	/**
   	 * @return int
   	 */
   	protected function getAuthorizationMethod()
   	{
   	    return static::AUTHORIZATION_METHOD_QUERY_STRING;
   	}
}