<?php
/**
 * Pinterest service.
 *
 * @author  Pedro Amorim <contact@pamorim.fr>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link    https://developers.pinterest.com/docs/api/overview/
 */

namespace OAuth\OAuth2\Service;

use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;

/**
 * Pinterest service.
 *
 * @author  Pedro Amorim <contact@pamorim.fr>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link    https://developers.pinterest.com/docs/api/overview/
 */
class Pinterest extends AbstractService
{
    /**
     * Defined scopes - More scopes are listed here:
     * https://developers.pinterest.com/docs/api/overview/
     */
    const SCOPE_READ_PUBLIC         = 'read_public';            // read a user’s Pins, boards and likes
    const SCOPE_WRITE_PUBLIC        = 'write_public';           // write Pins, boards, likes
    const SCOPE_READ_RELATIONSHIPS  = 'read_relationships';     // read a user’s follows (boards, users, interests)
    const SCOPE_WRITE_RELATIONSHIPS = 'write_relationships';    // follow boards, users and interests

    /**
     * {@inheritdoc}
     */
    protected function init()
    {
        $this->stateParameterInAuthUrl = true;

        if( $this->baseApiUri === null ) {
            $this->baseApiUri = new Uri('https://api.pinterest.com/');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://api.pinterest.com/oauth/');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://api.pinterest.com/v1/oauth/token');
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
            throw new TokenResponseException(
                'Error in retrieving token: "' . $data['error'] . '"'
            );
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);

        if (isset($data['expires_in'])) {
            $token->setLifeTime($data['expires_in']);
            unset($data['expires_in']);
        }
        // I hope one day Pinterest add a refresh token :)
        if (isset($data['refresh_token'])) {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }

        unset($data['access_token']);

        $token->setExtraParams($data);

        return $token;
    }
}
