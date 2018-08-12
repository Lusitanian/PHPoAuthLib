<?php
/**
 * Wrike service.
 *
 * @author  Ádám Bálint <adam.balint@srg.hu>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link    https://developers.wrike.com/documentation
 */

namespace OAuth\OAuth2\Service;

use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;

/**
 * Wrike service.
 *
 * @author  Ádám Bálint <adam.balint@srg.hu>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link    https://developers.wrike.com/documentation
 */
class Wrike extends AbstractService
{
    /*
     * Defined scopes
     * https://developers.wrike.com/documentation/oauth2
     */
    const SCOPE_DEFAULT                 = 'Default';
    const SCOPE_READ                    = 'wsReadOnly';
    const SCOPE_READ_WRITE              = 'wsReadWrite';
    const SCOPE_WORKFLOW_READ           = 'amReadOnlyWorkflow';
    const SCOPE_WORKFLOW_READ_WRITE     = 'amReadWriteWorkflow';
    const SCOPE_INVITATION_READ         = 'amReadOnlyInvitation';
    const SCOPE_INVITATION_READ_WRITE   = 'amReadWriteInvitation';
    const SCOPE_GROUP_READ              = 'amReadOnlyGroup';
    const SCOPE_GROUP_READ_WRITE        = 'amReadWriteGroup';
    const SCOPE_USER_READ               = 'amReadOnlyUser';
    const SCOPE_USER_READ_WRITE         = 'amReadWriteUser';

    const API_VERSION = '3';


    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = array(),
        UriInterface $baseApiUri = null,
        $stateParameterInAutUrl = false,
        $apiVersion = self::API_VERSION // The latest API version
    ) {
        parent::__construct(
            $credentials,
            $httpClient,
            $storage,
            $scopes,
            $baseApiUri,
            $stateParameterInAutUrl,
            $apiVersion
        );

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://www.wrike.com/api'.$this->getApiVersionString().'/');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://www.wrike.com/oauth2/authorize');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://www.wrike.com/oauth2/token');
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

        if(isset($data['refresh_token'])){
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }

        unset($data['access_token']);
        unset($data['expires_in']);

        $token->setExtraParams($data);

        return $token;
    }

    /**
    * {@inheritdoc}
    */
    protected function getApiVersionString()
    {
        return empty($this->apiVersion) ? '' : '/v' . $this->apiVersion;
    }

    /**
    * {@inheritdoc}
    */
    protected function getScopesDelimiter()
    {
        return ',';
    }

    /**
    * {@inheritdoc}
    */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }
}
