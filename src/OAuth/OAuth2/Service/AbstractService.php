<?php

namespace OAuth\OAuth2\Service;

use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Service\AbstractService as BaseAbstractService;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Token\Exception\ExpiredTokenException;
use OAuth\Common\Token\TokenInterface;
use OAuth\OAuth2\Service\Exception\InvalidAuthorizationStateException;
use OAuth\OAuth2\Service\Exception\InvalidScopeException;
use OAuth\OAuth2\Service\Exception\MissingRefreshTokenException;
use ReflectionClass;

abstract class AbstractService extends BaseAbstractService implements ServiceInterface
{
    /** @const OAUTH_VERSION */
    const OAUTH_VERSION = 2;

    /** @var array */
    protected $scopes;

    /** @var null|UriInterface */
    protected $baseApiUri;

    /** @var bool */
    protected $stateParameterInAuthUrl;

    /** @var string */
    protected $apiVersion;

    /**
     * @param array                 $scopes
     * @param bool $stateParameterInAutUrl
     * @param string                $apiVersion
     */
    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = [],
        ?UriInterface $baseApiUri = null,
        $stateParameterInAutUrl = false,
        $apiVersion = ''
    ) {
        parent::__construct($credentials, $httpClient, $storage);
        $this->stateParameterInAuthUrl = $stateParameterInAutUrl;

        foreach ($scopes as $scope) {
            if (!$this->isValidScope($scope)) {
                throw new InvalidScopeException('Scope ' . $scope . ' is not valid for service ' . get_class($this));
            }
        }

        $this->scopes = $scopes;

        $this->baseApiUri = $baseApiUri;

        $this->apiVersion = $apiVersion;
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationUri(array $additionalParameters = [])
    {
        $parameters = array_merge(
            $additionalParameters,
            [
                'type' => 'web_server',
                'client_id' => $this->credentials->getConsumerId(),
                'redirect_uri' => $this->credentials->getCallbackUrl(),
                'response_type' => 'code',
            ]
        );

        $parameters['scope'] = implode($this->getScopesDelimiter(), $this->scopes);

        if ($this->needsStateParameterInAuthUrl()) {
            if (!isset($parameters['state'])) {
                $parameters['state'] = $this->generateAuthorizationState();
            }
            $this->storeAuthorizationState($parameters['state']);
        }

        // Build the url
        $url = clone $this->getAuthorizationEndpoint();
        foreach ($parameters as $key => $val) {
            $url->addToQuery($key, $val);
        }

        return $url;
    }

    /**
     * {@inheritdoc}
     */
    public function requestAccessToken($code, $state = null)
    {
        if (null !== $state) {
            $this->validateAuthorizationState($state);
        }

        $bodyParams = [
            'code' => $code,
            'client_id' => $this->credentials->getConsumerId(),
            'client_secret' => $this->credentials->getConsumerSecret(),
            'redirect_uri' => $this->credentials->getCallbackUrl(),
            'grant_type' => 'authorization_code',
        ];

        $responseBody = $this->httpClient->retrieveResponse(
            $this->getAccessTokenEndpoint(),
            $bodyParams,
            $this->getExtraOAuthHeaders()
        );

        $token = $this->parseAccessTokenResponse($responseBody);
        $this->storage->storeAccessToken($this->service(), $token);

        return $token;
    }

    /**
     * Sends an authenticated API request to the path provided.
     * If the path provided is not an absolute URI, the base API Uri (must be passed into constructor) will be used.
     *
     * @param string|UriInterface $path
     * @param string              $method       HTTP method
     * @param array               $body         request body if applicable
     * @param array               $extraHeaders Extra headers if applicable. These will override service-specific
     *                                          any defaults.
     *
     * @return string
     */
    public function request($path, $method = 'GET', $body = null, array $extraHeaders = [])
    {
        $uri = $this->determineRequestUriFromPath($path, $this->baseApiUri);
        $token = $this->storage->retrieveAccessToken($this->service());

        if ($token->getEndOfLife() !== TokenInterface::EOL_NEVER_EXPIRES
            && $token->getEndOfLife() !== TokenInterface::EOL_UNKNOWN
            && time() > $token->getEndOfLife()
        ) {
            throw new ExpiredTokenException(
                sprintf(
                    'Token expired on %s at %s',
                    date('m/d/Y', $token->getEndOfLife()),
                    date('h:i:s A', $token->getEndOfLife())
                )
            );
        }

        // add the token where it may be needed
        if (static::AUTHORIZATION_METHOD_HEADER_OAUTH === $this->getAuthorizationMethod()) {
            $extraHeaders = array_merge(['Authorization' => 'OAuth ' . $token->getAccessToken()], $extraHeaders);
        } elseif (static::AUTHORIZATION_METHOD_QUERY_STRING === $this->getAuthorizationMethod()) {
            $uri->addToQuery('access_token', $token->getAccessToken());
        } elseif (static::AUTHORIZATION_METHOD_QUERY_STRING_V2 === $this->getAuthorizationMethod()) {
            $uri->addToQuery('oauth2_access_token', $token->getAccessToken());
        } elseif (static::AUTHORIZATION_METHOD_QUERY_STRING_V3 === $this->getAuthorizationMethod()) {
            $uri->addToQuery('apikey', $token->getAccessToken());
        } elseif (static::AUTHORIZATION_METHOD_QUERY_STRING_V4 === $this->getAuthorizationMethod()) {
            $uri->addToQuery('auth', $token->getAccessToken());
        } elseif (static::AUTHORIZATION_METHOD_HEADER_BEARER === $this->getAuthorizationMethod()) {
            $extraHeaders = array_merge(['Authorization' => 'Bearer ' . $token->getAccessToken()], $extraHeaders);
        } elseif (static::AUTHORIZATION_METHOD_HEADER_TOKEN === $this->getAuthorizationMethod()) {
            $extraHeaders = array_merge(array('Authorization' => 'token ' . $token->getAccessToken()), $extraHeaders);
        }

        $extraHeaders = array_merge($this->getExtraApiHeaders(), $extraHeaders);

        return $this->httpClient->retrieveResponse($uri, $body, $extraHeaders, $method);
    }

    /**
     * Accessor to the storage adapter to be able to retrieve tokens.
     *
     * @return TokenStorageInterface
     */
    public function getStorage()
    {
        return $this->storage;
    }

    /**
     * Refreshes an OAuth2 access token.
     *
     * @return TokenInterface $token
     */
    public function refreshAccessToken(TokenInterface $token)
    {
        $refreshToken = $token->getRefreshToken();

        if (empty($refreshToken)) {
            throw new MissingRefreshTokenException();
        }

        $parameters = [
            'grant_type' => 'refresh_token',
            'type' => 'web_server',
            'client_id' => $this->credentials->getConsumerId(),
            'client_secret' => $this->credentials->getConsumerSecret(),
            'refresh_token' => $refreshToken,
        ];

        $responseBody = $this->httpClient->retrieveResponse(
            $this->getAccessTokenEndpoint(),
            $parameters,
            $this->getExtraOAuthHeaders()
        );
        
        $responseBody = $this->carryRefreshToken($responseBody, $refreshToken);
        
        $token = $this->parseAccessTokenResponse($responseBody);
        $this->storage->storeAccessToken($this->service(), $token);

        return $token;
    }
    
    /**
     * Carry the refresh_token for next time getting refreshed
     *
     * @param $responseBody
     *
     * @param $refreshToken
     *
     * @return string
     */
    public function carryRefreshToken($responseBody, $refreshToken)
    {
        $data = json_decode($responseBody, true);
        $data['refresh_token'] = $refreshToken;
        return json_encode($data);
    }

    /**
     * Return whether or not the passed scope value is valid.
     *
     * @param string $scope
     *
     * @return bool
     */
    public function isValidScope($scope)
    {
        $reflectionClass = new ReflectionClass(get_class($this));

        return in_array($scope, $reflectionClass->getConstants(), true);
    }

    /**
     * Check if the given service need to generate a unique state token to build the authorization url.
     *
     * @return bool
     */
    public function needsStateParameterInAuthUrl()
    {
        return $this->stateParameterInAuthUrl;
    }

    /**
     * Validates the authorization state against a given one.
     *
     * @param string $state
     */
    protected function validateAuthorizationState($state): void
    {
        if ($this->retrieveAuthorizationState() !== $state) {
            throw new InvalidAuthorizationStateException();
        }
    }

    /**
     * Generates a random string to be used as state.
     *
     * @return string
     */
    protected function generateAuthorizationState()
    {
        return md5(mt_rand());
    }

    /**
     * Retrieves the authorization state for the current service.
     *
     * @return string
     */
    protected function retrieveAuthorizationState()
    {
        return $this->storage->retrieveAuthorizationState($this->service());
    }

    /**
     * Stores a given authorization state into the storage.
     *
     * @param string $state
     */
    protected function storeAuthorizationState($state): void
    {
        $this->storage->storeAuthorizationState($this->service(), $state);
    }

    /**
     * Return any additional headers always needed for this service implementation's OAuth calls.
     *
     * @return array
     */
    protected function getExtraOAuthHeaders()
    {
        return [];
    }

    /**
     * Return any additional headers always needed for this service implementation's API calls.
     *
     * @return array
     */
    protected function getExtraApiHeaders()
    {
        return [];
    }

    /**
     * Parses the access token response and returns a TokenInterface.
     *
     * @abstract
     *
     * @param string $responseBody
     *
     * @return TokenInterface
     */
    abstract protected function parseAccessTokenResponse($responseBody);

    /**
     * Returns a class constant from ServiceInterface defining the authorization method used for the API
     * Header is the sane default.
     *
     * @return int
     */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_OAUTH;
    }

    /**
     * Returns api version string if is set else retrun empty string.
     *
     * @return string
     */
    protected function getApiVersionString()
    {
        return !(empty($this->apiVersion)) ? '/' . $this->apiVersion : '';
    }

    /**
     * Returns delimiter to scopes in getAuthorizationUri
     * For services that do not fully respect the Oauth's RFC,
     * and use scopes with commas as delimiter.
     *
     * @return string
     */
    protected function getScopesDelimiter()
    {
        return ' ';
    }
}
