<?php

namespace OAuth\Common\Storage;

use OAuth\Common\Token\TokenInterface;
use OAuth\Common\Storage\Exception\TokenNotFoundException;
use OAuth\Common\Storage\Exception\AuthorizationStateNotFoundException;
/*
 * Stores a token in a Memcached server.
 */
class Memcached implements TokenStorageInterface
{
    /**
     * @var string
     */
    protected $key;

    /**
     * @var string
     */
    protected $stateKey;

    /**
     * @var object|\Memcached
     */
    protected $memcached;

    /**
     * @var object|TokenInterface
     */
    protected $cachedTokens;

    /**
     * @var object
     */
    protected $cachedStates;

    /**
     * @param \Memcached $memcache An instantiated and connected Memcached client
     * @param string $key The key to store the token under in Memcached
     * @param string $stateKey The key to store the state under in Memcached.
     */
    public function __construct(\Memcached $memcache, $key, $stateKey)
    {
        $this->memcached = $memcache;
        $this->key = $key;
        $this->stateKey = $stateKey;
        $this->cachedTokens = array();
        $this->cachedStates = array();
    }

    /**
     * {@inheritDoc}
     */
    public function retrieveAccessToken($service)
    {
        if (!$this->hasAccessToken($service)) {
            throw new TokenNotFoundException('Token not found in Memcached');
        }

        if (isset($this->cachedTokens[$service])) {
            return $this->cachedTokens[$service];
        }

        $val = unserialize($this->memcached->get($this->key));
        $val = $val[$service];

        return $this->cachedTokens[$service] = $val;
    }

    /**
     * {@inheritDoc}
     */
    public function storeAccessToken($service, TokenInterface $token)
    {
        // (over)write the token
        $all_tokens = $this->memcached->get($this->key);

        if ($this->memcached->getResultCode() == \Memcached::RES_NOTFOUND) {
            $all_tokens = array();
        } else {
            $all_tokens = unserialize($all_tokens);
        }

        $all_tokens[$service] = $token;
        $this->memcached->set($this->key, serialize($all_tokens));

        $this->cachedTokens[$service] = $token;

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function hasAccessToken($service)
    {
        if (isset($this->cachedTokens[$service])
            && $this->cachedTokens[$service] instanceof TokenInterface
        ) {
            return true;
        }

        $all_tokens = unserialize($this->memcached->get($this->key));

        return (bool)$all_tokens[$service];
    }

    /**
     * {@inheritDoc}
     */
    public function clearToken($service)
    {
        $all_tokens = unserialize($this->memcached->get($this->key));
        unset($all_tokens[$service]);

        if (empty($all_tokens)) {
            $this->memcached->delete($this->key);
        } else {
            $this->memcached->set($this->key, serialize($all_tokens));
        }

        unset($this->cachedTokens[$service]);

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function clearAllTokens()
    {
        // memory
        $this->cachedTokens = array();

        // memcached
        $this->memcached->delete($this->key);

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function retrieveAuthorizationState($service)
    {
        if (!$this->hasAuthorizationState($service)) {
            throw new AuthorizationStateNotFoundException('State not found in Memcached');
        }

        if (isset($this->cachedStates[$service])) {
            return $this->cachedStates[$service];
        }

        $val = unserialize($this->memcached->get($this->stateKey));
        $val = $val[$service];

        return $this->cachedStates[$service] = $val;
    }

    /**
     * {@inheritDoc}
     */
    public function storeAuthorizationState($service, $state)
    {
        // (over)write the token
        $all_states = $this->memcached->get($this->key);

        if ($this->memcached->getResultCode() == \Memcached::RES_NOTFOUND) {
            $all_states = array();
        } else {
            $all_states = unserialize($all_states);
        }

        $all_states[$service] = $state;
        $this->memcached->set($this->stateKey, serialize($all_states));

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function hasAuthorizationState($service)
    {
        if (isset($this->cachedStates[$service])
            && null !== $this->cachedStates[$service]
        ) {
            return true;
        }

        $all_states = unserialize($this->memcached->get($this->stateKey));

        return (bool)$all_states[$service];
    }

    /**
     * {@inheritDoc}
     */
    public function clearAuthorizationState($service)
    {
        $all_states = unserialize($this->memcached->get($this->stateKey));
        unset($all_states[$service]);

        if (empty($all_states)) {
            $this->memcached->delete($this->stateKey);
        } else {
            $this->memcached->set($this->stateKey, serialize($all_states));
        }

        unset($this->cachedTokens[$service]);

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function clearAllAuthorizationStates()
    {
        // memory
        $this->cachedStates = array();

        // memcached
        $this->memcached->delete($this->stateKey);

        // allow chaining
        return $this;
    }

    /**
     * @return \Memcached $memcached
     */
    public function getMemcached()
    {
        return $this->memcached;
    }

    /**
     * @return string $key
     */
    public function getKey()
    {
        return $this->key;
    }
}
