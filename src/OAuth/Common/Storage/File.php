<?php
namespace OAuth\Common\Storage;

use OAuth\Common\Token\TokenInterface;
use OAuth\Common\Storage\Exception\StorageException;
use OAuth\Common\Storage\Exception\TokenNotFoundException;
use OAuth\Common\Storage\Exception\AuthorizationStateNotFoundException;

/*
 * Stores a token in a file
 */
class File implements TokenStorageInterface
{
    /**
     * @var array of object|TokenInterface
     */
    protected $tokens;

    /**
     * @var array
     */
    protected $states;

    /**
     * @var string
     */
    protected $file_path;

    public function __construct($file_path = null)
    {
        $this->tokens = array();
        $this->states = array();

        if(!is_null($file_path))
        {
            $this->file_path = $file_path;

            if(file_exists($this->file_path))
                $this->parseFromFile();
        }
    }

    /**
     * {@inheritDoc}
     */
    public function retrieveAccessToken($service)
    {
        if($this->hasAccessToken($service)) {
            return $this->tokens[$service];
        }

        throw new TokenNotFoundException('Token not stored');
    }

    /**
     * {@inheritDoc}
     */
    public function storeAccessToken($service, TokenInterface $token)
    {
        $this->tokens[$service] = $token;
        $this->updateFile();

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function hasAccessToken($service)
    {
        return isset($this->tokens[$service]) && $this->tokens[$service] instanceof TokenInterface;
    }

    /**
     * {@inheritDoc}
     */
    public function clearToken($service)
    {
        if(array_key_exists($service, $this->tokens)) {
            unset($this->tokens[$service]);
            $this->updateFile();
        }

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function clearAllTokens()
    {
        $this->tokens = array();
        $this->updateFile();

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function retrieveAuthorizationState($service)
    {
        if($this->hasAuthorizationState($service)) {
            return $this->states[$service];
        }

        throw new AuthorizationStateNotFoundException('State not stored');
    }

    /**
     * {@inheritDoc}
     */
    public function storeAuthorizationState($service, $state)
    {
        $this->states[$service] = $state;
        $this->updateFile();

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function hasAuthorizationState($service)
    {
        return isset($this->states[$service]) && null !== $this->states[$service];
    }

    /**
     * {@inheritDoc}
     */
    public function clearAuthorizationState($service)
    {
        if(array_key_exists($service, $this->states)) {
            unset($this->states[$service]);
            $this->updateFile();
        }

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function clearAllAuthorizationStates()
    {
        $this->states = array();
        $this->updateFile();

        // allow chaining
        return $this;
    }

    /**
     * Set file path
     * @param $file_path
     * @return File
     */
    public function setFilePath($file_path = null)
    {
        if(!is_null($file_path))
            $this->file_path = $file_path;

        return $this;
    }

    /**
     * Update file containing tokens and states
     */
    private function updateFile()
    {
        if(is_null($this->file_path))
            throw new StorageException('Invalid file path');

        $data = array(
            'tokens' => $this->tokens,
            'states' => $this->states
        );

        file_put_contents($this->file_path, serialize($data));
    }

    /**
     * Get serialized content from a file
     */
    private function parseFromFile()
    {
        if(is_null($this->file_path))
            throw new StorageException('Invalid file path');

        $data = unserialize(file_get_contents($this->file_path));

        if($data === false)
            throw new StorageException('File contents not unserializeable');

        $this->tokens = $data['tokens'];
        $this->states = $data['states'];
    }
}
