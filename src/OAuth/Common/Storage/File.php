<?php

namespace OAuth\Common\Storage;

use OAuth\Common\Token\TokenInterface;
use OAuth\Common\Storage\Exception\StorageException;
use OAuth\Common\Storage\Exception\TokenNotFoundException;
use OAuth\Common\Storage\Exception\AuthorizationStateNotFoundException;
use OAuth\Common\Storage\TokenStorageInterface;


// Stores a token in a file and customer must set the file
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
	protected $filePath;

	public function __construct($filePath = null)
	{
		$this->tokens = array();
		$this->states = array();

		if ($filePath === null) {
			throw new StorageException('Invalid file path');
		}

		$this->filePath = $filePath;
		if (file_exists($this->filePath)) {
			$this->parseFromFile();
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public function retrieveAccessToken($service)
	{
		if ($this->hasAccessToken($service)) {
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
		if (array_key_exists($service, $this->tokens)) {
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
		if ($this->hasAuthorizationState($service)) {
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
		if (array_key_exists($service, $this->states)) {
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
	 * @param $filePath
	 * @return File
	 */
	public function setFilePath($filePath = null)
	{
		if (null !== $filePath) {
			$this->filePath = $filePath;
		}

		return $this;
	}

	/**
	 * Update file containing tokens and states
	 */
	private function updateFile()
	{
		if (null === $this->filePath) {
			throw new StorageException('Invalid file path');
		}

		$data = array(
			'tokens' => $this->tokens,
			'states' => $this->states
		);

		file_put_contents($this->filePath, serialize($data));
	}

	/**
	 * Get serialized content from a file
	 */
	private function parseFromFile()
	{
		if (null === $this->filePath) {
			throw new StorageException('Invalid file path');
		}

		$data = unserialize(file_get_contents($this->filePath));
		if (false === $data) {
			throw new StorageException('File contents not unserializeable');
		}

		$this->tokens = $data['tokens'];
		$this->states = $data['states'];
	}
}
