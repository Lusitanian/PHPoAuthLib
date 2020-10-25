<?php

namespace OAuthTest\Unit\Common\Storage;

use OAuth\Common\Storage\File;

class FileTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @covers OAuth\Common\Storage\File::__construct
     */
    public function testConstructCorrectInterface()
    {
        $storage = new File();

        $this->assertInstanceOf('\\OAuth\\Common\\Storage\\TokenStorageInterface', $storage);
    }

    /**
     * @covers OAuth\Common\Storage\File::__construct
     * @covers OAuth\Common\Storage\File::storeAccessToken
     */
    public function testStoreAccessToken()
    {
        $storage = new File();

        $this->assertInstanceOf(
            '\\OAuth\\Common\\Storage\\File',
            $storage->storeAccessToken('foo', $this->getMock('\\OAuth\\Common\\Token\\TokenInterface'))
        );
    }

    /**
     * @covers OAuth\Common\Storage\File::__construct
     * @covers OAuth\Common\Storage\File::storeAccessToken
     * @covers OAuth\Common\Storage\File::retrieveAccessToken
     * @covers OAuth\Common\Storage\File::hasAccessToken
     */
    public function testRetrieveAccessTokenValid()
    {
        $storage = new File();

        $storage->storeAccessToken('foo', $this->getMock('\\OAuth\\Common\\Token\\TokenInterface'));

        $this->assertInstanceOf('\\OAuth\\Common\\Token\\TokenInterface', $storage->retrieveAccessToken('foo'));
    }

    /**
     * @covers OAuth\Common\Storage\File::__construct
     * @covers OAuth\Common\Storage\File::retrieveAccessToken
     * @covers OAuth\Common\Storage\File::hasAccessToken
     */
    public function testRetrieveAccessTokenThrowsExceptionWhenTokenIsNotFound()
    {
        $this->setExpectedException('\\OAuth\\Common\\Storage\\Exception\\TokenNotFoundException');

        $storage = new File();

        $storage->retrieveAccessToken('foo');
    }

    /**
     * @covers OAuth\Common\Storage\File::__construct
     * @covers OAuth\Common\Storage\File::storeAccessToken
     * @covers OAuth\Common\Storage\File::hasAccessToken
     */
    public function testHasAccessTokenTrue()
    {
        $storage = new File();

        $storage->storeAccessToken('foo', $this->getMock('\\OAuth\\Common\\Token\\TokenInterface'));

        $this->assertTrue($storage->hasAccessToken('foo'));
    }

    /**
     * @covers OAuth\Common\Storage\File::__construct
     * @covers OAuth\Common\Storage\File::hasAccessToken
     */
    public function testHasAccessTokenFalse()
    {
        $storage = new File();

        $this->assertFalse($storage->hasAccessToken('foo'));
    }

    /**
     * @covers OAuth\Common\Storage\File::__construct
     * @covers OAuth\Common\Storage\File::clearToken
     */
    public function testClearTokenIsNotSet()
    {
        $storage = new File();

        $this->assertInstanceOf('\\OAuth\\Common\\Storage\\File', $storage->clearToken('foo'));
    }

    /**
     * @covers OAuth\Common\Storage\File::__construct
     * @covers OAuth\Common\Storage\File::storeAccessToken
     * @covers OAuth\Common\Storage\File::clearToken
     */
    public function testClearTokenSet()
    {
        $storage = new File();

        $storage->storeAccessToken('foo', $this->getMock('\\OAuth\\Common\\Token\\TokenInterface'));

        $this->assertTrue($storage->hasAccessToken('foo'));
        $this->assertInstanceOf('\\OAuth\\Common\\Storage\\File', $storage->clearToken('foo'));
        $this->assertFalse($storage->hasAccessToken('foo'));
    }

    /**
     * @covers OAuth\Common\Storage\File::__construct
     * @covers OAuth\Common\Storage\File::storeAccessToken
     * @covers OAuth\Common\Storage\File::clearAllTokens
     */
    public function testClearAllTokens()
    {
        $storage = new File();

        $storage->storeAccessToken('foo', $this->getMock('\\OAuth\\Common\\Token\\TokenInterface'));
        $storage->storeAccessToken('bar', $this->getMock('\\OAuth\\Common\\Token\\TokenInterface'));

        $this->assertTrue($storage->hasAccessToken('foo'));
        $this->assertTrue($storage->hasAccessToken('bar'));
        $this->assertInstanceOf('\\OAuth\\Common\\Storage\\File', $storage->clearAllTokens());
        $this->assertFalse($storage->hasAccessToken('foo'));
        $this->assertFalse($storage->hasAccessToken('bar'));
    }

    /**
     * @covers OAuth\Common\Storage\File::__construct
     * @covers OAuth\Common\Storage\File::setFilePath
     */
    public function testSetFilePath()
    {
        $storage = new File();

        $this->assertInstanceOf('\\OAuth\\Common\\Storage\\File', $storage->setFilePath('/var/tmp/oauth2token'));
    }
}
