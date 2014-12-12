<?php

namespace OAuthTest\Unit\OAuth1\Service;

use OAuth\OAuth1\Service\Etsy;
use OAuthTest\Unit\Common\TestHelper;

class EtsyTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @covers OAuth\OAuth1\Service\Etsy::__construct
     */
    public function testConstructCorrectInterfaceWithoutCustomUri()
    {
        $service = new Etsy(
            $this->getMock('\\OAuth\\Common\\Consumer\\CredentialsInterface'),
            $this->getMock('\\Ivory\\HttpAdapter\\HttpAdapterInterface'),
            $this->getMock('\\OAuth\\Common\\Storage\\TokenStorageInterface'),
            $this->getMock('\\OAuth\\OAuth1\\Signature\\SignatureInterface')
        );

        $this->assertInstanceOf('\\OAuth\\OAuth1\\Service\\ServiceInterface', $service);
    }

    /**
     * @covers OAuth\OAuth1\Service\Etsy::__construct
     */
    public function testConstructCorrectInstanceWithoutCustomUri()
    {
        $service = new Etsy(
            $this->getMock('\\OAuth\\Common\\Consumer\\CredentialsInterface'),
            $this->getMock('\\Ivory\\HttpAdapter\\HttpAdapterInterface'),
            $this->getMock('\\OAuth\\Common\\Storage\\TokenStorageInterface'),
            $this->getMock('\\OAuth\\OAuth1\\Signature\\SignatureInterface')
        );

        $this->assertInstanceOf('\\OAuth\\OAuth1\\Service\\AbstractService', $service);
    }

    /**
     * @covers OAuth\OAuth1\Service\Etsy::__construct
     */
    public function testConstructCorrectInstanceWithCustomUri()
    {
        $service = new Etsy(
            $this->getMock('\\OAuth\\Common\\Consumer\\CredentialsInterface'),
            $this->getMock('\\Ivory\\HttpAdapter\\HttpAdapterInterface'),
            $this->getMock('\\OAuth\\Common\\Storage\\TokenStorageInterface'),
            $this->getMock('\\OAuth\\OAuth1\\Signature\\SignatureInterface'),
            $this->getMock('\\OAuth\\Common\\Http\\Uri\\UriInterface')
        );

        $this->assertInstanceOf('\\OAuth\\OAuth1\\Service\\AbstractService', $service);
    }

    /**
     * @covers OAuth\OAuth1\Service\Etsy::__construct
     * @covers OAuth\OAuth1\Service\Etsy::getRequestTokenEndpoint
     */
    public function testGetRequestTokenEndpoint()
    {
        $service = new Etsy(
            $this->getMock('\\OAuth\\Common\\Consumer\\CredentialsInterface'),
            $this->getMock('\\Ivory\\HttpAdapter\\HttpAdapterInterface'),
            $this->getMock('\\OAuth\\Common\\Storage\\TokenStorageInterface'),
            $this->getMock('\\OAuth\\OAuth1\\Signature\\SignatureInterface')
        );

        $this->assertSame(
            'https://openapi.etsy.com/v2/oauth/request_token',
            $service->getRequestTokenEndpoint()->getAbsoluteUri()
        );

		$service->setScopes(array('email_r', 'cart_rw'));

        $this->assertSame(
            'https://openapi.etsy.com/v2/oauth/request_token?scope=email_r%20cart_rw',
            $service->getRequestTokenEndpoint()->getAbsoluteUri()
        );

    }

    /**
     * @covers OAuth\OAuth1\Service\Etsy::__construct
     * @covers OAuth\OAuth1\Service\Etsy::getAuthorizationEndpoint
     */
    public function testGetAuthorizationEndpoint()
    {
        $service = new Etsy(
            $this->getMock('\\OAuth\\Common\\Consumer\\CredentialsInterface'),
            $this->getMock('\\Ivory\\HttpAdapter\\HttpAdapterInterface'),
            $this->getMock('\\OAuth\\Common\\Storage\\TokenStorageInterface'),
            $this->getMock('\\OAuth\\OAuth1\\Signature\\SignatureInterface')
        );

        $this->assertSame(
            'https://openapi.etsy.com/v2/',
            $service->getAuthorizationEndpoint()->getAbsoluteUri()
        );
    }

    /**
     * @covers OAuth\OAuth1\Service\Etsy::__construct
     * @covers OAuth\OAuth1\Service\Etsy::getAccessTokenEndpoint
     */
    public function testGetAccessTokenEndpoint()
    {
        $service = new Etsy(
            $this->getMock('\\OAuth\\Common\\Consumer\\CredentialsInterface'),
            $this->getMock('\\Ivory\\HttpAdapter\\HttpAdapterInterface'),
            $this->getMock('\\OAuth\\Common\\Storage\\TokenStorageInterface'),
            $this->getMock('\\OAuth\\OAuth1\\Signature\\SignatureInterface')
        );

        $this->assertSame(
            'https://openapi.etsy.com/v2/oauth/access_token',
            $service->getAccessTokenEndpoint()->getAbsoluteUri()
        );
    }

    /**
     * @covers OAuth\OAuth1\Service\Etsy::__construct
     * @covers OAuth\OAuth1\Service\Etsy::getRequestTokenEndpoint
     * @covers OAuth\OAuth1\Service\Etsy::parseRequestTokenResponse
     */
    public function testParseRequestTokenResponseThrowsExceptionOnNulledResponse()
    {
        $client = $this->getMock('\\Ivory\\HttpAdapter\\HttpAdapterInterface');
        $client->expects($this->once())->method('post')->will($this->returnValue(TestHelper::createStringResponse(null)));

        $service = new Etsy(
            $this->getMock('\\OAuth\\Common\\Consumer\\CredentialsInterface'),
            $client,
            $this->getMock('\\OAuth\\Common\\Storage\\TokenStorageInterface'),
            $this->getMock('\\OAuth\\OAuth1\\Signature\\SignatureInterface')
        );

        $this->setExpectedException('\\OAuth\\Common\\Http\\Exception\\TokenResponseException');

        $service->requestRequestToken();
    }

    /**
     * @covers OAuth\OAuth1\Service\Etsy::__construct
     * @covers OAuth\OAuth1\Service\Etsy::getRequestTokenEndpoint
     * @covers OAuth\OAuth1\Service\Etsy::parseRequestTokenResponse
     */
    public function testParseRequestTokenResponseThrowsExceptionOnResponseNotAnArray()
    {
        $client = $this->getMock('\\Ivory\\HttpAdapter\\HttpAdapterInterface');
        $client->expects($this->once())->method('post')->will($this->returnValue(TestHelper::createStringResponse('notanarray')));

        $service = new Etsy(
            $this->getMock('\\OAuth\\Common\\Consumer\\CredentialsInterface'),
            $client,
            $this->getMock('\\OAuth\\Common\\Storage\\TokenStorageInterface'),
            $this->getMock('\\OAuth\\OAuth1\\Signature\\SignatureInterface')
        );

        $this->setExpectedException('\\OAuth\\Common\\Http\\Exception\\TokenResponseException');

        $service->requestRequestToken();
    }

    /**
     * @covers OAuth\OAuth1\Service\Etsy::__construct
     * @covers OAuth\OAuth1\Service\Etsy::getRequestTokenEndpoint
     * @covers OAuth\OAuth1\Service\Etsy::parseRequestTokenResponse
     */
    public function testParseRequestTokenResponseThrowsExceptionOnResponseCallbackNotSet()
    {
        $client = $this->getMock('\\Ivory\\HttpAdapter\\HttpAdapterInterface');
        $client->expects($this->once())->method('post')->will($this->returnValue(TestHelper::createStringResponse('foo=bar')));

        $service = new Etsy(
            $this->getMock('\\OAuth\\Common\\Consumer\\CredentialsInterface'),
            $client,
            $this->getMock('\\OAuth\\Common\\Storage\\TokenStorageInterface'),
            $this->getMock('\\OAuth\\OAuth1\\Signature\\SignatureInterface')
        );

        $this->setExpectedException('\\OAuth\\Common\\Http\\Exception\\TokenResponseException');

        $service->requestRequestToken();
    }

    /**
     * @covers OAuth\OAuth1\Service\Etsy::__construct
     * @covers OAuth\OAuth1\Service\Etsy::getRequestTokenEndpoint
     * @covers OAuth\OAuth1\Service\Etsy::parseRequestTokenResponse
     */
    public function testParseRequestTokenResponseThrowsExceptionOnResponseCallbackNotTrue()
    {
        $client = $this->getMock('\\Ivory\\HttpAdapter\\HttpAdapterInterface');
        $client->expects($this->once())->method('post')->will($this->returnValue(
            TestHelper::createStringResponse('oauth_callback_confirmed=false')
        ));

        $service = new Etsy(
            $this->getMock('\\OAuth\\Common\\Consumer\\CredentialsInterface'),
            $client,
            $this->getMock('\\OAuth\\Common\\Storage\\TokenStorageInterface'),
            $this->getMock('\\OAuth\\OAuth1\\Signature\\SignatureInterface')
        );

        $this->setExpectedException('\\OAuth\\Common\\Http\\Exception\\TokenResponseException');

        $service->requestRequestToken();
    }

    /**
     * @covers OAuth\OAuth1\Service\Etsy::__construct
     * @covers OAuth\OAuth1\Service\Etsy::getRequestTokenEndpoint
     * @covers OAuth\OAuth1\Service\Etsy::parseRequestTokenResponse
     * @covers OAuth\OAuth1\Service\Etsy::parseAccessTokenResponse
     */
    public function testParseRequestTokenResponseValid()
    {
        $client = $this->getMock('\\Ivory\\HttpAdapter\\HttpAdapterInterface');
        $client->expects($this->once())->method('post')->will($this->returnValue(
            TestHelper::createStringResponse('oauth_callback_confirmed=true&oauth_token=foo&oauth_token_secret=bar')
        ));

        $service = new Etsy(
            $this->getMock('\\OAuth\\Common\\Consumer\\CredentialsInterface'),
            $client,
            $this->getMock('\\OAuth\\Common\\Storage\\TokenStorageInterface'),
            $this->getMock('\\OAuth\\OAuth1\\Signature\\SignatureInterface')
        );

        $this->assertInstanceOf('\\OAuth\\OAuth1\\Token\\StdOAuth1Token', $service->requestRequestToken());
    }

    /**
     * @covers OAuth\OAuth1\Service\Etsy::__construct
     * @covers OAuth\OAuth1\Service\Etsy::getRequestTokenEndpoint
     * @covers OAuth\OAuth1\Service\Etsy::parseAccessTokenResponse
     */
    public function testParseAccessTokenResponseThrowsExceptionOnError()
    {
        $client = $this->getMock('\\Ivory\\HttpAdapter\\HttpAdapterInterface');
        $client->expects($this->once())->method('post')->will($this->returnValue(TestHelper::createStringResponse('error=bar')));

        $token = $this->getMock('\\OAuth\\OAuth1\\Token\\TokenInterface');

        $storage = $this->getMock('\\OAuth\\Common\\Storage\\TokenStorageInterface');
        $storage->expects($this->any())->method('retrieveAccessToken')->will($this->returnValue($token));

        $service = new Etsy(
            $this->getMock('\\OAuth\\Common\\Consumer\\CredentialsInterface'),
            $client,
            $storage,
            $this->getMock('\\OAuth\\OAuth1\\Signature\\SignatureInterface')
        );

        $this->setExpectedException('\\OAuth\\Common\\Http\\Exception\\TokenResponseException');

        $service->requestAccessToken('foo', 'bar', $token);
    }

    /**
     * @covers OAuth\OAuth1\Service\Etsy::__construct
     * @covers OAuth\OAuth1\Service\Etsy::getRequestTokenEndpoint
     * @covers OAuth\OAuth1\Service\Etsy::parseAccessTokenResponse
     */
    public function testParseAccessTokenResponseValid()
    {
        $client = $this->getMock('\\Ivory\\HttpAdapter\\HttpAdapterInterface');
        $client->expects($this->once())->method('post')->will($this->returnValue(
            TestHelper::createStringResponse('oauth_token=foo&oauth_token_secret=bar')
        ));

        $token = $this->getMock('\\OAuth\\OAuth1\\Token\\TokenInterface');

        $storage = $this->getMock('\\OAuth\\Common\\Storage\\TokenStorageInterface');
        $storage->expects($this->any())->method('retrieveAccessToken')->will($this->returnValue($token));

        $service = new Etsy(
            $this->getMock('\\OAuth\\Common\\Consumer\\CredentialsInterface'),
            $client,
            $storage,
            $this->getMock('\\OAuth\\OAuth1\\Signature\\SignatureInterface')
        );

        $this->assertInstanceOf('\\OAuth\\OAuth1\\Token\\StdOAuth1Token', $service->requestAccessToken('foo', 'bar', $token));
    }
}
