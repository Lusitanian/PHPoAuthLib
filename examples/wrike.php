<?php

/**
 * Example of retrieving an authentication token of the Wrike API service
 *
 * @author  Ádám Bálint <adam.balint@srg.hu>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link    https://developers.wrike.com/documentation
 */

use OAuth\OAuth2\Service\Wrike;
use OAuth\Common\Storage\Session;
use OAuth\Common\Consumer\Credentials;

/**
 * Bootstrap the example
 */
require_once __DIR__ . '/bootstrap.php';

// Session storage
$storage = new Session();

// Set scopes
$scopes = array(Wrike::SCOPE_DEFAULT);

// Setup the credentials for the requests
$credentials = new Credentials(
	$servicesCredentials['wrike']['key'],
	$servicesCredentials['wrike']['secret'],
	$currentUri->getAbsoluteUri()
);

// Instantiate the Wrike API service using the credentials, http client and storage mechanism for the token
/**
 * @var $wrikeService Wrike
 */
$wrikeService = $serviceFactory->createService('wrike', $credentials, $storage, $scopes);

if (!empty($_GET['code'])) {
	// retrieve the CSRF state parameter
	$state = isset($_GET['state']) ? $_GET['state'] : null;

	// This was a callback request from Wrike API service, get the token
	$token = $wrikeService->requestAccessToken($_GET['code'], $state);

	// Send a request with it
	$result = json_decode($wrikeService->request('/version'), true);

	echo 'The currently used API version is '.$result['data'][0]['major'];

} elseif (!empty($_GET['go']) && $_GET['go'] === 'go') {

	$url = $wrikeService->getAuthorizationUri();
	header('Location: ' . $url);

} else {

	$url = $currentUri->getRelativeUri() . '?go=go';
	echo "<a href='$url'>Login with Wrike!</a>";

}
