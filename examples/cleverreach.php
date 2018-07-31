<?php

/**
 * Example of retrieving an authentication token of the CleverReach service
 *
 * PHP version 5.4
 *
 * @author     Moritz Beller <beller.moritz@googlemail.com>
 * @author     David Desberg <david@daviddesberg.com>
 * @author     Pieter Hordijk <info@pieterhordijk.com>
 * @copyright  Copyright (c) 2012 The authors
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use OAuth\OAuth2\Service\CleverReach;
use OAuth\Common\Storage\Session;
use OAuth\Common\Consumer\Credentials;

/**
 * Bootstrap the example
 */
require_once __DIR__ . '/bootstrap.php';

// Session storage
$storage = new Session();

// Setup the credentials for the requests
$credentials = new Credentials(
    $servicesCredentials['cleverreach']['key'],
    $servicesCredentials['cleverreach']['secret'],
    $currentUri->getAbsoluteUri()
);

// Instantiate the CleverReach service using the credentials, http client and storage mechanism for the token
/** @var $cleverReach CleverReach */
$cleverReach = $serviceFactory->createService('CleverReach', $credentials, $storage, array('basic', 'read', 'write'));

if (!empty($_GET['code'])) {
    // This was a callback request from cleverreach, fetch the token
    $cleverReach->requestAccessToken($_GET['code']);

    $groups = json_decode($cleverReach->request('/v2/groups'), true);

    echo 'your first group at cleverreach ' . $result[0];

} elseif (!empty($_GET['go']) && $_GET['go'] === 'go') {
    $url = $cleverReach->getAuthorizationUri();
    header('Location: ' . $url);

} else {
    $url = $currentUri->getRelativeUri() . '?go=go';
    echo "<a href='$url'>Login with CleverReach!</a>";
}
