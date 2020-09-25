<?php

/**
 * Example of retrieving an authentication token from the Xena service and using it
 * to get some data from Xena
 *
 * PHP version 5.4
 *
 * @author     Thomas Joergensen <thomas@xena.biz>
 */

use OAuth\OAuth2\Service\Xena;
use OAuth\Common\Storage\Session;
use OAuth\Common\Consumer\Credentials;

require_once __DIR__ . '/bootstrap.php';

// Session storage
$storage = new Session();

// Setup the credentials for the requests
$credentials = new Credentials(
    $servicesCredentials['xena']['key'],
    $servicesCredentials['xena']['secret'],
    $currentUri->getAbsoluteUri()
);

// Instantiate the Xena service using the credentials, http client and storage mechanism for the token
$xenaService = $serviceFactory->createService('xena', $credentials, $storage,  array('http://xena.biz'));

if (!empty($_GET['code'])) {
    // This was a callback request from Xena, get the token
    $xenaService->requestAccessToken($_GET['code']);

    // Make a request to get all(well, at least the first 100) fiscalsetups(businesses) from your account
    $result = json_decode($xenaService->request('/Api/User/FiscalSetup?PageSize=100'),true);

    //Show our findings to the user
    echo 'Accessible businesses:';
    echo '<table border=1><thead><tr><td>Company</td></tr></thead>';
    foreach ($result['Entities'] as $fiscalsetup) {
        echo '<tr><td>' . $fiscalsetup['Description'] . '</td></tr>';
    }
    echo '</table>';

} elseif (!empty($_GET['go']) && $_GET['go'] === 'go') {
    $url = $xenaService->getAuthorizationUri();
    header('Location: ' . $url);
} else {
    $url = $currentUri->getRelativeUri() . '?go=go';
    echo "<a href='$url'>Login with Xena!</a>";
}
