<?php

use OAuth\Common\Consumer\Credentials;
use OAuth\Common\Http\Client\CurlClient;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Storage\Session;
use OAuth\Helper\Example;
use OAuth\OAuth2\Service\Slack;

require_once __DIR__.'/../bootstrap.php';

$helper = new Example();
$storage = new Session();
$client = new CurlClient();

// actions to perform on your slack workspace :
// go to https://api.slack.com/apps and create an app
// under OAuth & Permissions set http://localhost:8000/provider/slack.php as reply url
// under Scopes add identity.basic and identity.email to recover user's data


if (empty($_GET)) {
    echo $helper->getContent();
} elseif (!empty($_GET['key']) && !empty($_GET['secret']) && $_GET['oauth'] !== 'redirect') {
    echo $helper->getHeader();
    try {
        $credentials = new Credentials($_GET['key'], $_GET['secret'], $helper->getCurrentUrl());
        $slack =new Slack($credentials, $client, $storage,  array(Slack::SCOPE_ID_BASIC, Slack::SCOPE_ID_EMAIL));

        echo '<a href="'.$slack->getAuthorizationUri().'">get access token</a>';
    } catch (\Exception $exception) {
        $helper->getErrorMessage($exception);
    }
    echo $helper->getFooter();
} elseif (!empty($_GET['code'])) {
    $credentials = new Credentials($_GET['key'], $_GET['secret'], $helper->getCurrentUrl());
    $slack =new Slack($credentials, $client, $storage,  array(Slack::SCOPE_ID_BASIC, Slack::SCOPE_ID_EMAIL));

    echo $helper->getHeader();
    try {
        $token = $slack->requestAccessToken($_GET['code']);
        echo 'access token: ' . $token->getAccessToken() . '<br>';
        
        $result = json_decode($slack->request('users.identity'), true);
        //    Show some of the resultant data
        echo 'Your slack name is ' . $result['user']['name'] . ' and your email is ' . $result['user']['email'] . '<br>';
        echo 'You logged in with slack workspace id = ' . $result['team']['id'] . '<br>';
        echo "Full response :<pre>" . json_encode($result, JSON_PRETTY_PRINT) . '</pre>';        

    } catch (TokenResponseException $exception) {
        $helper->getErrorMessage($exception);
    }
    echo $helper->getFooter();
}
