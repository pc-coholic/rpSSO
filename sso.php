<?php
require_once('rpSSO.class.php');

$rpSSO = new rpSSO('secretkey', 'http://your.rp.url.tld/');

$challenge = explode('/', $_GET['challenge']);

if (empty($challenge[0])) {
	die('No challenge specified');
} elseif (empty($challenge[1])) {
	die('No hmac specified');
} elseif (empty($challenge[2])) {
	die('No IV specified');
}

// check challenge-request
$challenge = $rpSSO->check_challenge($challenge[0], $challenge[1], $challenge[2]);

if ($challenge != false) {
	$rpSSO->do_sso($challenge);
} else {
	die('Invalid challenge');
}
?>
