<?php
require_once('rpSSO.class.php');

$rpsso = new rpSSO('secretkey', 'http://your.rp.url.tld/');

if (empty($_GET['challenge'])) {
	die('No challenge specified');
}

// check challenge-request
$challenge = $rpSSO->check_challenge($_GET['challenge']);

if ($challenge != false) {
	$rpSSO->do_sso($challenge);
} else {
	die('Invalid challenge');
}
?>
