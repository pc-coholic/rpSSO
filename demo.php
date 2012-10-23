<?php
require_once('rpSSO.class.php');

$rpSSO = new rpSSO('secretkey', 'http://your.rp.url.tld/');

if ($rpSSO->auth('admin-123456', 'PASSWORD')) {
	echo("Login successfull");
} else {
	echo("Login failed");
}
echo '<br><br>';
echo $rpSSO->bid();
echo '<br><br>';
echo $rpSSO->sid();
echo '<br><br>';
echo $rpSSO->create_challenge();
echo '<br><br>';
echo $rpSSO->get_sso();
echo '<br><br>';
#echo $rpSSO->do_sso($rpSSO->create_challenge());
echo '<br><br>';
?>
