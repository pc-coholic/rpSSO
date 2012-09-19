<?php
require_once('rpSSO.class.php');

$rpsso = new rpSSO('secretkey', 'http://your.rp.url.tld/');

$rpSSO->auth('admin-123456', 'PASSWORD');
echo $rpSSO->bid();
echo '<br><br>';
echo $rpSSO->sid();
echo '<br><br>';
echo $rpSSO->create_challenge();
echo '<br><br>';
echo $rpSSO->get_sso();
echo '<br><br>';
echo $rpSSO->do_sso($rpSSO->create_challenge());
echo '<br><br>';
?>
