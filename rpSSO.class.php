<?php
class rpSSO {
	var $crypt;
	var $rpUrl;
	var $rpUser;
	var $rpPass;
	var $rpBid;
	var $rpSid;

	public function __construct($key, $rpUrl) {
		if ($key == 'secretkey') {
			die('For gods sake, would you please change that default encryption key?!');
		}

		$this->crypt = new rpSSO_Encryption($key);
		$this->rpUrl = $rpUrl;
	}

	public function auth($rpUser, $rpPass) {
		$this->rpUser = $rpUser;
		$this->rpPass = $rpPass;

		// construct the post-fields
		$fields = array(
			'_login[action]' => 'auth',
			'_login[user]' => $this->rpUser,
			'_login[pass]' => $this->rpPass,
			'_login[button]' => ' Anmelden',
			'js_call' => '1',
		);

		// url-ify the data for the POST
		foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
		rtrim($fields_string, '&');

		// open connection
		$ch = curl_init();

		// set the url, number of POST vars, POST data
		// and specify to get the header and the body
		curl_setopt($ch, CURLOPT_URL, $this->rpUrl);
		curl_setopt($ch, CURLOPT_POST, count($fields));
		curl_setopt($ch, CURLOPT_POSTFIELDS, $fields_string);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_HEADER, 1);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);

		// execute
		$result = curl_exec($ch);

		// separate header from body-content
		list($headers, $content) = explode("\r\n\r\n", $result, 2);

		//close connection
		curl_close($ch);

		// retrieve ALL the data
		$this->rpBid = self::get_bid($headers);
		$this->rpSid = self::get_sid($content);
	}

	private function get_bid($headers) {
		// get all cookies and extract bid
		preg_match('/^Set-Cookie: (.*?);/m', $headers, $m);
		$cookies = parse_url($m[1]);
		$cookies = explode('=', $cookies['path']);

		for ($i = 0; $i < count($cookies); $i++) {
			if ($cookies[$i] == 'bid') {
				$bid = $cookies[++$i];
				break;
			}
		}

		return $bid;
	}

	public function bid() {
		return $this->rpBid;
	}

	private function get_sid($content) {
		$content = json_decode($content);
		return $content->_sid;
	}

	public function sid() {
		return $this->rpSid;
	}

	public function create_challenge($validity = '30') {
		// construct the challenge-token
		$challenge = array(
				'bid'   => $this->rpBid,
				'sid'   => $this->rpSid,
		   		'valid' => time() + $validity);
		
		// convert token into importable plaintext
		$challenge = var_export($challenge, true);
		
		// add rpSSO-tag
		$challenge .= 'rpSSO';
		
		// encode that stuff
		$challenge = $this->crypt->encode($challenge);

		return $challenge;
	}

	public function check_challenge($challenge, $ignoretime = false) {
		$challenge = $this->crypt->decode($challenge);
		
		// check for rpSSO-tag
		if (substr($challenge, -5) == 'rpSSO') {
			// convert array-string back to array
			eval('$challenge = ' . substr($challenge, 0, -5) . ';');
			
			// check if challenge still valid by time
			if ( ($ignoretime == false) && (time() > $challenge['valid']) ) {
				$challenge = false;
			}
		} else {
			$challenge = false;
		}
	
		return $challenge;
	}

	public function get_sso($validity = '30') {
		return $this->rpUrl . 'sso/' . $this->create_challenge($validity);
	}

	public function do_sso($challenge, $target = '_info/') {
		setcookie('bid', $challenge['bid'], 0, '/');
		header('Location: ' . $this->rpUrl . $challenge['sid'] . '/' . $target);
		return;
	}


}

// Source: http://www.99points.info/2010/06/php-encrypt-decrypt-functions-to-encrypt-url-data/
class rpSSO_Encryption {
	var $skey;

	public function __construct($skey) {
		$this->skey = $skey;
	}

	private function safe_b64encode($string) {
		$data = base64_encode($string);
		$data = str_replace(array('+', '/', '='), array('-', '_', ''), $data);

		return $data;
	}

	private function safe_b64decode($string) {
		$data = str_replace(array('-', '_'), array('+', '/'), $string);
		$mod4 = strlen($data) % 4;

		if ($mod4) {
			$data .= substr('====', $mod4);
		}

		return base64_decode($data);
	}

	public function encode($value){ 
		if (!$value) {
			return false;
		}

		$text = $value;
		$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
		$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
		$crypttext = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $this->skey, $text, MCRYPT_MODE_ECB, $iv);

		return trim($this->safe_b64encode($crypttext)); 
	}

	public function decode($value){
		if (!$value) {
			return false;
		}

		$crypttext = $this->safe_b64decode($value); 
		$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
		$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
		$decrypttext = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $this->skey, $crypttext, MCRYPT_MODE_ECB, $iv);

		return trim($decrypttext);
	}
}
?>
