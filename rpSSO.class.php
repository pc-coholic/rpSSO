<?php
/**
 * rpSSO 
 *
 * Class to provide some kind of SingleSignOn-capability for
 * the ResellerProfessional2 by domainFACTORY
 *
 * @package 
 * @version $id$
 * @copyright 2012 PC-Coholic.de / Martin Gross
 * @author Martin Gross <martin@pc-coholic.de> 
 * @license GNU GPLv3 {@link http://www.gnu.org/licenses/gpl.html}
 */
class rpSSO {
	var $crypt;
	var $rpUrl;
	var $rpUser;
	var $rpPass;
	var $rpBid;
	var $rpSid;

	/**
	 * __construct 
	 *
	 * Consturctor must be called with a secret key that is used for
	 * encrypting authentificaton-data that is being passed in the wild.
	 *
	 * The rpURL should be complete with http:// and a trailing slash, i.e.
	 * http://123456.premium-admin.eu/
	 * You can also use your .htaccess-"masked" access-URL (and probably
	 * should), because only your .htaccess-RP is SSO-enabled.
	 *
	 * @param mixed $key 
	 * @param mixed $rpUrl 
	 * @access public
	 * @return void
	 */
	public function __construct($key, $rpUrl) {
		if ($key == 'secretkey') {
			die('For gods sake, would you please change that default encryption key?!');
		}

		$this->crypt = new rpSSO_Encryption($key);
		$this->rpUrl = $rpUrl;
	}

	/**
	 * auth 
	 * 
	 * Authenticate any given user against the RP2-backend.
	 * For SSO, where you don't know the users credentials, you probably
	 * want to use an administative user, i.e. admin-12345:7 where 7 is the users
	 * customer-number or own login.
	 *
	 * The password should always be the users password. Using the
	 * admin:user-login, you would need to provide the admin-password, not the
	 * user-password (we are doing SSO here, right?!)
	 *
	 * Function returns false if login failed.
	 *
	 * @param mixed $rpUser 
	 * @param mixed $rpPass 
	 * @access public
	 * @return true | false
	 */
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

		// emtpy sid is a sign of failed login
		if (empty($this->rpSid)) {
			return false;
		} else {
			return true;
		}
	}

	/**
	 * get_bid 
	 * 
	 * Takes a set of curl-getted HTTP-headers to extract the bid-cookie.
	 * 
	 * As a bid is always returned, even if the login was unseccessfully, don't
	 * rely on this for a decisson login sucessfull/unsucessfull! use ::auth()
	 * for this!
	 * 
	 * @param mixed $headers 
	 * @access private
	 * @return string
	 */
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

	/**
	 * bid 
	 * 
	 * Returns the bid.
	 *
	 * As a bid is always returned, even if the login was unseccessfully, don't
	 * rely on this for a decisson login sucessfull/unsucessfull! use ::auth()
	 * for this!
	 *
	 * @access public
	 * @return string
	 */
	public function bid() {
		return $this->rpBid;
	}

	/**
	 * get_sid 
	 *
	 * Takes the whole body of a RP2-RW-API-JSON-answer and extracts the sid, if
	 * one is set. If no JSON is present, the login probably failed. In that case,
	 * there also won't be any sid.
	 *
	 * @param mixed $content 
	 * @access private
	 * @return string
	 */
	private function get_sid($content) {
		$content = json_decode($content);
		return $content->_sid;
	}

	/**
	 * sid 
	 * 
	 * Returns the sid
	 *
	 * If no sid is returned, the authentification probably was not successfull.
	 *
	 * @access public
	 * @return string
	 */
	public function sid() {
		return $this->rpSid;
	}

	/**
	 * create_challenge 
	 * 
	 * Create a challenge-code, aka: encrypted set of bid and sid that is used to
	 * log in the authenticated user from any other location.
	 *
	 * If do not provide a validity, the token expires 30 seconds from generation.
	 *
	 * This validity is only enforced by the rpSSO-class itself and does not
	 * physically limit the session directly in the RP2-backend.
	 *
	 * @param string $validity 
	 * @access public
	 * @return string
	 */
	public function create_challenge($validity = '30') {
		// construct the challenge-token
		$challenge['key'] = array(
				'bid'   => $this->rpBid,
				'sid'   => $this->rpSid,
		   		'valid' => time() + $validity);
		
		// convert token into importable plaintext
		$challenge['key'] = serialize($challenge['key']);
		
		// add rpSSO-tag
		$challenge['key'] .= 'rpSSO';
		
		// encode that stuff and get the encrypted data and IV
		$crypted = $this->crypt->encode($challenge['key']);
		$challenge['key'] = $crypted['data'];
		$challenge['iv'] = $crypted['iv'];

		// create a HMAC-signature
		$challenge['hmac'] = $this->crypt->hmac($challenge['key']);

		return $challenge;
	}

	/**
	 * check_challenge 
	 * 
	 * Checks a provided SSO-challenge. This includes, the decryption of the
	 * challenge, the verification of the rpSSO-tag, converting it back into an
	 * array and checking the included expire-date.
	 *
	 * If you chose to "true" $ignoretime, the last check will be omitted and the
	 * challenge will be deemed valid even if expired.
	 *
	 * If you do so and your challenge is too old, it however might still be
	 * expired in the RP2-backend and be rejected.
	 *
	 * Returns the unencrypted challenge-array consisting of bid, sid and validity
	 * or just false.
	 *
	 * @param mixed $challenge 
	 * @param mixed $hmac 
	 * @param mixed $iv 
	 * @param mixed $ignoretime 
	 * @access public
	 * @return false | array
	 */
	public function check_challenge($challenge, $hmac, $iv, $ignoretime = false) {
		// Check hmac
		if ($hmac != $this->crypt->hmac($challenge)) {
			return false;
		}

		$challenge = $this->crypt->decode($challenge, $iv);

		// check for rpSSO-tag
		if (substr($challenge, -5) == 'rpSSO') {
			// convert array-string back to array
			$challenge = unserialize(substr($challenge, 0, -5));
			
			// check if challenge still valid by time
			if ( ($ignoretime == false) && (time() > $challenge['valid']) ) {
				$challenge = false;
			}
		} else {
			$challenge = false;
		}
	
		return $challenge;
	}

	/**
	 * get_sso 
	 *
	 * Create and return a complete link-target including a SSO-challenge. Even
	 * here, you can choose to superseed the default validity of 30 seconds by
	 * setting $validity.
	 *
	 * @param string $validity 
	 * @access public
	 * @return string
	 */
	public function get_sso($validity = '30') {
		$challenge = $this->create_challenge($validity);
		return $this->rpUrl . 'sso/' . $challenge['key'] . '/' . $challenge['hmac'] . '/' . $challenge['iv']; 
	}

	/**
	 * do_sso 
	 * 
	 * Actually perform the SSO-login based on an _unencrypted_ challange-array
	 * consisting of bid, sid and validity. In fact, last one is not checked here
	 * anymore - you should already have done this in ::check_challenge().
	 *
	 * You may set a target, where the user is forwarded to; it defaults to _info,
	 * which is the account-overview for admins and users alike.
	 *
	 * @param mixed $challenge 
	 * @param string $target 
	 * @access public
	 * @return void
	 */
	public function do_sso($challenge, $target = '_info/') {
		setcookie('bid', $challenge['bid'], 0, '/');
		header('Location: ' . $this->rpUrl . $challenge['sid'] . '/' . $target);
		return;
	}


}

/**
 * rpSSO_Encryption 
 *
 * Nifty class to provide URL-safe encryption using a secret key.
 *
 * Based on the Code of Zeeshan Rasool with some minor changes.
 *
 * @package 
 * @version $id$
 * @author Zeeshan Rasool <zeeshan@99points.info>
 * @author Martin Gross <martin@pc-coholic.de> 
 * @source {@link http://www.99points.info/2010/06/php-encrypt-decrypt-functions-to-encrypt-url-data/}
 * @license GNU GPLv3 {@link http://www.gnu.org/licenses/gpl.html}
 */
class rpSSO_Encryption {
	var $skey;

	/**
	 * __construct 
	 *
	 * Y U NO SETUP key to use with encryption?!
	 *
	 * @param mixed $skey 
	 * @access public
	 * @return void
	 */
	public function __construct($skey) {
		$this->skey = $skey;
	}

	/**
	 * safe_b64encode
	 * 
	 * Takes an existing encrypted string and makes it URL-safe.
	 * You really want to use this to not fuckup your data.
	 * 
	 * Does not need to be called directly as the ::encode()-function already
	 * takes care of this.

	 * @param mixed $string 
	 * @access private
	 * @return string
	 */
	private function safe_b64encode($string) {
		$data = base64_encode($string);
		$data = str_replace(array('+', '/', '='), array('-', '_', ''), $data);

		return $data;
	}

	/**
	 * safe_b64decode 
	 * 
	 * Takes an existing encrypted URL-safe string and converts it back.
	 * You really want to use this to not fuckup your data.
	 * 
	 * Does not need to be called directly as the ::decode()-function already
	 * takes care of this.

	 * @param mixed $string 
	 * @access private
	 * @return string
	 */
	private function safe_b64decode($string) {
		$data = str_replace(array('-', '_'), array('+', '/'), $string);
		$mod4 = strlen($data) % 4;

		if ($mod4) {
			$data .= substr('====', $mod4);
		}

		return base64_decode($data);
	}

	/**
	 * encode 
	 *
	 * Encodes your data and makes it URLsafe.
	 *
	 * @param mixed $value 
	 * @access public
	 * @return false | string
	 */
	public function encode($value){ 
		if (!$value) {
			return false;
		}

		$text = $value;
		$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC);
		$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
		$crypttext = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $this->skey, $text, MCRYPT_MODE_CBC, $iv);
		
		$return['data'] = trim($this->safe_b64encode($crypttext));
		$return['iv'] = trim($this->safe_b64encode($iv));
		return $return; 
	}

	/**
	 * decode 
	 *
	 * Decode encrypted data and remove URL-safe-stuff if needed.
	 *
	 * @param mixed $value 
	 * @param mixed $iv 
	 * @access public
	 * @return false | string
	 */
	public function decode($value, $iv){
		if (!$value) {
			return false;
		}

		$crypttext = $this->safe_b64decode($value); 
		$iv = $this->safe_b64decode($iv);
		$decrypttext = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $this->skey, $crypttext, MCRYPT_MODE_CBC, $iv);

		return trim($decrypttext);
	}

	/**
	 * hmac  
	 *
	 * Generate a keyed hash value using the HMAC-method
	 *
	 * @param mixed $value 
	 * @access public
	 * @return false | string
	 */
	public function hmac($value) {
		if (!$value) {
			return false;
		}

		$hmac = hash_hmac('sha256', $value, $this->skey);

		return $hmac;
	}
}
?>
