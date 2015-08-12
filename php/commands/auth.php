<?php
/**
 * Authenticate to Pantheon and store a local secret token.
 *
 */
 use Terminus\Request as Request;
 use Terminus\Utils;
 use Symfony\Component\DomCrawler\Crawler;
 use Guzzle\Parser\Cookie\CookieParser;
 use Terminus\Session;



class Auth_Command extends Terminus_Command {
  private $sessionid;
  private $session_cookie_name='X-Pantheon-Session';
  private $uuid;
  private $logged_in = false;

  // @TODO: move these somewhere better
  private $auth0_client_id = 'cTvdf4b1fAdaYRyMM5U2cCZx1Pkm74xl';
  private $auth0_domain = 'nodesquirrel.auth0.com';
  private $auth0_callback = 'http://localhost/callback';

  /**
   * Log in as a user
   *
   *  ## OPTIONS
   * [<email>]
   * : Email address to log in as.
   *
   * [--password=<value>]
   * : Log in non-interactively with this password. Useful for automation.
   * [--session=<value>]
   * : Authenticate using an existing session token
   * [--refresh=<value>]
   * : Authenticate using an refresh token
   * [--debug]
   * : dump call information when logging in.
   */
  public function login( $args, $assoc_args ) {
    # First try to login using a session token if provided
    if (isset($assoc_args['session'])) {
      Terminus::line( "Validating session token" );
      $data = $this->doLoginFromSessionToken($assoc_args['session']);
      if ( $data != FALSE ) {
        if (array_key_exists("debug", $assoc_args)){
          $this->_debug(get_defined_vars());
        }
        Terminus::line( "Logged in as ". $data['email'] );
        Terminus::launch_self("art", array("fist"));
      }
      else {
        Terminus::error( "Login Failed!" );
      }
      return;
    }

    // If a refresh token was passed in then try that.
    if (isset($assoc_args['refresh'])) {
      Terminus::line( "Setting refresh token" );
      $this->setRefreshToken($assoc_args['refresh']);
      return;
    }

    // If an email was sent then allow an email/password login
    if ( empty( $args ) ) {
      $this->startBrowserLogin();
      return;
    }
    // Otherwise do a normal email/password-based login
    else {
      $email = $args[0];
    }

    if ( \Terminus\Utils\is_valid_email( $email ) ) {
      if ( !isset( $assoc_args['password'] ) ) {
        exec("stty -echo");
        $password = Terminus::prompt( "Your dashboard password (input will not be shown)" );
        exec("stty echo");
        Terminus::line();
      }
      else {
        $password = $assoc_args['password'];
      }
      Terminus::line( "Logging in as $email" );
      $data = $this->doLogin($email, $password);

      if ( $data != FALSE ) {
        if (array_key_exists("debug", $assoc_args)){
          $this->_debug(get_defined_vars());
        }
        Terminus::launch_self("art", array("fist"));
      }
      else {
        Terminus::error( "Login Failed!" );
      }
    }
    else {
      Terminus::error( "Error: invalid email address" );
    }
  }

  /**
   * Refresh the session token using the stored refresh token.
   */
  public function refresh() {
    // Refresh the id_token.
    $this->getIDToken(true);
  }

  /**
   * Log yourself out and remove the secret session key.
   */
  public function logout() {
    Terminus::line( "Logging out of Pantheon." );
    $this->cache->remove('session');
  }

  /**
   * Find out what user you are logged in as.
   */
  public function whoami() {
    if (Session::getValue('email')) {
      Terminus::line( "You are authenticated as ". Session::getValue('email') );
    }
    else {
      Terminus::line( "You are not logged in." );
    }
  }

  private function _checkSession() {
    if ((!property_exists($this, "session")) || (!property_exists($this->session, "user_uuid"))) {
      return false;
    }
    $results = $this->terminus_request("user", $this->session->user_uuid, "profile", "GET");
    if ($results['info']['http_code'] >= 400){
      Terminus::line("Expired Session, please re-authenticate.");
      $this->cache->remove('session');
      Terminus::launch_self("auth", array("login"));
      $this->whoami();
      return true;
    } else {
      return (($results['info']['http_code'] <= 199 )||($results['info']['http_code'] >= 300 ))? false : true;
    }
  }

  /**
   * Execute the login based on email,password
   *
   * @param $email string (required)
   * @param $password string (required)
   * @package Terminus
   * @version 0.04-alpha
   * @return string
   */
  private function doLogin($email,$password) {
    $options = array(
        'body' => json_encode(array(
          'email' => $email,
          'password' => $password,
        )),
        'headers' => array('Content-type'=>'application/json'),
    );

    $response = Terminus_Command::request('login','','','POST',$options);
    if($response['status_code'] != '200') {
      \Terminus::error("[auth_error]: unsuccessful login");
    }

    // Prepare credentials for storage.
    $data = array(
      'user_uuid' => $response['data']->user_id,
      'session' => $response['data']->session,
      'session_expire_time' => $response['data']->expires_at,
      'email' => $email,
    );
    // creates a session instance
    Session::instance()->setData($data);
    return $data;
  }


  /**
   * Execute the login based on an existing session token
   *
   * @param $session_token string (required)
   * @return array
   */
  private function doLoginFromSessionToken($session_token)
  {

    $options = array(
        'headers' => array('Content-type'=>'application/json'),
        'cookies' => array('X-Pantheon-Session' => $session_token),
    );

    # Temporarily disable the cache for this GET call
    Terminus::set_config('nocache',TRUE);
    $response = Terminus_Command::request('user', '', '', 'GET', $options);
    Terminus::set_config('nocache',FALSE);

    if ( !$response OR '200' != @$response['info']['http_code'] ) {
      \Terminus::error("[auth_error]: session token not valid");
    }

    // Prepare credentials for storage.
    $data = array(
      'user_uuid' => $response['data']->id,
      'session' => $session_token,
      'session_expire_time' => 0, # there is not an API to provide this for a given session token
      'email' => $response['data']->email,
      'token_type' => 'X-Pantheon-Session',
    );

    // creates a session instance
    Session::instance()->setData($data);
    return $data;
  }


  /**
   * Initialize the browser-based oauth login procedure.
   */
  private function startBrowserLogin() {
    $default = 'Terminus CLI';
    $device = Terminus::prompt("What would you like to name this instance of Terminus? (default: '$default')", NULL, $default);

    // @TODO: Abstract this to a redirect
    $url = 'https://' . $this->auth0_domain . '/authorize?response_type=token&client_id='
      . $this->auth0_client_id . '&redirect_uri=' . $this->auth0_callback . '&device=' . urlencode($device) . '&scope=openid+offline_access';

    Terminus::line("To log in please visit the following url in a web browser:");
    Terminus::line($url);
  }

  /**
   * Store the a refresh token to allow login without an email and password.
   */
  private function setRefreshToken($refresh) {
    // @TODO: Validate the refresh token to ensure it works.

    $cache = Terminus::get_cache();
    // Save the token to the cache.
    $cache->put_data('auth_refresh_token', $refresh);

    // Refresh the id_token.
    $this->getIDToken(true);
  }

  /**
   * Get the id_token to be used for an API call.
   *
   * @param boolean $force_refresh
   *  Force the id token to be regenerated even if there is an unexpired one stored.
   *  This can be used if a seemingly valid token does not work.
   *
   * @return string|null
   *  A JWT token that can be used to make API requests or null if there was an error.
   */
  public function getIDToken($force_refresh = false) {
    // If we already have a valid id token stored then return it.
    $session = Session::instance();
    if (!$force_refresh && ($session->getValue('session', false))) {
      $expiration = $session->getValue('session_expire_time', false);
      if (!$expiration || $expiration > time()) {
        // @TODO: Check if this session token actually works so it can be regenerated if needed.
        return $session->getValue('session', false);
      }
    }

    // If we have a refresh token use it to generate an id_token.
    $cache = Terminus::get_cache();
    $refresh = $cache->get_data('auth_refresh_token');
    if ($info = $this->getAuthTokenFromRefreshToken($refresh)) {
      // Prepare credentials for storage.
      $data = array(
        'session' => $info['id_token'],
        'token_type' => $info['token_type']
      );
      // Add the expiration if there is any.
      if (!empty($info['expires_in'])) {
        $data['session_expire_time'] = time() + $info['expires_in'];
      }

      // Query for email/uuid.
      // @TODO: Inspect the JWT for this.
      $options = array(
        'headers' => array('Content-type'=>'application/json', 'Bearer' => $info['id_token']),
      );
      # Temporarily disable the cache for this GET call
      Terminus::set_config('nocache',TRUE);
      $response = Terminus_Command::request('user', '', '', 'GET', $options);
      Terminus::set_config('nocache',FALSE);

      if ( !$response OR '200' != @$response['info']['http_code'] ) {
        \Terminus::error("[auth_error]: session token not valid");
      }

      // Prepare credentials for storage.
      $data['user_uuid'] = $response['data']->id;
      $data['email'] = $response['data']->id;

      // creates a session instance
      Session::instance()->setData($data);
      return $info['id_token'];
    }
    return null;
  }

  /**
   * Get a
   * @param $refresh_token
   * @return \Guzzle\Http\EntityBodyInterface|null|string
   */
  private function getAuthTokenFromRefreshToken($refresh_token) {
    if (!$refresh_token) {
      // @TODO: Offer a remedy in this error message
      \Terminus::error("[auth_error]: There is no refresh token.");
      return null;
    }

    // Assemble the parameters needed to request a JWT access token.
    $url = 'https://' . $this->auth0_domain . '/delegation';
    $body = array(
      'client_id' => $this->auth0_client_id,
      'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      'refresh_token' => $refresh_token,
      'target' => $this->auth0_client_id,
      'scope' => 'openid email pnth_uid',
      'api_type' => 'app',
    );

    // Retrieve a JWT token from the authentication server.
    $options = array(
      'json' => true,
      'body' => json_encode($body),
      'headers' => array(
        'Content-Type' => 'application/json'
      )
    );
    $resp = Request::send($url, 'POST', $options);
    $json = $resp->getBody(true);
    if ($info = json_decode($json)) {
      if (isset($info->id_token)) {
        return (array)$info;
      }
    }

    // @TODO: Offer a remedy in this error message
    \Terminus::error("[auth_error]: The saved refresh token is invalid.");
    return null;
  }
}

Terminus::add_command( 'auth', 'Auth_Command' );
