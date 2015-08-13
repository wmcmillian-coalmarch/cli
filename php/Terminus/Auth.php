<?php
namespace Terminus;

use Terminus\FileCache;
use Terminus;
use Terminus\Session;
use Terminus_Command;

class Auth {

  /**
   * Ensure the user is logged in or die with an error.
   *
   * @return bool
   */
  public static function loggedIn() {
    // If there a saved, valid session token then return true.
    if (Auth::getSavedAuthToken()) {
      return true;
    }

    // Attempt to generate or retrieve a session token from a refresh if available.
    if (Auth::getAuthToken(true)) {
      return true;
    }

    // Otherwise die with a warning.
    \Terminus::error("Please login first with `terminus auth login`");
  }

  /**
   * Store the a refresh token to allow login without an email and password.
   *
   * @param $refresh string
   *  The refresh token to be stored and used to generate session auth tokens.
   */
  public static function setRefreshToken($refresh) {
    // Save the token to the cache.
    Terminus::get_cache()->put_data('auth_refresh_token', $refresh);

    // Refresh the id_token. This makes sure refresh token is invalid.
    Auth::getAuthToken(true);
  }

  /**
   * Get the stored session token.
   *
   * @return mixed
   */
  public static function getSavedAuthToken() {
    $auth_token = Session::getValue('session', false);
    if ($auth_token === false) {
      return FALSE;
    }
    $expiration = Session::getValue('session_expire_time', false);
    if (!$expiration || $expiration > time()) {
      return $auth_token;
    }
    return FALSE;
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
  public static function getAuthToken($force_refresh = false) {

    // If we already have a valid id token stored then return it.
    if (!$force_refresh && $auth_token = Auth::getSavedAuthToken()) {
      return $auth_token;
    }

    // If we have a refresh token use it to generate an id_token.
    $refresh = Terminus::get_cache()->get_data('auth_refresh_token');
    if ($info = Auth::getAuthTokenFromRefreshToken($refresh)) {
      // Prepare credentials for storage.
      $data = array(
        'session' => $info['id_token'],
        'token_type' => $info['token_type']
      );
      // Add the expiration if there is any.
      if (!empty($info['expires_in'])) {
        $data['session_expire_time'] = time() + $info['expires_in'];
      }

      // Query the API for email/uuid.
      // @TODO: We may be able to inspect the JWT for this.
      $options = array('auth_token' => $info['id_token']);
      # Temporarily disable the cache for this GET call
      Terminus::set_config('nocache',TRUE);
      $response = Terminus_Command::request('user', '', '', 'GET', $options);
      Terminus::set_config('nocache',FALSE);
      if (!$response OR '200' != @$response['info']['http_code']) {
        \Terminus::error("[auth_error]: Could not generate a session. Try logging in again or adding another refresh token.");
      }

      // Prepare credentials for storage.
      $data['user_uuid'] = $response['data']->id;
      $data['email'] = $response['data']->email;

      // Save the auth info to the session.
      Session::setData($data);

      return $info['id_token'];
    }
    return null;
  }

  /**
   * Get a
   * @param $refresh_token
   * @return \Guzzle\Http\EntityBodyInterface|null|string
   */
  public static function getAuthTokenFromRefreshToken($refresh_token) {
    if (!$refresh_token) {
      // @TODO: Offer a remedy in this error message
      \Terminus::error("[auth_error]: There is no refresh token.");
      return null;
    }

    // Assemble the parameters needed to request a JWT access token.
    $url = 'https://' . TERMINUS_AUTH0_DOMAIN . '/delegation';
    $body = array(
      'client_id' => TERMINUS_AUTH0_CLIENT_ID,
      'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      'refresh_token' => $refresh_token,
      'target' => TERMINUS_AUTH0_CLIENT_ID,
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
