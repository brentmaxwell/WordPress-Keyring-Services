<?php

class Keyring_Service_OneDrive extends Keyring_Service_OAuth2 {
	const NAME  = 'onedrive';
	const LABEL = 'OneDrive';
	const SCOPE = 'wl.basic wl.photos wl.skydrive wl.offline_access';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_onedrive_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_onedrive_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'authorize',    'https://login.live.com/oauth20_authorize.srf',   'GET'  );
		$this->set_endpoint( 'access_token', 'https://login.live.com/oauth20_token.srf',       'POST' );
		$this->set_endpoint( 'user',         'https://apis.live.net/v5.0/me',    'GET'  );

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->authorization_header    = 'Bearer';
		$this->authorization_parameter = false;
		
		add_filter( 'keyring_onedrive_request_token_params', array( $this, 'request_token_params' ) );
	}

	function basic_ui_intro() {
		echo '<p>' . sprintf( __( 'You\'ll need to <a href="%s">register a new application</a> on Live so that you can connect.', 'keyring' ), 'https://account.live.com/developers/applications/' ) . '</p>';
		echo '<p>' . __( "Once you've registered your application, copy the <strong>Client ID</strong> into the <strong>App ID </strong> field below, and the <strong>Client Secret</strong> value into <strong>API Secret</strong>.", 'keyring' ) . '</p>';
	}
	
	function request_token_params( $params ) {
		$params['scope'] = apply_filters( 'keyring_onedrive_scope', self::SCOPE );
		return $params;
	}


	function build_token_meta( $token ) {
		$expires = isset( $token['expires_in'] ) ? gmdate( 'Y-m-d H:i:s', time() + $token['expires_in'] ) : 0;
		
		$meta = array(
			'refresh_token' => $token['refresh_token'],
			'expires'       => $expires,
			'_classname'    => get_called_class(),
		);
		
		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				$token['access_token'],
				array()
			)
		);
		$response = $this->request( $this->user_url, array( 'method' => $this->user_method ) );
		if ( Keyring_Util::is_error( $response ) ) {
		} else {
			$meta['user_id'] = $response->id;
			$meta['name'] = $response->name;
		}
		return apply_filters( 'keyring_access_token_meta', $meta, 'onedrive', $token, $response, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );;
	}
	
	function test_connection() {
		$this->maybe_refresh_token();

		$res = $this->request( 'https://apis.live.net/v5.0/me' );
		if ( !Keyring_Util::is_error( $res ) )
			return true;

		return $res;
	}
	
	function maybe_refresh_token() {
		global $wpdb;

		if ( empty( $this->token->meta ) || empty( $this->token->meta['expires'] ) )
			return;
	
		if ( $this->token->meta['expires'] && $this->token->is_expired() ) {
			$api_url  = 'https://login.live.com/oauth20_token.srf';
			
			$refresh = $this->request( $api_url, array(
				'method'       => 'POST',
				'raw_response' => true,
				'body' => array(
					'client_id'=>$this->key,
					'client_secret'=>$this->secret,
					'redirect_uri'=>$this->callback_url,
					'refresh_token'=>$this->token->meta['refresh_token'],
					'grant_type'=>'refresh_token')
			) );

			if ( !Keyring_Util::is_error( $refresh ) ) {
				$token_id = $this->token->unique_id;
				$token = $this->parse_access_token( $refresh );

				// Fake request token
				global $keyring_request_token;
				$keyring_request_token = new Keyring_Request_Token(
					$this->get_name(),
					array()
				);
				// Build (real) access token
				
				$access_token = new Keyring_Access_Token(
					$this->get_name(),
					$token['access_token'],
					$this->build_token_meta( $token ),
					$token_id
				);
					// Store the updated access token
				$access_token = apply_filters( 'keyring_access_token', $access_token, $token );
				$id = $this->store->update( $access_token );
				// And switch to using it
				$this->set_token( $access_token );
			}
		}
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_OneDrive', 'init' ) );