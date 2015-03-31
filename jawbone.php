<?php





class Keyring_Service_Jawbone extends Keyring_Service_OAuth2 {
	const NAME  = 'jawbone';
	const LABEL = 'Jawbone';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_jawbone_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_jawbone_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->set_endpoint( 'authorize',    'https://jawbone.com/auth/oauth2/auth',   'GET'  );
		$this->set_endpoint( 'access_token', 'https://jawbone.com/auth/oauth2/token',       'POST' );
		$this->set_endpoint( 'user',         'https://jawbone.com/nudge/api/v.1.1/users/@me',    'GET'  );

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->authorization_header    = 'Bearer';
		$this->authorization_parameter = false;
	}

	function basic_ui_intro() {
		echo '<p>' . sprintf( __( 'You\'ll need to <a href="%s">register a new application</a> on Jawbone so that you can connect.', 'keyring' ), 'https://jawbone.com/up/developer/' ) . '</p>';
		echo '<p>' . __( "Once you've registered your application, copy the <strong>Client ID</strong> into the <strong>App ID </strong> field below, and the <strong>Client Secret</strong> value into <strong>API Secret</strong>.", 'keyring' ) . '</p>';
	}

	function build_token_meta( $token ) {
		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				$token['access_token'],
				array()
			)
		);
		$response = $this->request( $this->user_url, array( 'method' => $this->user_method ) );
		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			// Only useful thing in that request is userID
			$meta = array(
				'user_id' => $response->data->xid,
				'name' => $response->data->first . " " . $response->data->last,
				'picture' => 'https://jawbone.com/' . $response->data->image
			);

			return apply_filters( 'keyring_access_token_meta', $meta, 'jawbone', $token, $profile, $this );
		}
		return array();
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Jawbone', 'init' ) );