<?php

/**
 * ReCaptchaResponse is returned on every ReCaptcha->post()
 */
class ReCaptchaResponse {

    // Errors:
    //  invalid-site-private-key - triggered on invalid private key.
    const INVALID_PRIVATE_KEY   = 'invalid-site-private-key';
    //  incorrect-captcha-sol    - triggered on all kind of form errors - form is being resubmitted, the entered code is wrong and so on.
    const INCORRECT_CAPTCHA_SOL = 'incorrect-captcha-sol';
    //  invalid-site-public-key  - triggered on invalid public key.
    const INVALID_PUBLIC_KEY    = 'invalid-site-public-key';
    //  captcha-timeout          - triggered when the captcha form has expired.
    const CAPTCHA_TIMEOUT       = 'captcha-timeout';

    // check status
    private $is_valid = false;

    // incorrect-captcha-sol means the form contains invalid data (resubmitted, has a wrong code, etc)
    private $error = ReCaptchaResponse::INCORRECT_CAPTCHA_SOL;

    private $raw_response = '';

    /**
     * @param string $response
     */
    public function __construct($response = '') {
        if($response) {
            $this->raw_response = $response;
            $this->parseResponse();
        }
    }

    /**
     * Parse the response
     */
    protected function parseResponse() {
        $parse = explode( "\n", $this->raw_response );
        $this->is_valid = ($parse[0] == 'true' ? true : false);
        $this->error = $parse[1];
        if($this->error == ReCaptchaResponse::INVALID_PRIVATE_KEY)
            throw new ErrorException('Your private key is invalid and resolved in invalid-site-private-key error!');
    }

    /**
     * Check if the entered code was correct.
     * @return bool
     */
    public function isValid() {
        return $this->is_valid;
    }

    /**
     *
     * @param $error
     * @return bool
     */
    public function has_error($error = ''){
        if($error)
            return $this->error == $error;
        else
            return $this->error;
    }

}

/**
 * A class representation of ReCaptcha's functions.
 *
 * @Author:  Steve Todorov
 * @Contact: s.todorov@itnews-bg.com
 */
class ReCaptcha {

    /**
     * Do not include http(s) - it's automatically appended.
     */
    const RECAPTCHA_VERIFY_SERVER = "www.google.com/recaptcha/api";

    /**
     * Public key
     * @var string|bool
     */
    private $public_key = false;

    /**
     * Private key
     * @var string|bool
     */
    private $private_key = false;

    /**
     * If we should be using http or https
     * @var bool
     */
    private $use_ssl = true;

    /**
     * Is the form $_POSTed
     * @var bool
     */
    private $is_post = false;

    /**
     * Form challenge field
     * @var bool
     */
    private $form_challenge_field = false;

    /**
     * Form response field
     * @var bool
     */
    private $form_response_field = false;

    /**
     * Holds ReCaptchaResponse object with information about google's response on our post.
     * @var ReCaptchaResponse
     */
    protected $response = false;

    /**
     * Constructor
     * @param bool $use_ssl
     */
    public function __construct($use_ssl = true) {
        $this->use_ssl = $use_ssl;
        $this->is_post = (strtolower($_SERVER['REQUEST_METHOD']) === strtolower('POST'));

        $this->setFormChallengeField();
        $this->setFormResponseField();
    }

    /**
     * Submit data to google's server.
     *
     * @param  array $data
     * @return array response
     */
    private function post( array $data ) {
        $options = array(
            'http' => array(
                'method' => "POST",
                'header' => array(
                    'Content-Type: application/x-www-form-urlencoded',
                    'User-Agent: reCAPTCHA/PHP-Alternative'
                ),
                'content' => http_build_query($data)
            )
        );

        $context = stream_context_create($options);
        $this->setResponse(new ReCaptchaResponse(file_get_contents($this->getServer().'/verify',null,$context)));
        return $this->getResponse();
    }

    /**
     * Gets the challenge HTML (javascript and non-javascript version).
     * This is called from the browser, and the resulting reCAPTCHA HTML widget
     * is embedded within the HTML form it was called from.
     *
     * @param string $error The error given by reCAPTCHA (optional, default is null)
     *
     * @throws ErrorException
     * @return string - The HTML to be embedded in the user's form.
     */
    public function get_html ($error = null) {
        if (!$this->getPublicKey())
            throw new ErrorException("To use reCAPTCHA you must get a Public API key from https://www.google.com/recaptcha/admin/create");

        $errorpart = "";
        if ($error)
            $errorpart = "&error=" . $error;

        return <<<HTML
<script type="text/javascript" src="{$this->getServer()}/challenge?k={$this->public_key}{$errorpart}"></script>
<noscript>
    <iframe src="{$this->getServer()}/noscript?k={$this->public_key}{$errorpart}" height="300" width="500" frameborder="0"></iframe><br/>
    <textarea name="recaptcha_challenge_field" rows="3" cols="40"></textarea>
    <input type="hidden" name="recaptcha_response_field" value="manual_challenge"/>
</noscript>
HTML;
    }

    /**
     * Calls an HTTP POST function to verify if the user's guess was correct
     *
     * @param array  $extra_params an array of extra variables to post to the server
     *
     * @throws ErrorException
     * @return ReCaptchaResponse
     */
    public function check_answer($extra_params = array()) {
        if (!$this->getPrivateKey())
            throw new ErrorException("To use reCAPTCHA you must get a Private API key from https://www.google.com/recaptcha/admin/create");

        // discard spam submissions
        if (!$this->getFormChallengeField() || !$this->getFormResponseField()) {
            $this->setResponse(new ReCaptchaResponse());
            return false;
        }

        // Prepare post options
        $post = array_merge(
            array (
                  'privatekey' => $this->getPrivateKey(),
                  'remoteip'   => $_SERVER['REMOTE_ADDR'],
                  'challenge'  => $this->getFormChallengeField(),
                  'response'   => $this->getFormResponseField()
            ),
            $extra_params
        );

        // Return response.
        return $this->post($post);
    }

    /**
     * gets a URL where the user can sign up for reCAPTCHA. If your application
     * has a configuration page where you enter a key, you should provide a link
     * using this function.
     * @param  string $domain The domain where the page is hosted
     * @param  string $appname The name of your application
     * @return string
     */
    public function get_signup_url($domain = null, $appname = null) {
        return "https://www.google.com/recaptcha/admin/create?" .  http_build_query(array ('domains' => $domain, 'app' => $appname));
    }

    // TODO: Implement MailHide.

    /**
     * Get public key
     * @return bool
     */
    public function getPublicKey() {
        return $this->public_key;
    }

    /**
     * Set public key
     * @param $public_key
     */
    public function setPublicKey( $public_key ) {
        $this->public_key = $public_key;
    }

    /**
     * Get private key
     * @return bool
     */
    protected function getPrivateKey(){
        return $this->private_key;
    }

    /**
     * Set private key
     * @param $private_key
     */
    public function setPrivateKey( $private_key ) {
        $this->private_key = $private_key;
    }

    /**
     * Generates a url to google's server.
     * @return string
     */
    public function getServer(){
        return ($this->use_ssl ? 'https://' : 'http://').ReCaptcha::RECAPTCHA_VERIFY_SERVER;
    }

    /**
     * Get form challenge field
     * @return bool
     */
    public function getFormChallengeField(){
        return $this->form_challenge_field;
    }

    /**
     * Sets challenge field.
     */
    private function setFormChallengeField() {
        $field = ( $this->is_post ? $_POST["recaptcha_challenge_field"] : $_GET["recaptcha_challenge_field"] );
        if(strlen($field) > 0)
            $this->form_challenge_field = $field;
    }

    /**
     * Get form response field
     * @return bool
     */
    public function getFormResponseField(){
        return $this->form_response_field;
    }

    /**
     * Set form response field
     */
    private function setFormResponseField() {
        $field = ( $this->is_post ? $_POST["recaptcha_response_field"] : $_GET["recaptcha_response_field"] );
        if(strlen($field) > 0)
            $this->form_response_field = $field;
    }

    /**
     * Get google response
     * @return ReCaptchaResponse
     */
    public function getResponse() {
        return $this->response;
    }

    /**
     * Set google response
     * @param ReCaptchaResponse $response
     */
    protected function setResponse( ReCaptchaResponse $response ) {
        $this->response = $response;
    }

}

?>
