<?php

/**
 * Plugin wykrywający Cross-site request forgery (CSRF)
 *
 * @author Marcin Grabowski <marcin.grabowski@gnb.pl>
 */
class Base_Controller_Plugin_CsrfProtect extends Zend_Controller_Plugin_Abstract {

    /**
     * Sesja
     * @var Zend_Session_Namespace
     */
    protected $session = null;

    /**
     * Nazwa elementu formularza, który zawiera klucz
     * @var string
     */
    protected $keyName = 'csrf';

    /**
     * Ważność klucza w sekundach
     * @var int
     */
    protected $expiryTime = 60;

    /**
     * Poprzedni token ustawiany przez initToken()
     * @var string
     */
    protected $previousToken = '';

    public function __construct()
    {
        $this->session = new Zend_Session_Namespace('CsrfProtect');
    }

    /**
     * @return string
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * @return string
     */
    public function getKeyName()
    {
        return $this->keyName;
    }

    /**
     * Sprawdzenie czy tokeny są takie same
     *
     * @param string $value Token z posta
     *
     * @return bool
     */
    public function isValidToken($value)
    {
        return $value === $this->previousToken;
    }

    /**
     * Sprawdzenie czy atak CSRF
     * @param Zend_Controller_Request_Abstract $request
     */
    public function preDispatch(Zend_Controller_Request_Abstract $request)
    {
        $this->initTokens();

        if ($request->isPost() === true) {
            if (empty($this->previousToken)) {
                throw new Exception('Atak CSRF wykryty: brak tokenu');
            }

            $value = $request->getPost($this->keyName);
            if (!$this->isValidToken($value)) {
                throw new Exception('Atak CSRF wykryty: tokeny nie pasują');
            }
        }
    }

    /**
     * Initializes a new token
     */
    protected function initTokens()
    {
        $this->previousToken = $this->session->key;
        $newKey = sha1(microtime() . mt_rand());
        $this->session->key = $newKey;
        if ($this->expiryTime > 0) {
            $this->session->setExpirationSeconds($this->expiryTime);
        }

        $this->token = $newKey;
    }

    /**
     * Dodanie pola z tokenem do formularza
     */
    public function dispatchLoopShutdown()
    {
        $response = $this->getResponse();
        foreach ($response->getHeaders() as $header) {
            /**
             * Jeżeli content-type nie jest html/xhtml
             */
            if ($header['name'] === 'Content-Type' && strpos($header['value'], 'html') === false) {
                return;
            }
        }
        
        $body = $response->getBody();
        $element = '<input type="hidden" name="' . $this->getKeyName() . '" value="' . $this->getToken() . '" />';
        /**
         * Wstawienie pola z tokenem
         */
        $body = preg_replace('/<form[^>]*>/i', '$0' . $element, $body);
        $response->setBody($body);
    }

}
