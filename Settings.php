<?php

namespace dokuwiki\plugin\saml;

use OneLogin\Saml2\Constants;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * The settings of the php-saml library
 *
 * Builds the settings array that the library expects from the configuration of the plugin.
 */
class Settings
{
    /** @var array the configuration of the plugin */
    protected $conf;

    /** @var KeyStore the key pair of this wiki */
    protected $keys;

    /**
     * @param array $conf the configuration of the plugin
     * @param KeyStore|null $keys the key pair of this wiki, the standard store by default
     */
    public function __construct(array $conf, ?KeyStore $keys = null)
    {
        $this->conf = $conf;
        $this->keys = $keys ?: new KeyStore();
    }

    /**
     * The settings for the php-saml library
     *
     * @return array
     */
    public function toArray()
    {
        global $conf;
        $title = htmlentities($conf['title']);

        return [
            'strict' => true,
            'debug' => false,
            'baseurl' => DOKU_URL,

            // Our own meta data
            'sp' => [
                'entityId' => DOKU_URL,
                'assertionConsumerService' => [
                    'url' => DOKU_URL . DOKU_SCRIPT,
                    'binding' => Constants::BINDING_HTTP_POST,
                ],
                'singleLogoutService' => [
                    'url' => DOKU_URL . DOKU_SCRIPT . '?do=saml_sls',
                    'binding' => Constants::BINDING_HTTP_REDIRECT,
                ],
                'NameIDFormat' => Constants::NAMEID_EMAIL_ADDRESS,
                'privateKey' => $this->keys->getKey(),
                'x509cert' => $this->keys->getCertificate(),
            ],

            // The SAML server we talk to
            'idp' => [
                'entityId' => $this->conf['idPEntityID'],
                'singleSignOnService' => [
                    'url' => $this->conf['endpoint'],
                    'binding' => Constants::BINDING_HTTP_REDIRECT,
                ],
                'singleLogoutService' => [
                    'url' => $this->conf['slo_endpoint'],
                    'binding' => Constants::BINDING_HTTP_REDIRECT,
                ],
                'NameIDFormat' => Constants::NAMEID_UNSPECIFIED,
                'x509certMulti' => ['signing' => $this->getCertificates()],
            ],

            'security' => [
                'authnRequestsSigned' => (bool)$this->conf['sign_requests'],
                'logoutRequestSigned' => (bool)$this->conf['sign_requests'],
                'logoutResponseSigned' => (bool)$this->conf['sign_requests'],
                // the SP metadata is signed with the key of the wiki
                'signMetadata' => true,
                // the library refuses a response without any signature in every case.
                // This demands a signature of the assertion itself.
                'wantAssertionsSigned' => (bool)$this->conf['want_assertions_signed'],
                'wantAssertionsEncrypted' => (bool)$this->conf['want_encrypted'],
                // every identity provider understands SHA-256, a stronger hash brings
                // nothing here and not all of them support it
                'signatureAlgorithm' => XMLSecurityKey::RSA_SHA256,
                'digestAlgorithm' => XMLSecurityDSig::SHA256,
                // ADFS with Windows Integrated Authentication answers with another
                // context class and refuses a request that demands one
                'requestedAuthnContext' => false,
                // we send no NameIDPolicy, so ADFS may answer without a NameID. The
                // plugin reads the user from an attribute, not from the NameID.
                'wantNameId' => false,
                // the library builds the address of this wiki from our baseurl, so the
                // Destination of a response has to match it exactly
                'destinationStrictlyMatches' => true,
                // the plugin decides about a response that answers an unknown request
                // itself, see seesOwnSession() of the auth plugin
                'rejectUnsolicitedResponsesWithInResponseTo' => false,
                'allowRepeatAttributeName' => true,
            ],

            'organization' => [
                'en-US' => [
                    'name' => $title,
                    'displayname' => $title,
                    'url' => DOKU_URL,
                ],
            ],
        ];
    }

    /**
     * The settings for a logout message of the identity provider
     *
     * @return array
     */
    public function forLogout()
    {
        $settings = $this->toArray();

        // the library removes the query string before it compares the Destination, and
        // only the SLS address of this wiki has one
        $settings['security']['destinationStrictlyMatches'] = false;

        // everybody can send a logout message to the SLS address, so it must be signed
        // by the identity provider
        $settings['security']['wantMessagesSigned'] = true;

        return $settings;
    }

    /**
     * The signing certificates of the identity provider
     *
     * The configuration holds one or more certificates, with or without the PEM header
     * and footer. More than one certificate lets the identity provider change its key
     * without a break: the wiki accepts a signature of each of them.
     *
     * @return array the base64 body of each certificate, the library adds the header
     */
    protected function getCertificates()
    {
        $config = trim($this->conf['certificate']);
        if ($config === '') return [];

        if (preg_match_all('/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s', $config, $match)) {
            $certs = $match[1];
        } else {
            // a configuration from the adfs plugin holds the base64 body alone
            $certs = [$config];
        }

        return array_map(static fn($cert) => (string)preg_replace('/\s+/', '', $cert), $certs);
    }
}
