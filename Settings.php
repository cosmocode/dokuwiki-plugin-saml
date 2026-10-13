<?php

namespace dokuwiki\plugin\saml;

use OneLogin\Saml2\Constants;

/**
 * The settings of the php-saml library
 *
 * Builds the settings array that the library expects from the configuration of the plugin.
 */
class Settings
{
    /** @var array the configuration of the plugin */
    protected $conf;

    /**
     * @param array $conf the configuration of the plugin
     */
    public function __construct(array $conf)
    {
        $this->conf = $conf;
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
                    'url' => wl('', ['do' => 'logout'], true, '&'),
                    'binding' => Constants::BINDING_HTTP_REDIRECT,
                ],
                'NameIDFormat' => Constants::NAMEID_EMAIL_ADDRESS,
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
                'x509cert' => $this->getCertificate(),
            ],

            'security' => [
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
                // itself, with the allow_unsolicited setting
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
     * The signing certificate of the identity provider
     *
     * The configuration may hold the certificate with or without the PEM header and footer.
     *
     * @return string the certificate in PEM format
     */
    protected function getCertificate()
    {
        $cert = wordwrap($this->conf['certificate'], 65, "\n", true);
        $cert = trim($cert);
        if (!preg_match('/^-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----$/s', $cert)) {
            return "-----BEGIN CERTIFICATE-----\n$cert\n-----END CERTIFICATE-----";
        }
        return $cert;
    }
}
