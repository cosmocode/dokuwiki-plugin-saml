<?php

use dokuwiki\Extension\Plugin;
use dokuwiki\plugin\saml\LogoutHandler;
use dokuwiki\plugin\saml\Session;
use dokuwiki\plugin\saml\Settings;
use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\Metadata;
use OneLogin\Saml2\Settings as LibrarySettings;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * SAML authentication plugin
 *
 * @author     Andreas Gohr <gohr@cosmocode.de>
 * @author     Sam Yelman <sam.yelman@temple.edu>
 */
class helper_plugin_saml extends Plugin
{
    /** @var Auth the SAML authentication library */
    protected $saml;

    /**
     * The SAML library, set up with the configuration of this plugin
     *
     * Built on first use. The wiki has to load and send its SP metadata before an admin
     * can know the settings of the identity provider.
     *
     * @return Auth
     * @throws Exception when the configuration is not valid
     */
    public function getSamlLib()
    {
        if ($this->saml === null) {
            $this->saml = new Auth($this->getSettings()->toArray());
        }
        return $this->saml;
    }

    /**
     * The settings of the plugin
     *
     * @return Settings
     */
    protected function getSettings()
    {
        if (!$this->configloaded) $this->loadConfig();
        return new Settings($this->conf);
    }

    /**
     * The handler for the Single Logout messages of the identity provider
     *
     * @return LogoutHandler
     * @throws Exception when the configuration is not valid
     */
    public function getLogoutHandler()
    {
        return new LogoutHandler(new Auth($this->getSettings()->forLogout()), new Session());
    }

    /**
     * The address of the page that the RelayState of a message names
     *
     * The identity provider sends the RelayState of our message back, which holds the ID
     * of the page that the user wanted. The wiki builds the address itself, so a value
     * that somebody else chose cannot send the user to another site.
     *
     * @return string the address of that page, of the current page otherwise
     */
    public function getTargetPage()
    {
        global $ID;
        global $INPUT;

        $relay = $INPUT->str('RelayState');
        $page = cleanID($relay);
        if ($page === '' || $page !== $relay) $page = $ID;

        return wl($page, '', true, '&');
    }

    /**
     * The SP metadata that describes this wiki to the identity provider
     *
     * The identity provider may create its client from this file, so the wiki sends it
     * before an admin can know the settings of the identity provider. The library
     * therefore checks the service provider part of the settings only.
     *
     * @return string the metadata in XML
     * @throws Exception when the settings of this wiki are not valid
     */
    public function getMetadata()
    {
        $config = $this->getSettings()->toArray();
        // the plugin signs the metadata itself, after it added the encryption algorithm
        $config['security']['signMetadata'] = false;
        $settings = new LibrarySettings($config, true);

        $xml = $settings->getSPMetadata(
            false, // the certificate for encryption travels when the wiki wants encryption
            null, // validUntil: the next parameter drops it
            null, // cacheDuration: the default of one week
            true // no validUntil: an admin may upload this file by hand once
        );

        return Metadata::signMetadata(
            $this->addEncryptionMethod($xml),
            $settings->getSPkey(),
            $settings->getSPcert(),
            $config['security']['signatureAlgorithm'],
            $config['security']['digestAlgorithm']
        );
    }

    /**
     * Name the key transport that this wiki can read
     *
     * xmlseclibs decrypts RSA-OAEP with the digest SHA-1 only. Without this element an
     * identity provider picks its own standard, which is SHA-256 for Keycloak, and the
     * wiki cannot read the assertion. The library writes no EncryptionMethod itself.
     *
     * @param string $xml the metadata
     * @return string the metadata with the algorithm of each encryption certificate
     */
    protected function addEncryptionMethod($xml)
    {
        $doc = new DOMDocument();
        $doc->loadXML($xml);

        foreach ($doc->getElementsByTagNameNS(Constants::NS_MD, 'KeyDescriptor') as $descriptor) {
            if ($descriptor->getAttribute('use') !== 'encryption') continue;

            // the schema puts EncryptionMethod after KeyInfo
            $method = $doc->createElementNS(Constants::NS_MD, 'md:EncryptionMethod');
            $method->setAttribute('Algorithm', XMLSecurityKey::RSA_OAEP_MGF1P);
            $descriptor->appendChild($method);
        }

        return $doc->saveXML();
    }
}
