<?php

use dokuwiki\Extension\Plugin;
use dokuwiki\plugin\saml\LogoutHandler;
use dokuwiki\plugin\saml\Session;
use dokuwiki\plugin\saml\Settings;
use OneLogin\Saml2\Auth;

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
     * @return string the metadata in XML
     * @throws Exception when the configuration is not valid
     */
    public function getMetadata()
    {
        return $this->getSamlLib()->getSettings()->getSPMetadata(
            true, // publish the certificate for encryption as well
            null, // validUntil: the next parameter drops it
            null, // cacheDuration: the default of one week
            true // no validUntil: an admin may upload this file by hand once
        );
    }
}
