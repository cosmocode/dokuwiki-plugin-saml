<?php

use dokuwiki\Extension\Plugin;
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
            if (!$this->configloaded) $this->loadConfig();
            $settings = new Settings($this->conf);
            $this->saml = new Auth($settings->toArray());
        }
        return $this->saml;
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
            null, // validUntil: not used, see the next parameter
            null, // cacheDuration: the default of one week
            true // no validUntil: an admin may upload this file by hand once
        );
    }
}
