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
}
