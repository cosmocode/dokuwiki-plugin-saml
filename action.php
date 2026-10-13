<?php

use dokuwiki\Extension\ActionPlugin;
use dokuwiki\Extension\Event;
use dokuwiki\Extension\EventHandler;
use dokuwiki\Form\Form;

/**
 * SAML authentication plugin
 *
 * @author     Andreas Gohr <gohr@cosmocode.de>
 * @author     Sam Yelman <sam.yelman@temple.edu>
 */
class action_plugin_saml extends ActionPlugin
{
    /** @inheritdoc */
    public function register(EventHandler $controller)
    {
        $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'handleLogoutMessage');
        $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'handleMetadata');
        $controller->register_hook('FORM_LOGIN_OUTPUT', 'BEFORE', $this, 'handleLoginForm');
    }

    /**
     * Log the user out when the identity provider asks for it
     *
     * The core logout action refuses a request without a security token, which a message
     * of the identity provider does not have. The logout runs here instead. auth_logoff()
     * ends the local session and then calls the logOff() of the plugin, which answers the
     * identity provider.
     *
     * @param Event $event
     * @param mixed $param
     * @return void
     */
    public function handleLogoutMessage(Event $event, $param)
    {
        global $auth;
        global $INPUT;

        if (!$auth instanceof auth_plugin_saml) return;
        if (act_clean($event->data) != 'logout') return;
        if (!$this->getConf('use_slo')) return;
        if (!$INPUT->get->has('SAMLResponse') && !$INPUT->get->has('SAMLRequest')) return;

        $event->preventDefault();
        $event->stopPropagation();
        auth_logoff();
    }

    /**
     * Send the Federation Metadata about this Service Provider
     *
     * @param Event $event
     * @param mixed $param
     * @return void
     */
    public function handleMetadata(Event $event, $param)
    {
        if (act_clean($event->data) != 'saml') return;
        $event->preventDefault();
        $event->stopPropagation();

        /** @var helper_plugin_saml $hlp */
        $hlp = plugin_load('helper', 'saml');

        try {
            $xml = $hlp->getMetadata();
        } catch (Exception $e) {
            http_status(500);
            echo hsc($e->getMessage());
            exit();
        }

        header('Content-Type: application/samlmetadata+xml');
        header('Content-Disposition: attachment; filename="saml-metadata.xml"');
        echo $xml;
        exit();
    }

    /**
     * Disable the login form and instead use a button to trigger the login
     *
     * @param Event $event
     * @param mixed $param
     * @return void
     */
    public function handleLoginForm(Event $event, $param)
    {
        global $conf;
        if ($conf['authtype'] != 'saml') return;

        /** @var Form $form */
        $form = $event->data;

        // the form keeps the action and the hidden fields, we only replace its contents
        for ($pos = $form->elementCount(); $pos > 0; $pos--) {
            $form->removeElement($pos - 1);
        }

        $form->addFieldsetOpen($this->getLang('login'));
        $form->addButton('', hsc($this->getLang('login')))->attr('type', 'submit');
        $form->addFieldsetClose();
    }
}
