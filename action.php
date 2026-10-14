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
     * The Single Logout Service of this wiki
     *
     * A LogoutRequest arrives when a logout started somewhere else, a LogoutResponse when
     * the identity provider answers a logout that started in this wiki. Both come with
     * the Redirect binding, which the SP metadata announces.
     *
     * @param Event $event
     * @param mixed $param
     * @return void
     */
    public function handleLogoutMessage(Event $event, $param)
    {
        global $INPUT;

        if (act_clean($event->data) != 'saml_sls') return;
        $event->preventDefault();
        $event->stopPropagation();

        /** @var helper_plugin_saml $hlp */
        $hlp = plugin_load('helper', 'saml');

        try {
            if ($INPUT->get->has('SAMLRequest')) {
                // the handler answers the identity provider itself
                $hlp->getLogoutHandler()->handleRequest($INPUT->get->str('SAMLRequest'));
            } elseif ($INPUT->get->has('SAMLResponse')) {
                $hlp->getLogoutHandler()->handleResponse($INPUT->get->str('SAMLResponse'));
                send_redirect($hlp->getTargetPage());
            } else {
                http_status(400);
                echo 'No SAML logout message found';
            }
        } catch (Exception $e) {
            http_status(400);
            echo hsc($e->getMessage());
        }
        exit();
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

        header('Content-Type: application/xml');
        header('Content-Disposition: inline; filename="saml-metadata.xml"');
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
