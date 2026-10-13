<?php

use dokuwiki\plugin\saml\ReplayCache;
use dokuwiki\plugin\saml\Session;
use dokuwiki\plugin\saml\UserMapper;
use OneLogin\Saml2\Auth;

/**
 * SAML authentication plugin
 *
 * @author     Andreas Gohr <gohr@cosmocode.de>
 * @author     Sam Yelman <sam.yelman@temple.edu>
 */
class auth_plugin_saml extends auth_plugin_authplain
{
    /** @var Auth the SAML authentication library */
    protected $saml;

    /** @var UserMapper the user data of a SAML response */
    protected $mapper;

    /** @var Session the data of this plugin in the PHP session */
    protected $session;

    /** @var ReplayCache the assertions that were used already */
    protected $replay;

    /** @inheritdoc */
    public function __construct()
    {
        parent::__construct();
        $this->loadConfig();

        $this->cando['external'] = true;
        /* logout makes no sense in case of always auto_login */
        $this->cando['logout'] = $this->getConf('auto_login') !== 'always';
        /* We only want auth_plain for e-mail tracking and group storage */
        $this->cando['addUser'] = false;
        $this->cando['modLogin'] = false;
        $this->cando['modPass'] = false;
        $this->cando['modName'] = false;
        $this->cando['modMail'] = false;
        $this->cando['modGroups'] = false;

        $this->mapper = new UserMapper($this->conf);
        $this->session = new Session();
        $this->replay = new ReplayCache();

        /** @var helper_plugin_saml $hlp */
        $hlp = plugin_load('helper', 'saml');
        $this->saml = $hlp->getSamlLib();
    }

    /**
     * Checks the session to see if the user is already logged in
     *
     * If not logged in, redirects to the SAML identity provider
     *
     * @inheritdoc
     */
    public function trustExternal($user, $pass, $sticky = false)
    {
        global $ID;
        global $ACT;
        global $INPUT;

        if (empty($ID)) $ID = getID();

        // trust session info, no need to recheck
        $login = $this->session->getLogin();
        if ($login !== null) {
            $this->setCurrentUser($login['info']);
            return true;
        }

        if ($INPUT->post->has('SAMLResponse')) {
            return $this->processResponse();
        }

        // the core cleans $ACT only later, in act_dispatch()
        if (act_clean($ACT) == 'login' || $this->isAutoLogin()) {
            $this->startLogin();
        }

        // no login happened
        return false;
    }

    /** @inheritdoc */
    public function logOff()
    {
        global $ID;
        global $INPUT;

        set_doku_pref('saml_autologin', 0);

        /* By default, try to return the user to the page they were just viewing */
        $redirTo = wl($ID, '', true, '&');

        if ($INPUT->get->has('SAMLResponse') || $INPUT->get->has('SAMLRequest')) {
            /* Process a logout request or response of the identity provider */
            $this->saml->processSLO();
            $errors = $this->saml->getErrors();
            if ($errors) {
                msg('SAML SLO: ' . hsc(implode(', ', $errors) . '; ' . $this->saml->getLastErrorReason()), -1);
            }

            /* The RelayState holds the page that the user wanted */
            $redirTo = $this->getTarget($INPUT->get->str('RelayState'));
        } elseif ($this->getConf('use_slo')) {
            /* The user started the logout in the wiki itself */
            $this->saml->logout($ID); // returnTo: comes back as the RelayState
        }

        /* Manually redirect the user if we ever get here */
        send_redirect($redirTo);
    }

    /** @inheritdoc */
    public function cleanUser($user)
    {
        return $this->mapper->cleanUser($user);
    }

    /** @inheritdoc */
    public function cleanGroup($group)
    {
        return $this->mapper->cleanGroup($group);
    }

    /**
     * Send the user to the identity provider
     *
     * @return void
     */
    protected function startLogin()
    {
        global $ID;

        $url = $this->saml->login(
            $ID, // returnTo: the identity provider sends this page back as the RelayState
            [], // parameter: we do not send any additional parameters
            false, // forceAuthn: would skip any available SSO data, not what we want
            false, // isPassive: would avoid all user interaction, not what we want
            true, // stay: do not redirect, we do that ourselves
            false // setNameIdPolicy: we need to disable this or SAML complains about our request
        );
        $this->session->setRequestId($this->saml->getLastRequestID()); // check the answer
        send_redirect($url);
    }

    /**
     * Log the user in with the response of the identity provider
     *
     * @return bool true when the login succeeded
     */
    protected function processResponse()
    {
        global $ID;
        global $INPUT;

        // A response answers the request of this session, one time only. The session may
        // be empty: the browser does not send its cookie with a cross site POST.
        $requestId = $this->session->getRequestId();
        $this->session->clearRequestId();
        if ($requestId === null && !$this->getConf('allow_unsolicited')) {
            return $this->abortLogin($this->getLang('err_unsolicited'));
        }

        try {
            $this->saml->processResponse($requestId);
            if (!$this->saml->isAuthenticated()) {
                return $this->abortLogin('SAML: ' . hsc($this->saml->getLastErrorReason()));
            }

            if ($this->replay->isKnown($this->saml->getLastAssertionId())) {
                return $this->abortLogin($this->getLang('err_replay'));
            }
            $this->replay->add($this->saml->getLastAssertionId(), $this->saml->getLastAssertionNotOnOrAfter());

            // always read the user id from the SAML response
            $userinfo = $this->mapper->getUserData($this->saml);

            if ($this->getConf('autoprovisioning')) {
                $this->provisionUser($userinfo);
            } else {
                $userinfo = $this->addLocalUserData($userinfo);
            }

            // the user is known now, only now they become the user of this request
            $this->setCurrentUser($userinfo);
            $this->session->setLogin($userinfo['user'], $userinfo);
            $this->session->setExpiry($this->saml->getSessionExpiration());
            set_doku_pref('saml_autologin', 1);

            // successful login, the RelayState holds the page that the user wanted
            send_redirect($this->getTarget($INPUT->post->str('RelayState'))); // not the POST
            return true;
        } catch (Exception $e) {
            return $this->abortLogin('Invalid SAML response: ' . hsc($e->getMessage()));
        }
    }

    /**
     * The address of the page that a RelayState names
     *
     * The identity provider sends the RelayState of our message back, which holds the ID
     * of the page that the user wanted. The session cannot hold that page, because the
     * browser does not send the session cookie with a cross site POST. The wiki builds
     * the address itself, so a RelayState of somebody else cannot send the user to
     * another site.
     *
     * @param string $relay the RelayState of the message
     * @return string the address of the page, the current page when the RelayState
     *                holds no page ID of this wiki
     */
    protected function getTarget($relay)
    {
        global $ID;

        $page = cleanID((string)$relay);
        if ($page === '' || $page !== $relay) $page = $ID;

        return wl($page, '', true, '&');
    }

    /**
     * Make the given user the user of this request
     *
     * @param array $userinfo the user data
     * @return void
     */
    protected function setCurrentUser($userinfo)
    {
        global $USERINFO;
        global $INPUT;

        $USERINFO = $userinfo;
        $INPUT->server->set('REMOTE_USER', $userinfo['user']);
    }

    /**
     * Refuse the login and tell the user why
     *
     * Does not start a logout at the identity provider: the user has no SAML session yet
     * and an error of the logout would hide the error of the login.
     *
     * @param string $reason the message for the user
     * @return false
     */
    protected function abortLogin($reason)
    {
        set_doku_pref('saml_autologin', 0); // do not try again on the next request
        msg($reason, -1);
        return false;
    }

    /**
     * Create or update the local user with the data of the SAML response
     *
     * @param array $userinfo the user data of the response
     * @return void
     */
    protected function provisionUser($userinfo)
    {
        if ($this->getUserData($userinfo['user']) === false) {
            $this->triggerUserMod('create', [
                $userinfo['user'],
                "\0\0nil\0\0",
                $userinfo['name'],
                $userinfo['mail'],
                $userinfo['grps']
            ]);
        } else {
            $this->triggerUserMod('modify', [
                $userinfo['user'],
                $userinfo
            ]);
        }
    }

    /**
     * Add the data of the local user to the user data of the SAML response
     *
     * Without auto provisioning the wiki keeps name, mail and groups itself and the user
     * has to exist already.
     *
     * @param array $userinfo the user data of the response
     * @return array the user data of the local user database
     * @throws Exception when the user does not exist in the local user database
     */
    protected function addLocalUserData($userinfo)
    {
        $local = $this->getUserData($userinfo['user']);
        if ($local === false) {
            throw new Exception('This user is not in the local user database and may not login');
        }

        $userinfo['name'] = $local['name'];
        $userinfo['mail'] = $local['mail'];
        $userinfo['grps'] = $local['grps'];
        return $userinfo;
    }

    /**
     * Should the user be sent to the identity provider without a click on the login button?
     *
     * @return bool
     */
    protected function isAutoLogin()
    {
        $mode = $this->getConf('auto_login');
        if ($mode == 'always') return true;
        if ($mode == 'after login') return (bool)get_doku_pref('saml_autologin', 0);
        return false;
    }
}
