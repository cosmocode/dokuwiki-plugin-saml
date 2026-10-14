<?php

use dokuwiki\plugin\saml\ReplayCache;
use dokuwiki\plugin\saml\Session;
use dokuwiki\plugin\saml\UserMapper;

/**
 * SAML authentication plugin
 *
 * @author     Andreas Gohr <gohr@cosmocode.de>
 * @author     Sam Yelman <sam.yelman@temple.edu>
 */
class auth_plugin_saml extends auth_plugin_authplain
{
    /** @var UserMapper the user data of a SAML response */
    protected $mapper;

    /** @var Session the data of this plugin in the PHP session */
    protected $session;

    /** @var ReplayCache the assertions that were used already */
    protected $replay;

    /** @var helper_plugin_saml the services of this plugin */
    protected $hlp;

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

        $this->hlp = plugin_load('helper', 'saml');
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
        if (act_clean($ACT) == 'login') {
            if ($this->session->takeLoggedOut()) {
                // the core sends the browser here after a logout. Show the page that
                // the user was on, a login form of this plugin has nothing to offer.
                $ACT = 'show';
            } else {
                $this->startLogin();
            }
        } elseif ($this->isAutoLogin()) {
            $this->startLogin();
        }

        // no login happened
        return false;
    }

    /**
     * Tell the identity provider that this user logged out
     *
     * The core calls this at the end of auth_logoff(), which already ended the session of
     * the wiki.
     *
     * @inheritdoc
     */
    public function logOff()
    {
        global $ID;

        set_doku_pref('saml_autologin', 0);
        $this->session->setLoggedOut();

        if (!$this->getConf('use_slo')) return;
        if (!$this->getConf('slo_endpoint')) return;

        $idp = $this->session->getIdpSession();
        if ($idp['nameid'] === '') return; // no SAML session to end

        $this->session->clearLogin();

        $saml = $this->hlp->getSamlLib();
        $url = $saml->logout(
            $ID, // returnTo: the identity provider sends this page back as the RelayState
            [], // parameters: none
            $idp['nameid'],
            $idp['sessionindex'],
            true, // stay: the redirect happens below
            $idp['format'],
            $idp['namequalifier'],
            $idp['spnamequalifier']
        );
        $this->session->setRequestId($saml->getLastRequestID()); // the answer names it
        send_redirect($url);
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

        try {
            $saml = $this->hlp->getSamlLib();
            $url = $saml->login(
                $ID, // returnTo: the identity provider sends this page back as the RelayState
                [], // parameter: we do not send any additional parameters
                false, // forceAuthn: would skip any available SSO data, not what we want
                false, // isPassive: would avoid all user interaction, not what we want
                true, // stay: do not redirect, we do that ourselves
                false // setNameIdPolicy: we need to disable this or SAML complains about our request
            );
        } catch (Exception $e) {
            $this->abortLogin('SAML: ' . hsc($e->getMessage()));
            return;
        }

        $this->session->setRequestId($saml->getLastRequestID()); // check the answer
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
            $saml = $this->hlp->getSamlLib();
            $saml->processResponse($requestId);
            if (!$saml->isAuthenticated()) {
                return $this->abortLogin('SAML: ' . hsc($saml->getLastErrorReason()));
            }

            if ($this->replay->isKnown($saml->getLastAssertionId())) {
                return $this->abortLogin($this->getLang('err_replay'));
            }
            $this->replay->add($saml->getLastAssertionId(), $saml->getLastAssertionNotOnOrAfter());

            // always read the user id from the SAML response
            $userinfo = $this->mapper->getUserData($saml);

            if ($this->getConf('autoprovisioning')) {
                $this->provisionUser($userinfo);
            } else {
                $userinfo = $this->addLocalUserData($userinfo);
            }

            // the user is known now, only now they become the user of this request
            $this->setCurrentUser($userinfo);
            $this->session->setLogin($userinfo['user'], $userinfo);
            $this->session->setExpiry($saml->getSessionExpiration());
            $this->session->setIdpSession([
                'nameid' => (string)$saml->getNameId(),
                'format' => (string)$saml->getNameIdFormat(),
                'namequalifier' => (string)$saml->getNameIdNameQualifier(),
                'spnamequalifier' => (string)$saml->getNameIdSPNameQualifier(),
                'sessionindex' => (string)$saml->getSessionIndex(),
            ]);
            set_doku_pref('saml_autologin', 1);

            // the redirect keeps the POST out of the history of the browser
            send_redirect($this->hlp->getTargetPage());
            return true;
        } catch (Exception $e) {
            return $this->abortLogin('Invalid SAML response: ' . hsc($e->getMessage()));
        }
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
