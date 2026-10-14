<?php

namespace dokuwiki\plugin\saml;

/**
 * The data of the plugin in the PHP session
 *
 * The login that DokuWiki caches in the session is shared with the core. All data that
 * only this plugin uses is kept in its own part of the session.
 */
class Session
{
    /**
     * The login that the session holds
     *
     * A login that expired is removed and not returned.
     *
     * @return array|null user and info, null when the session has no valid login for this browser
     */
    public function getLogin()
    {
        if (!isset($_SESSION[DOKU_COOKIE]['auth']['user'])) return null;
        if (!isset($_SESSION[DOKU_COOKIE]['auth']['buid'])) return null;
        if ($_SESSION[DOKU_COOKIE]['auth']['buid'] !== auth_browseruid()) return null;

        if ($this->isExpired()) {
            $this->clearLogin();
            return null;
        }

        return $_SESSION[DOKU_COOKIE]['auth'];
    }

    /**
     * Keep the login in the session
     *
     * @param string $user the login name
     * @param array $userinfo the user data
     * @return void
     */
    public function setLogin($user, array $userinfo)
    {
        $_SESSION[DOKU_COOKIE]['auth']['user'] = $user;
        $_SESSION[DOKU_COOKIE]['auth']['info'] = $userinfo;
        $_SESSION[DOKU_COOKIE]['auth']['buid'] = auth_browseruid();
    }

    /**
     * Forget the login
     *
     * @return void
     */
    public function clearLogin()
    {
        unset($_SESSION[DOKU_COOKIE]['auth']);
        $this->set('expiry', null);
        $this->set('idpsession', null);
    }

    /**
     * The session of the user at the identity provider
     *
     * @return array nameid, format, namequalifier, spnamequalifier and sessionindex,
     *               all empty when the session holds no SAML login
     */
    public function getIdpSession()
    {
        return array_merge([
            'nameid' => '',
            'format' => '',
            'namequalifier' => '',
            'spnamequalifier' => '',
            'sessionindex' => '',
        ], (array)$this->get('idpsession', []));
    }

    /**
     * Keep the session of the user at the identity provider
     *
     * Single Logout names a session with these values.
     *
     * @param array $data nameid, format, namequalifier, spnamequalifier and sessionindex
     * @return void
     */
    public function setIdpSession(array $data)
    {
        $this->set('idpsession', $data);
    }

    /**
     * Did the identity provider end the login?
     *
     * An assertion may limit how long the login is valid. Without such a limit the login
     * lasts as long as the session of the wiki.
     *
     * @return bool
     */
    protected function isExpired()
    {
        $expiry = $this->getExpiry();
        return $expiry && $expiry <= time();
    }

    /**
     * The time at which the login of the identity provider ends
     *
     * @return int a timestamp, 0 when the assertion gave no time
     */
    public function getExpiry()
    {
        return (int)$this->get('expiry', 0);
    }

    /**
     * Keep the time at which the login of the identity provider ends
     *
     * @param int|null $time null when the assertion gives no time
     * @return void
     */
    public function setExpiry($time)
    {
        $this->set('expiry', $time ? (int)$time : null);
    }

    /**
     * The identifier of the request that this wiki sent to the identity provider
     *
     * @return string|null null when this wiki started no login
     */
    public function getRequestId()
    {
        return $this->get('requestid');
    }

    /**
     * Keep the identifier of the request to the identity provider
     *
     * @param string $id
     * @return void
     */
    public function setRequestId($id)
    {
        $this->set('requestid', $id);
    }

    /**
     * Forget the identifier of the request to the identity provider
     *
     * @return void
     */
    public function clearRequestId()
    {
        $this->set('requestid', null);
    }

    /**
     * One value of the plugin in the session
     *
     * @param string $key
     * @param mixed $default the value when the session has no such key
     * @return mixed
     */
    protected function get($key, $default = null)
    {
        return $_SESSION[DOKU_COOKIE]['plugin']['saml'][$key] ?? $default;
    }

    /**
     * Keep one value of the plugin in the session
     *
     * @param string $key
     * @param mixed $value null removes the key
     * @return void
     */
    protected function set($key, $value)
    {
        if ($value === null) {
            unset($_SESSION[DOKU_COOKIE]['plugin']['saml'][$key]);
            return;
        }
        $_SESSION[DOKU_COOKIE]['plugin']['saml'][$key] = $value;
    }
}
