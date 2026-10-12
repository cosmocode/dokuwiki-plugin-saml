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
     * @return array|null user and info, null when the session has no login for this browser
     */
    public function getLogin()
    {
        if (!isset($_SESSION[DOKU_COOKIE]['auth']['user'])) return null;
        if (!isset($_SESSION[DOKU_COOKIE]['auth']['buid'])) return null;
        if ($_SESSION[DOKU_COOKIE]['auth']['buid'] !== auth_browseruid()) return null;

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
     * The address that the user wanted before the login started
     *
     * @return string an empty string when the session has no address
     */
    public function getRedirect()
    {
        return $this->get('redirect', '');
    }

    /**
     * Keep the address that the user wanted before the login started
     *
     * @param string $url
     * @return void
     */
    public function setRedirect($url)
    {
        $this->set('redirect', $url);
    }

    /**
     * Forget the address that the user wanted before the login started
     *
     * @return void
     */
    public function clearRedirect()
    {
        $this->set('redirect', null);
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
