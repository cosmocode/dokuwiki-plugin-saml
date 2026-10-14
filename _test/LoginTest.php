<?php

namespace dokuwiki\plugin\saml\test;

use auth_plugin_saml;
use dokuwiki\plugin\saml\Session;

/**
 * Gives the test the plugin under its own name
 */
class LoginAuth extends auth_plugin_saml
{
    /** @inheritdoc */
    public function getPluginName()
    {
        return 'saml';
    }
}

/**
 * Tests for the login of a user through the auth plugin
 *
 * @group plugin_saml
 * @group plugins
 */
class LoginTest extends AbstractMessageTest
{
    /** @inheritdoc */
    public function setUp(): void
    {
        parent::setUp();

        global $conf;
        $conf['plugin']['saml'] = $this->getConf();
        $_SESSION = [];

        // the identity provider of the tests is on another site, so the browser sends
        // no session cookie with its response
        unset($_COOKIE[DOKU_SESSION_NAME]);
    }

    /**
     * The wiki still loads when nobody configured the identity provider
     *
     * An admin needs the admin page and the SP metadata of the wiki before they can
     * know the settings of the identity provider.
     */
    public function testWithoutConfiguration()
    {
        global $conf;
        $conf['plugin']['saml'] = $this->getDefaultConf();

        $auth = new LoginAuth();

        $this->assertFalse($auth->trustExternal('', '', false));
    }

    /**
     * A valid response logs the user in
     */
    public function testLogin()
    {
        global $USERINFO;
        $_POST['SAMLResponse'] = $this->getResponse();

        $auth = new LoginAuth();
        $ok = $auth->trustExternal('', '', false);

        $this->assertTrue($ok);
        $this->assertEquals('andi', $USERINFO['user']);
        $this->assertEquals('andi@example.org', $USERINFO['mail']);
    }

    /**
     * The login keeps what Single Logout needs
     */
    public function testKeepsSamlSession()
    {
        $_POST['SAMLResponse'] = $this->getResponse();

        (new LoginAuth())->trustExternal('', '', false);

        $saml = $_SESSION[DOKU_COOKIE]['plugin']['saml']['idpsession'];
        $this->assertEquals('andi', $saml['nameid']);
        $this->assertEquals('_session1', $saml['sessionindex']);
        $this->assertNotEmpty($_SESSION[DOKU_COOKIE]['plugin']['saml']['expiry']);
    }

    /**
     * A login that the identity provider ended is not used again
     *
     * The assertion tells how long the session of the identity provider lasts. The wiki
     * trusts its own session until that time and asks the identity provider afterwards.
     */
    public function testExpiredSession()
    {
        $_POST['SAMLResponse'] = $this->getResponse();
        (new LoginAuth())->trustExternal('', '', false);
        $_POST = [];

        (new Session())->setExpiry(time() - 1);

        $ok = (new LoginAuth())->trustExternal('', '', false);

        $this->assertFalse($ok);
        $this->assertArrayNotHasKey('auth', $_SESSION[DOKU_COOKIE]);
    }

    /**
     * A logout does not start a new login
     *
     * The core sends the browser to do=login after a logout. Without the mark of the
     * logout the plugin would read that as a request to log in and send the user back
     * to the identity provider, which still knows them. The user sees their page.
     */
    public function testLogoutDoesNotLogInAgain()
    {
        global $ACT;
        $_POST['SAMLResponse'] = $this->getResponse();
        (new LoginAuth())->trustExternal('', '', false);
        $_POST = [];

        // the core clears its part of the session and then calls logOff()
        global $auth;
        $auth = new LoginAuth();
        $ACT = 'logout';
        auth_logoff();

        $ACT = 'login';
        $ok = (new LoginAuth())->trustExternal('', '', false);

        $this->assertFalse($ok);
        $this->assertNull($this->getRequestId(), 'the wiki asked the identity provider again');
        $this->assertEquals('show', $ACT);
    }

    /**
     * A logout elsewhere leaves no mark that eats the next login
     *
     * Only its own logout action makes the core send the browser to do=login. A logout
     * that starts at the identity provider answers that provider instead, so the mark
     * would stay in the session and swallow the next click on the login link.
     */
    public function testLogoutElsewhereKeepsLoginWorking()
    {
        global $ACT;
        $_POST['SAMLResponse'] = $this->getResponse();
        (new LoginAuth())->trustExternal('', '', false);
        $_POST = [];

        global $auth;
        $auth = new LoginAuth();
        $ACT = 'saml_sls';
        auth_logoff();

        $ACT = 'login';
        (new LoginAuth())->trustExternal('', '', false);

        $this->assertNotNull($this->getRequestId(), 'the wiki did not ask the identity provider');
    }

    /**
     * A click on the login link sends the user to the identity provider
     */
    public function testLoginLinkStartsLogin()
    {
        global $ACT;
        $ACT = 'login';

        $ok = (new LoginAuth())->trustExternal('', '', false);

        $this->assertFalse($ok);
        $this->assertNotNull($this->getRequestId(), 'the wiki asked no identity provider');
    }

    /**
     * The identifier of the request that the wiki sent to the identity provider
     *
     * @return string|null
     */
    protected function getRequestId()
    {
        return $_SESSION[DOKU_COOKIE]['plugin']['saml']['requestid'] ?? null;
    }

    /**
     * A response that no request of this browser answers is refused
     *
     * The browser sends the session cookie of the wiki, so the wiki sees the session in
     * which it would have kept the identifier of its request. The empty session proves
     * that this wiki started no login.
     */
    public function testRefusesUnsolicited()
    {
        $_COOKIE[DOKU_SESSION_NAME] = 'session1';
        $_POST['SAMLResponse'] = $this->getResponse();

        $ok = (new LoginAuth())->trustExternal('', '', false);

        $this->assertFalse($ok);
    }

    /**
     * A response that answers the request of this browser logs the user in
     */
    public function testAcceptsOwnRequest()
    {
        $_COOKIE[DOKU_SESSION_NAME] = 'session1';
        $_SESSION[DOKU_COOKIE]['plugin']['saml']['requestid'] = '_request1';
        $_POST['SAMLResponse'] = $this->getResponse(['inResponseTo' => '_request1']);

        $ok = (new LoginAuth())->trustExternal('', '', false);

        $this->assertTrue($ok);
    }

    /**
     * The same response a second time is refused
     */
    public function testRefusesReplay()
    {
        $_POST['SAMLResponse'] = $this->getResponse();
        $this->assertTrue((new LoginAuth())->trustExternal('', '', false));

        $_SESSION = [];
        $ok = (new LoginAuth())->trustExternal('', '', false);

        $this->assertFalse($ok);
    }
}
