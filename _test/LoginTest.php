<?php

namespace dokuwiki\plugin\saml\test;

use auth_plugin_saml;

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
        auth_logoff();

        $ACT = 'login';
        $ok = (new LoginAuth())->trustExternal('', '', false);

        $this->assertFalse($ok);
        $this->assertNull($this->getRequestId(), 'the wiki asked the identity provider again');
        $this->assertEquals('show', $ACT);
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
