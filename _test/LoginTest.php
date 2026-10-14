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
