<?php

namespace dokuwiki\plugin\saml\test;

use dokuwiki\plugin\saml\Session;
use Exception;

/**
 * Tests for the Single Logout messages of the identity provider
 *
 * @group plugin_saml
 * @group plugins
 */
class LogoutTest extends AbstractMessageTest
{
    /** @inheritdoc */
    public function setUp(): void
    {
        parent::setUp();

        // the library builds the address of the endpoint from the base URL and the script
        $_SERVER['REQUEST_URI'] = '/' . DOKU_SCRIPT . '?do=saml_sls';
        $_SERVER['QUERY_STRING'] = 'do=saml_sls';
        $_SESSION = [];
    }

    /**
     * The handler of the plugin
     *
     * @param array $overrides settings that differ from the default
     * @return \dokuwiki\plugin\saml\LogoutHandler
     */
    protected function getHandler($overrides = [])
    {
        global $conf;
        $conf['plugin']['saml'] = $this->getConf($overrides);

        /** @var \helper_plugin_saml $hlp */
        $hlp = plugin_load('helper', 'saml', true);
        return $hlp->getLogoutHandler();
    }

    /**
     * A login of the given user in the session of this browser
     *
     * @param string $nameId
     * @param string $sessionIndex
     * @return void
     */
    protected function login($nameId = 'andi', $sessionIndex = '_session1')
    {
        $session = new Session();
        $session->setLogin($nameId, ['user' => $nameId, 'name' => '', 'mail' => '', 'grps' => []]);
        $session->setIdpSession([
            'nameid' => $nameId,
            'format' => '',
            'namequalifier' => '',
            'spnamequalifier' => '',
            'sessionindex' => $sessionIndex,
        ]);
    }

    /**
     * Is the browser of this test still logged in?
     *
     * @return bool
     */
    protected function isLoggedIn()
    {
        return isset($_SESSION[DOKU_COOKIE]['auth']['user']);
    }

    /**
     * A signed request ends the login of this browser
     */
    public function testRequest()
    {
        $this->login();
        $this->sendByRedirect($this->getLogoutMessage(), true);

        $this->getHandler()->handleRequest($_GET['SAMLRequest']);

        $this->assertFalse($this->isLoggedIn());
    }

    /**
     * A request without a signature is refused
     */
    public function testUnsignedRequest()
    {
        $this->login();
        $this->sendByRedirect($this->getLogoutMessage(['sign' => false]), true, false);

        try {
            $this->getHandler()->handleRequest($_GET['SAMLRequest']);
            $this->fail('the request was not refused');
        } catch (Exception $e) {
            $this->assertTrue($this->isLoggedIn());
        }
    }

    /**
     * A request for another address is refused
     */
    public function testWrongDestination()
    {
        $this->sendByRedirect($this->getLogoutMessage(['destination' => 'https://evil.example.org/sls']), true);

        $this->expectException(Exception::class);
        $this->getHandler()->handleRequest($_GET['SAMLRequest']);
    }

    /**
     * A request for another login leaves this one alone
     */
    public function testOtherSession()
    {
        $this->login('andi', '_session1');
        $this->sendByRedirect($this->getLogoutMessage(['sessionIndex' => '_other']), true);

        $this->getHandler()->handleRequest($_GET['SAMLRequest']);

        $this->assertTrue($this->isLoggedIn());
    }

    /**
     * A request for another user leaves this login alone
     */
    public function testOtherUser()
    {
        $this->login('andi', '_session1');
        $this->sendByRedirect($this->getLogoutMessage(['nameId' => 'eve']), true);

        $this->getHandler()->handleRequest($_GET['SAMLRequest']);

        $this->assertTrue($this->isLoggedIn());
    }

    /**
     * A request without a SessionIndex ends the login of that user
     */
    public function testRequestWithoutSessionIndex()
    {
        $this->login('andi', '_session1');
        $this->sendByRedirect($this->getLogoutMessage(['sessionIndex' => '']), true);

        $this->getHandler()->handleRequest($_GET['SAMLRequest']);

        $this->assertFalse($this->isLoggedIn());
    }

    /**
     * The answer of the identity provider to a logout of this wiki is accepted
     */
    public function testResponse()
    {
        $this->sendByRedirect($this->getLogoutMessage(['inResponseTo' => '_request1']), false);

        $this->getHandler()->handleResponse($_GET['SAMLResponse']);

        $this->assertNull($_SESSION[DOKU_COOKIE]['plugin']['saml']['requestid'] ?? null);
    }

    /**
     * An answer that reports a failure does not stop the user
     *
     * The wiki ended its own login before it sent the request, so the user goes on.
     */
    public function testFailedResponse()
    {
        $this->sendByRedirect($this->getLogoutMessage([
            'inResponseTo' => '_request1',
            'status' => 'urn:oasis:names:tc:SAML:2.0:status:Requester',
        ]), false);

        $this->getHandler()->handleResponse($_GET['SAMLResponse']);

        $this->assertNull($_SESSION[DOKU_COOKIE]['plugin']['saml']['requestid'] ?? null);
    }

    /**
     * An answer without a signature is refused
     */
    public function testUnsignedResponse()
    {
        $this->sendByRedirect($this->getLogoutMessage(['inResponseTo' => '_request1', 'sign' => false]), false, false);

        $this->expectException(Exception::class);
        $this->getHandler()->handleResponse($_GET['SAMLResponse']);
    }
}
