<?php

namespace dokuwiki\plugin\saml\test;

/**
 * Gives the test access to the protected target of a RelayState
 */
class TargetAuth extends \auth_plugin_saml
{
    /** @inheritdoc */
    public function getPluginName()
    {
        return 'saml';
    }

    /**
     * The address that a RelayState leads to
     *
     * @param string $relay
     * @return string
     */
    public function relayTarget($relay)
    {
        return $this->getTarget($relay);
    }
}

/**
 * Tests for the page that the user sees after a login or a logout
 *
 * @group plugin_saml
 * @group plugins
 */
class TargetTest extends AbstractMessageTest
{
    /** @var string the page that the user is on while the test runs */
    protected const CURRENT = 'current:page';

    /**
     * RelayState values and the ID of the page that they lead to
     *
     * @return array
     */
    public function provideRelayStates()
    {
        return [
            'a page of the wiki' => ['wiki:syntax', 'wiki:syntax'],
            'the start page' => ['start', 'start'],
            'empty' => ['', self::CURRENT],
            'another site' => ['https://evil.example.org/', self::CURRENT],
            'an address of the wiki' => [DOKU_URL . 'doku.php?id=start', self::CURRENT],
            'a line break' => ["start\nSet-Cookie: x=y", self::CURRENT],
            'a value of the identity provider' => ['RPID=https%3A%2F%2Fexample.org', self::CURRENT],
            'a name that needs cleaning' => ['Wiki Syntax', self::CURRENT],
        ];
    }

    /**
     * Only a page ID that this wiki sent is used, everything else gives the current page
     *
     * @dataProvider provideRelayStates
     * @param string $relay
     * @param string $expected the ID of the page that the user should see
     */
    public function testTarget($relay, $expected)
    {
        global $conf;
        global $ID;
        $conf['plugin']['saml'] = $this->getConf();
        $ID = self::CURRENT;

        $auth = new TargetAuth();

        $this->assertEquals(wl($expected, '', true, '&'), $auth->relayTarget($relay));
    }

    /**
     * The wiki builds the address itself, so it always points into the wiki
     *
     * @dataProvider provideRelayStates
     * @param string $relay
     */
    public function testTargetStaysInTheWiki($relay)
    {
        global $conf;
        global $ID;
        $conf['plugin']['saml'] = $this->getConf();
        $ID = self::CURRENT;

        $auth = new TargetAuth();

        $this->assertStringStartsWith(DOKU_URL, $auth->relayTarget($relay));
    }
}
