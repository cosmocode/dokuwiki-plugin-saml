<?php

namespace dokuwiki\plugin\saml\test;

use DokuWikiTest;

/**
 * Tests for the page that the RelayState of a message names
 *
 * @group plugin_saml
 * @group plugins
 */
class TargetPageTest extends DokuWikiTest
{
    /** @inheritdoc */
    protected $pluginsEnabled = ['saml'];

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
            'empty' => ['', 'current:page'],
            'another site' => ['https://evil.example.org/', 'current:page'],
            'an address of the wiki' => [DOKU_URL . 'doku.php?id=start', 'current:page'],
            'a line break' => ["start\nSet-Cookie: x=y", 'current:page'],
            'a value of the identity provider' => ['RPID=https%3A%2F%2Fexample.org', 'current:page'],
            'a name that needs cleaning' => ['Wiki Syntax', 'current:page'],
        ];
    }

    /**
     * Only a page ID that this wiki sent is used, everything else gives the current page
     *
     * @dataProvider provideRelayStates
     * @param string $relay
     * @param string $expected the ID of the page that the user should see
     */
    public function testTargetPage($relay, $expected)
    {
        global $ID;
        global $INPUT;
        $ID = 'current:page';
        $INPUT->set('RelayState', $relay);

        /** @var \helper_plugin_saml $hlp */
        $hlp = plugin_load('helper', 'saml', true);

        $this->assertEquals(wl($expected, '', true, '&'), $hlp->getTargetPage());
    }

    /**
     * The wiki builds the address itself, so it always points into the wiki
     *
     * @dataProvider provideRelayStates
     * @param string $relay
     */
    public function testStaysInTheWiki($relay)
    {
        global $ID;
        global $INPUT;
        $ID = 'current:page';
        $INPUT->set('RelayState', $relay);

        /** @var \helper_plugin_saml $hlp */
        $hlp = plugin_load('helper', 'saml', true);

        $this->assertStringStartsWith(DOKU_URL, $hlp->getTargetPage());
    }
}
