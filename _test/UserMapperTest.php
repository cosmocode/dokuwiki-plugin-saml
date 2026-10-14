<?php

namespace dokuwiki\plugin\saml\test;

use dokuwiki\plugin\saml\UserMapper;
use DokuWikiTest;
use Exception;
use OneLogin\Saml2\Auth;

/**
 * Tests for the user data of a SAML response
 *
 * @group plugin_saml
 * @group plugins
 */
class UserMapperTest extends DokuWikiTest
{
    /** @inheritdoc */
    protected $pluginsEnabled = ['saml'];

    /**
     * The plugin configuration that the tests start from
     *
     * @param array $overrides settings that differ from the default
     * @return array
     */
    protected function getConf($overrides = [])
    {
        return array_merge([
            'lowercase' => 1,
            'autoprovisioning' => 1,
            'userid_attr_name' => 'login',
            'fullname_attr_name' => 'fullname',
            'email_attr_name' => 'email',
            'groups_attr_name' => 'groups',
        ], $overrides);
    }

    /**
     * A processed response with the given attributes
     *
     * @param array $attributes Name to values
     * @param array $friendly FriendlyName to values
     * @return Auth
     */
    protected function getLib($attributes, $friendly = [])
    {
        $saml = $this->createMock(Auth::class);
        $saml->method('getAttribute')->willReturnCallback(
            static fn($name) => $attributes[$name] ?? null
        );
        $saml->method('getAttributeWithFriendlyName')->willReturnCallback(
            static fn($name) => $friendly[$name] ?? null
        );
        return $saml;
    }

    /**
     * A processed response with all the attributes
     *
     * @param array $overrides attributes that differ from the default
     * @return Auth
     */
    protected function getResponse($overrides = [])
    {
        return $this->getLib(array_merge([
            'login' => ['Andi'],
            'fullname' => ['Andreas Gohr'],
            'email' => ['andi@example.org'],
            'groups' => ['Admins', 'Wiki,Users'],
        ], $overrides));
    }

    /**
     * All attributes are read and cleaned
     */
    public function testFullResponse()
    {
        global $conf;
        $mapper = new UserMapper($this->getConf());

        $userdata = $mapper->getUserData($this->getResponse());

        $this->assertEquals('andi', $userdata['user']);
        $this->assertEquals('Andreas Gohr', $userdata['name']);
        $this->assertEquals('andi@example.org', $userdata['mail']);
        $this->assertEquals(['admins', 'wikiusers', $conf['defaultgroup']], $userdata['grps']);
    }

    /**
     * Names keep their case when the plugin does not lowercase them
     */
    public function testKeepCase()
    {
        $mapper = new UserMapper($this->getConf(['lowercase' => 0]));

        $userdata = $mapper->getUserData($this->getResponse());

        $this->assertEquals('Andi', $userdata['user']);
        $this->assertEquals('Admins', $userdata['grps'][0]);
    }

    /**
     * A user without any group gets the default group only
     */
    public function testNoGroupsInResponse()
    {
        global $conf;
        $mapper = new UserMapper($this->getConf());
        $response = $this->getLib([
            'login' => ['andi'],
            'fullname' => ['Andreas Gohr'],
            'email' => ['andi@example.org'],
        ]);

        $userdata = $mapper->getUserData($response);

        $this->assertEquals([$conf['defaultgroup']], $userdata['grps']);
    }

    /**
     * Without a configured group attribute the response groups are ignored
     */
    public function testNoGroupsConfigured()
    {
        global $conf;
        $mapper = new UserMapper($this->getConf(['groups_attr_name' => '']));

        $userdata = $mapper->getUserData($this->getResponse());

        $this->assertEquals([$conf['defaultgroup']], $userdata['grps']);
    }

    /**
     * The login name is the fallback for the full name
     */
    public function testNoFullnameConfigured()
    {
        $mapper = new UserMapper($this->getConf(['fullname_attr_name' => '']));

        $userdata = $mapper->getUserData($this->getResponse());

        $this->assertEquals('Andi', $userdata['name']);
    }

    /**
     * An attribute may repeat in the response
     */
    public function testRepeatedAttribute()
    {
        global $conf;
        $mapper = new UserMapper($this->getConf());

        $userdata = $mapper->getUserData($this->getResponse(['groups' => ['one', 'two', 'three']]));

        $this->assertEquals(['one', 'two', 'three', $conf['defaultgroup']], $userdata['grps']);
    }

    /**
     * Without auto provisioning only the login name is read
     */
    public function testNoAutoProvisioning()
    {
        $mapper = new UserMapper($this->getConf(['autoprovisioning' => 0]));

        $userdata = $mapper->getUserData($this->getResponse());

        $this->assertEquals('andi', $userdata['user']);
        $this->assertEquals('', $userdata['name']);
        $this->assertEquals('', $userdata['mail']);
    }

    /**
     * An attribute that the Name does not give is taken from the FriendlyName
     */
    public function testFriendlyNameFallback()
    {
        global $conf;
        $mapper = new UserMapper($this->getConf());
        $response = $this->getLib(
            ['urn:oid:0.9.2342.19200300.100.1.1' => ['Andi']],
            [
                'login' => ['Someone Else'],
                'fullname' => ['Andreas Gohr'],
                'email' => ['andi@example.org'],
                'groups' => ['Admins'],
            ]
        );

        $userdata = $mapper->getUserData($response);

        $this->assertEquals('someone else', $userdata['user']);
        $this->assertEquals('Andreas Gohr', $userdata['name']);
        $this->assertEquals('andi@example.org', $userdata['mail']);
        $this->assertEquals(['admins', $conf['defaultgroup']], $userdata['grps']);
    }

    /**
     * The Name of an attribute counts before the FriendlyName
     */
    public function testNamePreferredOverFriendlyName()
    {
        $mapper = new UserMapper($this->getConf());
        $response = $this->getLib(
            [
                'login' => ['Andi'],
                'fullname' => ['Andreas Gohr'],
                'email' => ['andi@example.org'],
            ],
            ['login' => ['Someone Else']]
        );

        $userdata = $mapper->getUserData($response);

        $this->assertEquals('andi', $userdata['user']);
    }

    /**
     * The first configured attribute with a value gives the login name and the mail
     */
    public function testSeveralNamesFirstValue()
    {
        $mapper = new UserMapper($this->getConf([
            'userid_attr_name' => 'uid login',
            'email_attr_name' => 'mail email',
        ]));
        $response = $this->getLib([
            'login' => ['Andi'],
            'fullname' => ['Andreas Gohr'],
            'email' => ['andi@example.org'],
        ]);

        $userdata = $mapper->getUserData($response);

        $this->assertEquals('andi', $userdata['user']);
        $this->assertEquals('andi@example.org', $userdata['mail']);
    }

    /**
     * An attribute without a value does not win over the next one
     */
    public function testSeveralNamesEmptyValue()
    {
        $mapper = new UserMapper($this->getConf(['userid_attr_name' => 'uid login']));

        $userdata = $mapper->getUserData($this->getResponse(['uid' => ['']]));

        $this->assertEquals('andi', $userdata['user']);
    }

    /**
     * The full name joins the values of all configured attributes
     */
    public function testSeveralNamesJoined()
    {
        $mapper = new UserMapper($this->getConf(['fullname_attr_name' => 'givenName sn']));
        $response = $this->getResponse(['givenName' => ['Andreas'], 'sn' => ['Gohr']]);

        $userdata = $mapper->getUserData($response);

        $this->assertEquals('Andreas Gohr', $userdata['name']);
    }

    /**
     * The groups collect the values of all configured attributes once
     */
    public function testSeveralNamesCollected()
    {
        global $conf;
        $mapper = new UserMapper($this->getConf(['groups_attr_name' => 'groups ou']));
        $response = $this->getResponse([
            'groups' => ['Admins', 'Users'],
            'ou' => ['Users', 'Staff'],
        ]);

        $userdata = $mapper->getUserData($response);

        $this->assertEquals(['admins', 'users', 'staff', $conf['defaultgroup']], $userdata['grps']);
    }

    /**
     * A response without the login attribute is refused
     */
    public function testMissingUserAttribute()
    {
        $mapper = new UserMapper($this->getConf());

        $this->expectException(Exception::class);
        $mapper->getUserData($this->getResponse(['login' => null]));
    }

    /**
     * A response without the mail attribute is refused
     */
    public function testMissingMailAttribute()
    {
        $mapper = new UserMapper($this->getConf());

        $this->expectException(Exception::class);
        $mapper->getUserData($this->getResponse(['email' => null]));
    }
}
