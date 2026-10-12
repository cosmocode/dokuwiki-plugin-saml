<?php

namespace dokuwiki\plugin\saml;

use dokuwiki\Utf8\PhpString;
use Exception;
use OneLogin\Saml2\Auth;

/**
 * The user data of a SAML response
 *
 * Maps the attributes of an assertion to the user data that DokuWiki expects and
 * removes the characters that DokuWiki does not permit in user and group names.
 */
class UserMapper
{
    /** @var array the configuration of the plugin */
    protected $conf;

    /**
     * @param array $conf the configuration of the plugin
     */
    public function __construct(array $conf)
    {
        $this->conf = $conf;
    }

    /**
     * The user data of a validated response
     *
     * Reads the login name only when the plugin does not provision users. The wiki then
     * takes the other data from the local user database.
     *
     * @param Auth $saml the library with a processed response
     * @return array user, name, mail and grps
     * @throws Exception when a required attribute is missing
     */
    public function getUserData(Auth $saml)
    {
        global $conf;

        $userdata = ['user' => '', 'name' => '', 'mail' => '', 'grps' => []];

        $userdata['user'] = $this->cleanUser(
            $this->getAttribute($saml, $this->conf['userid_attr_name'])[0]
        );

        if ($this->conf['autoprovisioning']) {
            // the login name is the fallback for the full name
            $nameattr = $this->conf['fullname_attr_name'] ?: $this->conf['userid_attr_name'];
            $userdata['name'] = $this->getAttribute($saml, $nameattr)[0];
            $userdata['mail'] = $this->getAttribute($saml, $this->conf['email_attr_name'])[0];

            // groups are optional, a user without any group is permitted
            if ($this->conf['groups_attr_name']) {
                $userdata['grps'] = $this->getAttribute($saml, $this->conf['groups_attr_name'], false);
            }
        }

        $userdata['grps'][] = $conf['defaultgroup'];
        $userdata['grps'] = array_map($this->cleanGroup(...), $userdata['grps']);

        return $userdata;
    }

    /**
     * Remove the characters that DokuWiki does not permit in a user name
     *
     * @param string $user
     * @return string
     */
    public function cleanUser($user)
    {
        $user = strtr(
            $user,
            [
                ',' => '',
                '/' => '',
                '#' => '',
                ';' => '',
                ':' => ''
            ]
        );
        if ($this->conf['lowercase']) {
            return PhpString::strtolower($user);
        }
        return $user;
    }

    /**
     * Remove the characters that DokuWiki does not permit in a group name
     *
     * @param string $group
     * @return string
     */
    public function cleanGroup($group)
    {
        return $this->cleanUser($group);
    }

    /**
     * One attribute of the assertion
     *
     * @param Auth $saml the library with a processed response
     * @param string $name the name of the attribute
     * @param bool $required throw when the attribute is missing
     * @return array the values of the attribute, at least one when required
     * @throws Exception when a required attribute is missing
     */
    protected function getAttribute(Auth $saml, $name, $required = true)
    {
        $values = (array)$saml->getAttribute($name);
        if ($required && $values === []) {
            throw new Exception('SAML Response is missing attribute ' . $name);
        }
        return $values;
    }
}
