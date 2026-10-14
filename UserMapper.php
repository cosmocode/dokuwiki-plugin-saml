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
     * The login name and the mail address take the first value that the configured
     * attributes give, the full name joins all of them and the groups collect all of
     * them.
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
            $this->getAttributes($saml, $this->conf['userid_attr_name'])[0]
        );

        if ($this->conf['autoprovisioning']) {
            // the login name is the fallback for the full name
            $nameattr = $this->conf['fullname_attr_name'] ?: $this->conf['userid_attr_name'];
            $userdata['name'] = implode(' ', $this->getAttributes($saml, $nameattr));
            $userdata['mail'] = $this->getAttributes($saml, $this->conf['email_attr_name'])[0];

            // groups are optional, a user without any group is permitted
            if ($this->conf['groups_attr_name']) {
                $userdata['grps'] = $this->getAttributes($saml, $this->conf['groups_attr_name'], false);
            }
        }

        $userdata['grps'][] = $conf['defaultgroup'];
        $userdata['grps'] = array_values(array_unique(array_map($this->cleanGroup(...), $userdata['grps'])));

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
     * The values that one or more attributes of the assertion give
     *
     * The values keep the order of the configured names, so the first one belongs to
     * the first attribute that has a value.
     *
     * @param Auth $saml the library with a processed response
     * @param string $names one or more attribute names, separated by spaces
     * @param bool $required throw when no attribute has a value
     * @return array the values, at least one when required
     * @throws Exception when a required attribute is missing
     */
    protected function getAttributes(Auth $saml, $names, $required = true)
    {
        $values = [];
        foreach (preg_split('/\s+/', trim($names), -1, PREG_SPLIT_NO_EMPTY) as $name) {
            $values = array_merge($values, $this->getAttribute($saml, $name));
        }

        if ($required && $values === []) {
            throw new Exception('SAML Response is missing attribute ' . $names);
        }
        return $values;
    }

    /**
     * The values of one attribute of the assertion
     *
     * The Name of an attribute counts first. An identity provider that gives the full
     * Name as a URN names the attribute a second time with a short FriendlyName, which
     * the administrator can configure instead.
     *
     * @param Auth $saml the library with a processed response
     * @param string $name the Name or the FriendlyName of the attribute
     * @return array the values of the attribute, empty when the response has none
     */
    protected function getAttribute(Auth $saml, $name)
    {
        $values = (array)$saml->getAttribute($name);
        if ($values === []) {
            $values = (array)$saml->getAttributeWithFriendlyName($name);
        }

        // an attribute without a value must not win over the next one
        return array_values(array_filter($values, static fn($value) => trim((string)$value) !== ''));
    }
}
