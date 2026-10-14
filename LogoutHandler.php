<?php

namespace dokuwiki\plugin\saml;

use dokuwiki\Logger;
use Exception;
use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\LogoutRequest;
use OneLogin\Saml2\LogoutResponse;
use OneLogin\Saml2\Utils;

/**
 * The handler for the Single Logout messages of the identity provider
 *
 * The wiki serves the HTTP-Redirect binding. A message arrives as a GET in the browser of
 * the user, so the session cookie of the wiki comes with it.
 */
class LogoutHandler
{
    /** @var Auth the SAML library, set up for a logout message */
    protected $saml;

    /** @var Session the data of this plugin in the PHP session */
    protected $session;

    /**
     * @param Auth $saml the SAML library, set up for a logout message
     * @param Session $session the data of this plugin in the PHP session
     */
    public function __construct(Auth $saml, Session $session)
    {
        $this->saml = $saml;
        $this->session = $session;
    }

    /**
     * End the login that the identity provider names and answer it
     *
     * @param string $message the base64 LogoutRequest
     * @return void
     * @throws Exception when the request is not valid
     */
    public function handleRequest($message)
    {
        $settings = $this->saml->getSettings();

        $request = new LogoutRequest($settings, $message);
        if (!$request->isValid()) {
            throw new Exception('Invalid SAML LogoutRequest: ' . $request->getError());
        }

        $nameId = LogoutRequest::getNameId($request->getXML(), $settings->getSPkey());
        $indexes = LogoutRequest::getSessionIndexes($request->getXML());
        $this->endSession($nameId, $indexes);

        $this->sendResponse($request->id);
    }

    /**
     * Read the answer of the identity provider to a logout of this wiki
     *
     * @param string $message the base64 LogoutResponse
     * @return void
     * @throws Exception when the response is not valid
     */
    public function handleResponse($message)
    {
        $response = new LogoutResponse($this->saml->getSettings(), $message);
        if (!$response->isValid($this->session->getRequestId())) {
            throw new Exception('Invalid SAML LogoutResponse: ' . $response->getError());
        }

        // the wiki ended its own login before it sent the request, so a failure
        // elsewhere is nothing that the user can act on
        if ($response->getStatus() !== Constants::STATUS_SUCCESS) {
            Logger::error('SAML: the identity provider reported a failed logout', $response->getStatus());
        }

        $this->session->clearRequestId();
    }

    /**
     * End the login of this browser when the request names it
     *
     * A request without a SessionIndex ends every login of that user.
     *
     * @param string $nameId the NameID of the request
     * @param array $indexes the SessionIndexes of the request
     * @return void
     */
    protected function endSession($nameId, $indexes)
    {
        $own = $this->session->getIdpSession();
        if ($own['nameid'] === '' || $own['nameid'] !== $nameId) return;
        if ($indexes !== [] && !in_array($own['sessionindex'], $indexes, true)) return;

        // the SAML session goes first: logOff() of the auth plugin starts a new logout at
        // the identity provider as long as it finds one
        $this->session->clearLogin();
        auth_logoff();
    }

    /**
     * Answer the identity provider with a LogoutResponse
     *
     * @param string $inResponseTo the identifier of the request
     * @return void
     */
    protected function sendResponse($inResponseTo)
    {
        global $INPUT;

        $settings = $this->saml->getSettings();
        $security = $settings->getSecurityData();

        $builder = new LogoutResponse($settings);
        $builder->build($inResponseTo);

        $parameters = ['SAMLResponse' => $builder->getResponse()];
        $relay = $INPUT->str('RelayState');
        if ($relay !== '') $parameters['RelayState'] = $relay;
        if ($security['logoutResponseSigned']) {
            $parameters['SigAlg'] = $security['signatureAlgorithm'];
            $parameters['Signature'] = $this->saml->buildResponseSignature(
                $parameters['SAMLResponse'],
                $parameters['RelayState'] ?? null,
                $security['signatureAlgorithm']
            );
        }

        send_redirect(Utils::redirect($this->saml->getSLOResponseUrl(), $parameters, true));
    }
}
