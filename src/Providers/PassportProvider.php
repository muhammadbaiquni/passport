<?php

namespace FoF\Passport\Providers;

use FoF\Passport\Events\ParsingResourceOwner;
use FoF\Passport\ResourceOwner;
use Flarum\Settings\SettingsRepositoryInterface;
use Illuminate\Contracts\Events\Dispatcher;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;
use Ahc\Jwt\JWT;

class PassportProvider extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * @var SettingsRepositoryInterface
     */
    protected $settings;

    /**
     * Returns the base URL for authorizing a client.
     *
     * Eg. https://oauth.service.com/authorize
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return $this->settings->get('fof-passport.app_auth_url');
    }

    /**
     * Returns the base URL for requesting an access token.
     *
     * Eg. https://oauth.service.com/token
     *
     * @param array $params
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->settings->get('fof-passport.app_token_url');
    }

    /**
     * Returns the URL for requesting the resource owner's details.
     *
     * @param AccessToken $token
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return $this->settings->get('fof-passport.app_user_url');
    }

    /**
     * Returns the default scopes used by this provider.
     *
     * This should only be the scopes that are required to request the details
     * of the resource owner, rather than all the available scopes.
     *
     * @return array
     */
    protected function getDefaultScopes()
    {
        return explode(',', $this->settings->get('fof-passport.app_oauth_scopes', ''));
    }

    /**
     * Checks a provider response for errors.
     *
     * @throws IdentityProviderException
     * @param  ResponseInterface $response
     * @param  array|string $data Parsed response data
     * @return void
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
    }

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     *
     * @param  array $response
     * @param  AccessToken $token
     * @return ResourceOwnerInterface
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        resolve(Dispatcher::class)->dispatch(new ParsingResourceOwner($response));

        return new ResourceOwner($response);
    }

    /**
     * Request resource owner detail
     * 
     * @param AccessToken $token
     * @return mixed
     */
    protected function fetchResourceOwnerDetails(AccessToken $token)
    {
        $url = $this->getResourceOwnerDetailsUrl($token);

        $body = ['token' => $token->getToken()];

        $options['body'] = \http_build_query($body);
        $options['headers']['Content-type'] = 'application/x-www-form-urlencoded';

        $request = $this->getAuthenticatedRequest(parent::METHOD_POST, $url, $token, $options);

        $response = $this->getParsedResponse($request);

        if (false === is_array($response)) {
            throw new UnexpectedValueException(
                'Invalid response received from Authorization Server. Expected JSON.'
            );
        }

        return $response;
    }

    /**
     * Get resource owner email from token
     * 
     * @param AccessToken $token
     * @return string
     */
    public function getEmailFromToken(AccessToken $token)
    {
        $email = '';

        $values = $token->getValues();
        $id_token = $values['id_token'];

        $key = 'secret';

        if(!empty($id_token)) {
            $jwt = new JWT($key, 'RS256');
            $payload = $jwt->decode($id_token, FALSE);
            $email = $payload['email'];
        }

        return $email;
    }
}
