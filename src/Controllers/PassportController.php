<?php

namespace FoF\Passport\Controllers;

use Exception;
use FoF\Passport\Events\SendingResponse;
use FoF\Passport\Providers\PassportProvider;
use Flarum\Forum\Auth\Registration;
use Flarum\Forum\Auth\ResponseFactory;
use Flarum\Settings\SettingsRepositoryInterface;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Arr;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Laminas\Diactoros\Response\RedirectResponse;
use Flarum\Http\UrlGenerator;
use League\OAuth2\Client\OptionProvider\HttpBasicAuthOptionProvider;

class PassportController implements RequestHandlerInterface
{
    protected $settings;
    protected $response;
    protected $events;
    protected $url;
    protected $email;

    public function __construct(ResponseFactory $response, SettingsRepositoryInterface $settings, Dispatcher $events, UrlGenerator $url)
    {
        $this->response = $response;
        $this->settings = $settings;
        $this->events = $events;
        $this->url = $url;
    }

    protected function getProvider($redirectUri)
    {
        return new PassportProvider([
            'clientId'     => $this->settings->get('fof-passport.app_id'),
            'clientSecret' => $this->settings->get('fof-passport.app_secret'),
            'redirectUri'  => $redirectUri,
            'settings'     => $this->settings
        ], [
            'optionProvider' => new HttpBasicAuthOptionProvider()
        ]);
    }

    /**
     * @return array
     */
    protected function getAuthorizationUrlOptions()
    {
        $scopes = $this->settings->get('fof-passport.app_oauth_scopes', '');

        return ['scope' => $scopes];
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $redirectUri = $this->url->to('forum')->route('auth.passport'); 

        $provider = $this->getProvider($redirectUri); 

        $session     = $request->getAttribute('session');
        $queryParams = $request->getQueryParams(); 

        if ($error = Arr::get($queryParams, 'error')) {
            $hint = Arr::get($queryParams, 'hint');

            throw new Exception("$error: $hint");
        }

        $code = Arr::get($queryParams, 'code'); 

        if (!$code) {
            $authUrl = $provider->getAuthorizationUrl($this->getAuthorizationUrlOptions());
            $session->put('oauth2state', $provider->getState());

            return new RedirectResponse($authUrl);
        }

        $state = Arr::get($queryParams, 'state');

        if (!$state || $state !== $session->get('oauth2state')) {
            $session->remove('oauth2state');
            throw new Exception('Invalid state');
        }

        $token = $provider->getAccessToken('authorization_code', compact('code'));
        $user  = $provider->getResourceOwner($token);
        $this->email = $provider->getEmailFromToken($token);
        
        $session->put('id_token_identity', $token->getValues()['id_token']);
        
        // -- test
        //echo "<pre>";
        //echo "provider:\n"; print_r($provider); echo "\n\n";
        //echo "token:\n"; print_r($token); echo "\n\n";
        //echo "user:\n"; print_r($user); echo "\n\n";
        //echo "email:\n"; print_r($email); echo "\n\n";
        //echo "user:\n"; print_r($user); echo "\n\n";
        //echo "user_id:\n"; print_r($user->getId()); echo "\n\n";
        //die;
        

        $response = $this->response->make(
            'passport', $user->getId(),
            function (Registration $registration) use ($user, $provider, $token) {
                $registration
                    ->provideTrustedEmail($this->email)
                    ->setPayload($user->toArray());
            }
        );

        $this->events->dispatch(new SendingResponse(
            $response,
            $user,
            $token
        ));

        return $response;
    }
}
