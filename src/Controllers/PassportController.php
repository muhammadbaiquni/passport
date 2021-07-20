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
use Illuminate\Support\Str;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Laminas\Diactoros\Response\RedirectResponse;
use Flarum\Http\UrlGenerator;
use League\OAuth2\Client\OptionProvider\HttpBasicAuthOptionProvider;

use Flarum\User\Command\RegisterUser;
use Flarum\User\Exception\PermissionDeniedException;
use Flarum\User\User;
use Flarum\User\UserRepository;
use Illuminate\Database\Eloquent\ModelNotFoundException;

class PassportController implements RequestHandlerInterface
{
    protected $settings;
    protected $response;
    protected $events;
    protected $url;
    
    private $users;

    public function __construct(ResponseFactory $response, SettingsRepositoryInterface $settings, Dispatcher $events, UrlGenerator $url, UserRepository $users)
    {
        $this->response = $response;
        $this->settings = $settings;
        $this->events = $events;
        $this->url = $url;
        $this->users = $users;
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
        $email = $provider->getEmailFromToken($token);
        
        $session->put('id_token_identity', $token->getValues()['id_token']);
        
        // Register new user when nothing found
        try {
            $userFromIdentity = $this->users->findOrFailByUsername($user->getId());
        } catch (ModelNotFoundException $e) {
            $userFromIdentity = $this->users->findByIdentification($email ?? $user->getId());
        }
        
        if ($userFromIdentity === null) {
            $userFromIdentity = User::register(
                $user->getId(),
                $email,
                Str::random(20)
            );
            
            $userFromIdentity->activate();
            $userFromIdentity->save();
        }

        $response = $this->response->make(
            'passport', $user->getId(),
            function (Registration $registration) use ($user, $provider, $token, $email) {
                $registration
                    ->provideTrustedEmail($email)
                    ->provide('username', $user->getId())
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
