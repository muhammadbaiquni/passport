<?php

namespace FoF\Passport\Middleware;

//use Flarum\Http\RequestUtil;
use Illuminate\Support\Arr;
use Laminas\Diactoros\Response\RedirectResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use Flarum\Foundation\Application;
use Illuminate\Events\Dispatcher;
use Flarum\Http\SessionAuthenticator;
use Flarum\Http\Rememberer;
use Flarum\User\Event\LoggedOut;
use Flarum\User\Exception\PermissionDeniedException;
use Flarum\Settings\SettingsRepositoryInterface;

class LogoutMiddleware implements MiddlewareInterface
{
    public function __construct(Application $app,
                                Dispatcher $events,
                                SessionAuthenticator $authenticator,
                                Rememberer $rememberer,
                                SettingsRepositoryInterface $settings)
    {
        $this->app = $app;
        $this->events = $events;
        $this->settings = $settings;
        $this->authenticator = $authenticator;
        $this->rememberer = $rememberer;
    }
    
    final public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $flarum_logout_url = resolve('flarum.config')['url'] . resolve('flarum.forum.routes')->getPath('logout');
        $identity_logout_url = 'https://identity.forum-thebigbox.com/oauth2/sessions/logout';
        $path = $request->getUri()->getPath();
        $logout_url = resolve('flarum.forum.routes')->getPath('logout');
        
        $actor = $request->getAttribute('actor');
        $session = $request->getAttribute('session');
        $token = $session->token();
        $id_token = $session->get('id_token_identity');
        $cookies = $request->getCookieParams();
        
        $response = $handler->handle($request);
        
        if (!$actor->isGuest() and $path === $logout_url) {
            //$response = new RedirectResponse("$identity_logout_url?id_token_hint=$id_token&post_logout_redirect_uri=$flarum_logout_url");
            
            
            
            // Logout
            $this->authenticator->logOut($session);
            $actor->accessTokens()->delete();
            $this->rememberer->forget($response);
            
            return $response->withHeader("location", "$identity_logout_url?id_token_hint=$id_token&post_logout_redirect_uri=$flarum_logout_url");
        }
        
        return $response;
    }
    
    /*final public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        //$actor = RequestUtil::getActor($request);
        $actor = $request->getAttribute('actor');
        $logout_url = resolve('flarum.forum.routes')->getPath('logout');
        $token = $request->getAttribute('session')->token();
        $path = $request->getUri()->getPath();
        $cookies = $request->getCookieParams();

        if (Arr::exists($cookies, 'flarum_logout') and !$actor->isGuest() and $path !== $logout_url) {
            return new RedirectResponse("$logout_url?token=$token&redirect=false&path=$path");
        }

        return $handler->handle($request);
    }*/
}