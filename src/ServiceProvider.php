<?php 

/**
 * Facebook Grant ServiceProvider.
 *
 * @author      Andreas Pfurtscheller <hello@aplr.me>
 * @copyright   Copyright (c) Andreas Pfurtscheller
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/andreas.pfurtscheller
 */

namespace Aplr\LaravelPassportFacebook;

use Illuminate\Support\ServiceProvider as LaravelServiceProvider;

use Laravel\Passport\Passport;
use League\OAuth2\Server\AuthorizationServer;
use Laravel\Passport\Bridge\RefreshTokenRepository;

use Aplr\LaravelPassportFacebook\FacebookGrant;
use Aplr\LaravelPassportFacebook\FacebookUserRepository;

class ServiceProvider extends LaravelServiceProvider {
        
    public function boot()
    {
        $this->app->resolving(AuthorizationServer::class, function ($server, $app) {
            $server->enableGrantType(
                $this->makeFacebookGrant(), Passport::tokensExpireIn()
            );
        });
    }
    
    protected function makeFacebookGrant()
    {
        $grant = new FacebookGrant(
            $this->app->make(FacebookUserRepository::class),
            $this->app->make(RefreshTokenRepository::class)
        );
        
        $grant->setRefreshTokenTTL(Passport::refreshTokensExpireIn());
        
        return $grant;
    }
    
}