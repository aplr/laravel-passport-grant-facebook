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

use Aplr\LaravelFacebook\Facade as Facebook;
use Illuminate\Support\ServiceProvider as LaravelServiceProvider;


use Laravel\Passport\Passport;
use League\OAuth2\Server\AuthorizationServer;
use Laravel\Passport\Bridge\RefreshTokenRepository;

class ServiceProvider extends LaravelServiceProvider {
        
    public function register()
    {
        $this->registerFacebookGrant();
    }
    
    protected function registerFacebookGrant()
    {
        $this->app->make(AuthorizationServer::class)->enableGrantType(
            $this->makeFacebookGrant(), Passport::tokensExpireIn()
        );
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