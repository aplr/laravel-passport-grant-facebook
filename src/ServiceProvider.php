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
        // get key paths
        list($publicKey, $privateKey) = [
            Passport::keyPath('oauth-public.key'),
            Passport::keyPath('oauth-private.key'),
        ];

        // exit early, as the keys are not set yet.
        // thereby, passport is not ready to be used yet,
        // as it will just exit with an exception.
        if (! (file_exists($publicKey) || file_exists($privateKey)) ) {
            return;
        }

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