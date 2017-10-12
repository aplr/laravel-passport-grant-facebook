<?php 

/**
 * Facebook Grant User Repository
 *
 * @author      Andreas Pfurtscheller <hello@aplr.me>
 * @copyright   Copyright (c) Andreas Pfurtscheller
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/andreas.pfurtscheller
 */

namespace Aplr\LaravelPassportFacebook;

use RuntimeException;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;

use Laravel\Passport\Bridge\User;

class FacebookUserRepository implements UserRepositoryInterface {
    
    /**
     * {@inheritdoc}
     */
    public function getUserEntityByUserCredentials($username, $password, $grantType, ClientEntityInterface $clientEntity)
    {
        $provider = config('auth.guards.api.provider');
        
        if (is_null($model = config("auth.providers.{$provider}.model"))) {
            throw new RuntimeException('Unable to determine authentication model from configuration.');
        }
        
        if (method_exists($model, 'findForFacebook')) {
            $user = (new $model)->findForFacebook($username);
        } else {
            $user = (new $model)->where('facebook_id', $username)->first();
        }
        
        if (! $user) {
            return;
        }
        
        return new User($user->getAuthIdentifier());
    }
    
}