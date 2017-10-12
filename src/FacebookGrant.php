<?php

/**
 * OAuth 2.0 Facebook grant.
 *
 * @author      Andreas Pfurtscheller <hello@aplr.me>
 * @copyright   Copyright (c) Andreas Pfurtscheller
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/andreas.pfurtscheller
 */

namespace Aplr\LaravelPassportFacebook;

use Psr\Http\Message\ServerRequestInterface;

use Aplr\LaravelFacebook\Facade as Facebook;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;

class FacebookGrant extends AbstractGrant {
    
    /**
     * @param UserRepositoryInterface         $userRepository
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     */
    public function __construct(
        UserRepositoryInterface $userRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository
    ) {
        $this->setUserRepository($userRepository);
        $this->setRefreshTokenRepository($refreshTokenRepository);
        $this->refreshTokenTTL = new \DateInterval('P1M');
    }
    
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $accessTokenTTL
    ) {
        // Validate request
        $client = $this->validateClient($request);
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request));
        $user = $this->validateFacebookToken($request, $client);
        
        $scopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $user->getIdentifier());
        
        // Issue and persist new tokens
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $user->getIdentifier(), $scopes);
        $refreshToken = $this->issueRefreshToken($accessToken);
        
        // Inject tokens into response
        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);
        
        return $responseType;
    }
    
    protected function validateFacebookToken(ServerRequestInterface $request, ClientEntityInterface $client)
    {
        $token = $this->getRequestParameter('facebook_token', $request);
        
        if (is_null($token)) {
            throw OAuthServerException::invalidRequest('facebook_token');
        }
        
        try
        {
            $fbResponse = Facebook::get('/me?fields=id', $token);
            $fbUser = $fbResponse->getGraphUser();
        }
        catch (\Exception $e)
        {
            throw OAuthServerException::invalidCredentials();
        }

        if (!$fbUser)
        {
            throw OAuthServerException::invalidCredentials();
        }
        
        $user = $this->userRepository->getUserEntityByUserCredentials(
            $fbUser['id'],
            null,
            $this->getIdentifier(),
            $client
        );
        
        if ($user instanceof UserEntityInterface === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));
            
            throw OAuthServerException::invalidCredentials();
        }
        
        return $user;
    }
    
    public function getIdentifier()
    {
        return 'facebook';
    }
    
}