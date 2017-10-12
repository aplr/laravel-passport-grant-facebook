# Laravel-Facebook

[![Travis](https://img.shields.io/travis/aplr/laravel-passport-grant-facebook.svg)](https://packagist.org/packages/aplr/laravel-passport-grant-facebook)
[![Packagist](https://img.shields.io/packagist/v/aplr/laravel-passport-grant-facebook.svg)](https://packagist.org/packages/aplr/laravel-passport-grant-facebook)
[![license](https://img.shields.io/github/license/aplr/laravel-passport-grant-facebook.svg)](https://packagist.org/packages/aplr/laravel-passport-grant-facebook)

## Introduction

The `laravel-passport-grant-facebook` package allows you to use a Facebook Grant in addition to the default Password Grant in Laravel Passport.

## Installation

Require the aplr/laravel-passport-grant-facebook package in your composer.json and update your dependencies:

```shell
$ composer require aplr/laravel-passport-grant-facebook
```
    
Laravel 5.5 uses Package Auto-Discovery, so doesn't require you to manually add the ServiceProvider.
    
If you don't use auto-discovery, add the ServiceProvider to the providers array in config/app.php

```php
Aplr\LaravelPassportFacebook\ServiceProvider::class,
```

## Configuration

This package is using `aplr/laravel-facebook` to access Facebook Graph. See [laravel-facebook configuration](https://github.com/aplr/laravel-facebook#configuration) for details.


## Licence

`laravel-passport-grant-facebook` is open-sourced software licensed under the MIT license.