<?php

namespace Tests\Stubs;

use Illuminate\Foundation\Auth\User;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\WebAuthnAuthentication;

/**
 * @method static static forceCreate(array $attributes = [])
 */
class WebAuthnAuthenticatableUser extends User implements WebAuthnAuthenticatable
{
    use WebAuthnAuthentication;

    protected $table = 'users';
}
