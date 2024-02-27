<?php

namespace Laragear\WebAuthn\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\Models\WebAuthnCredential;

class CredentialCreated
{
    use Dispatchable;

    /**
     * Create a new event instance.
     */
    public function __construct(public WebAuthnAuthenticatable $user, public WebAuthnCredential $credential)
    {
        //
    }
}
