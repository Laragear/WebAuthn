<?php

namespace Laragear\WebAuthn\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Laragear\WebAuthn\Models\WebAuthnCredential;

class CredentialCloned
{
    use Dispatchable;

    /**
     * Create a new event instance.
     */
    public function __construct(public WebAuthnCredential $credential, public int $reportedCount)
    {
        //
    }
}
