<?php

namespace Laragear\WebAuthn\Attestation\Creator\Pipes;

use Closure;
use Illuminate\Support\Str;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreation;

/**
 * @internal
 */
class AddUserDescriptor
{
    /**
     * Handle the Attestation creation
     *
     * @param  \Laragear\WebAuthn\Attestation\Creator\AttestationCreation  $attestable
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(AttestationCreation $attestable, Closure $next): mixed
    {
        $config = $attestable->user->webAuthnData();

        // Create a new User UUID if it doesn't existe already in the credentials.
        // @phpstan-ignore-next-line
        $config['id'] = $attestable->user->webAuthnCredentials()->value('user_id')
            ?: Str::uuid()->getHex()->toString();

        $attestable->json->set('user', $config);

        return $next($attestable);
    }
}
