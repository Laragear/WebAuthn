<?php

namespace Laragear\WebAuthn\Attestation\Creator\Pipes;

use Closure;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreation;
use Ramsey\Uuid\Uuid;

/**
 * @internal
 */
class AddUserDescriptor
{
    /**
     * Handle the Attestation creation.
     */
    public function handle(AttestationCreation $attestable, Closure $next): mixed
    {
        // Try to find the User Handle (user_id) to reuse it on the new credential.
        $existingId = $attestable->user->webAuthnCredentials()->getQuery()->value('user_id');

        $attestable->json->set('user', [
            'id' => ($existingId ? Uuid::fromString($existingId) : $attestable->user->webAuthnId())->getHex()->toString(),
            ...$attestable->user->webAuthnData(),
        ]);

        return $next($attestable);
    }
}
