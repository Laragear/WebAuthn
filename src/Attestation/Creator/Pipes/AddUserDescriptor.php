<?php

namespace Laragear\WebAuthn\Attestation\Creator\Pipes;

use Closure;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreation;
use Laragear\WebAuthn\WebAuthnData;
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
        $attestable->json->set('user', [
            'id' => $this->retrieveUserUuid($attestable),
            ...$this->getUserData($attestable)->toArray(),
        ]);

        return $next($attestable);
    }

    /**
     * Retrieve the User UUID if it already exists, or create one from the user instance.
     */
    protected function retrieveUserUuid(AttestationCreation $attestable): string
    {
        // Try to find the User Handle (user_id) first to reuse it on the new credential.
        $existingId = $attestable->user->webAuthnCredentials()->getQuery()->value('user_id');

        if ($existingId) {
            return Uuid::fromString($existingId)->getHex()->toString();
        }

        return $attestable->user->webAuthnId()->getHex()->toString();
    }

    /**
     * Retrieve the user data from the attestation or the user itself.
     */
    protected function getUserData(AttestationCreation $attestable): WebAuthnData
    {
        return $attestable->using
            ? ($attestable->using)($attestable->user, $attestable->uniqueCredentials)
            : $attestable->user->webAuthnData();
    }
}
