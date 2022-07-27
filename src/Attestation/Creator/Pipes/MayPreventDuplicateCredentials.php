<?php

namespace Laragear\WebAuthn\Attestation\Creator\Pipes;

use Closure;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreation;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\Models\WebAuthnCredential;

/**
 * @internal
 */
class MayPreventDuplicateCredentials
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
        if ($attestable->uniqueCredentials) {
            $attestable->json->set('excludeCredentials', $this->credentials($attestable->user));
        }

        return $next($attestable);
    }

    /**
     * Returns a collection of credentials ready to be inserted into the Attestable JSON.
     *
     * @param  \Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable  $user
     * @return array
     */
    protected function credentials(WebAuthnAuthenticatable $user): array
    {
        return $user
            ->webAuthnCredentials()
            ->get(['id', 'transports'])
            // @phpstan-ignore-next-line
            ->map(static function (WebAuthnCredential $credential): array {
                return array_filter([
                    'id'=> $credential->getKey(),
                    'type' => 'public-key',
                    'transports' => $credential->transports
                ]);
            })
            ->toArray();
    }
}
