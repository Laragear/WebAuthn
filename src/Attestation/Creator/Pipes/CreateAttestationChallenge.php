<?php

namespace Laragear\WebAuthn\Attestation\Creator\Pipes;

use Closure;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreation;
use Laragear\WebAuthn\ChallengeRepository;

/**
 * @internal
 */
class CreateAttestationChallenge
{
    /**
     * Create a new pipe instance.
     */
    public function __construct(protected ChallengeRepository $challenge)
    {
        //
    }

    /**
     * Handle the Attestation creation.
     */
    public function handle(AttestationCreation $attestable, Closure $next): mixed
    {
        $challenge = $this->challenge->store($attestable->userVerification, [
            'user_uuid' => $attestable->json->get('user.id'),
            'user_handle' => $attestable->json->get('user.name'),
        ]);

        $attestable->json->set('timeout', $challenge->timeout * 1000);
        $attestable->json->set('challenge', $challenge->data);

        return $next($attestable);
    }
}
