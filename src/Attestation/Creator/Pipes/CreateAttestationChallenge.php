<?php

namespace Laragear\WebAuthn\Attestation\Creator\Pipes;

use Closure;
use Illuminate\Contracts\Config\Repository as ConfigContract;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreation;
use Laragear\WebAuthn\Challenge\Challenge;
use Laragear\WebAuthn\Contracts\WebAuthnChallengeRepository as ChallengeRepositoryContract;
use Laragear\WebAuthn\Enums\UserVerification;

/**
 * @internal
 */
class CreateAttestationChallenge
{
    /**
     * Create a new pipe instance.
     */
    public function __construct(protected ChallengeRepositoryContract $challenge, protected ConfigContract $config)
    {
        //
    }

    /**
     * Handle the Attestation creation.
     */
    public function handle(AttestationCreation $attestable, Closure $next): mixed
    {
        $attestable->challenge ??= Challenge::random(
            $this->config->get('webauthn.challenge.bytes'),
            $this->config->get('webauthn.challenge.timeout')
        );

        $attestable->challenge->verify = $attestable->userVerification === UserVerification::Required;
        $attestable->challenge->properties = [
            'user_uuid' => $attestable->json->get('user.id'),
            'user_handle' => $attestable->json->get('user.name'),
        ];

        $attestable->json->set('timeout', $attestable->challenge->timeout * 1000);
        $attestable->json->set('challenge', $attestable->challenge->data);

        $this->challenge->store($attestable, $attestable->challenge);

        return $next($attestable);
    }
}
