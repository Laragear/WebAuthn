<?php

namespace Laragear\WebAuthn\Attestation\Creator;

use Illuminate\Http\Request;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\JsonTransport;

class AttestationCreation
{

    public const ATTACHMENT_CROSS_PLATFORM = 'cross-platform';
    public const ATTACHMENT_PLATFORM = 'platform';

    /**
     * The underlying JSON representation of the Assertion Challenge.
     *
     * @var \Laragear\WebAuthn\JsonTransport
     */
    public JsonTransport $json;

    /**
     * Create a new Attestation Instructions instance.
     *
     * @param  \Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable  $user
     * @param  \Illuminate\Http\Request  $request
     * @param  string|null  $residentKey
     * @param  string|null  $userVerification
     * @param  bool  $uniqueCredentials
     */
    public function __construct(
        public WebAuthnAuthenticatable $user,
        public Request $request,
        public ?string $residentKey = null,
        public ?string $userVerification = null,
        public bool $uniqueCredentials = true,
    ) {
        $this->json = new JsonTransport();
    }
}
