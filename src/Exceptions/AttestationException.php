<?php

namespace Laragear\WebAuthn\Exceptions;

use Illuminate\Validation\ValidationException;
use Laragear\WebAuthn\Contracts\WebAuthnException;

class AttestationException extends ValidationException implements WebAuthnException
{
    /**
     * Create a new Attestation Exception with the error message.
     */
    public static function make(string $message): static
    {
        return static::withMessages(['attestation' => "Attestation Error: $message"]);
    }
}
