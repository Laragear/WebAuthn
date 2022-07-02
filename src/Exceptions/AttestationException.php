<?php

namespace Laragear\WebAuthn\Exceptions;

use Illuminate\Validation\ValidationException;
use Laragear\WebAuthn\Contracts\WebAuthnException;

class AttestationException extends ValidationException implements WebAuthnException
{
    /**
     * Create a new Attestation Exception with the error message.
     *
     * @param  string  $message
     * @return \Laragear\WebAuthn\Exceptions\AttestationException
     */
    public static function make(string $message): self
    {
        return static::withMessages(['attestation' => "Attestation Error: $message"]);
    }
}
