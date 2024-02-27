<?php

namespace Laragear\WebAuthn\Exceptions;

use Illuminate\Validation\ValidationException;
use Laragear\WebAuthn\Contracts\WebAuthnException;

class AssertionException extends ValidationException implements WebAuthnException
{
    /**
     * Create a new Assertion Exception with the error message.
     */
    public static function make(string $message): static
    {
        return static::withMessages(['assertion' => "Assertion Error: $message"]);
    }
}
