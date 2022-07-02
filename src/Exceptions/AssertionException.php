<?php

namespace Laragear\WebAuthn\Exceptions;

use Illuminate\Validation\ValidationException;
use Laragear\WebAuthn\Contracts\WebAuthnException;

class AssertionException extends ValidationException implements WebAuthnException
{
    /**
     * Create a new Assertion Exception with the error message.
     *
     * @param  string  $message
     * @return \Laragear\WebAuthn\Exceptions\AssertionException
     */
    public static function make(string $message): self
    {
        return static::withMessages(['assertion' => "Assertion Error: $message"]);
    }
}
