<?php

namespace Laragear\WebAuthn;

use Illuminate\Contracts\Support\Arrayable;

/** @phpstan-consistent-constructor **/
class WebAuthnData implements Arrayable
{
    /**
     * Create a new WebAuthn Data instance.
     */
    public function __construct(readonly protected string $name, readonly protected string $displayName)
    {
        // ...
    }

    /**
     * @inheritDoc
     */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'displayName' => $this->displayName,
        ];
    }

    /**
     * Create a new WebAuthn Data instance.
     */
    public static function make(mixed $email, mixed $name): static
    {
        return new static($email, $name);
    }
}
