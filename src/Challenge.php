<?php

namespace Laragear\WebAuthn;

use Illuminate\Support\Facades\Date;

class Challenge
{
    /**
     * Create a new Challenge instance.
     */
    final public function __construct(
        public ByteBuffer $data,
        public int $timeout,
        public bool $verify = true,
        public array $properties = [],
        public int $expiresAt = 0,
    ) {
        $this->expiresAt = Date::now()->getTimestamp() + $this->timeout;
    }

    /**
     * Check if the current challenge has not expired.
     */
    public function isValid(): bool
    {
        return Date::now()->getTimestamp() <= $this->expiresAt;
    }

    /**
     * Check if the current challenge has expired in time and no longer valid.
     */
    public function isExpired(): bool
    {
        return ! $this->isValid();
    }

    /**
     * Creates a new Challenge instance using a random ByteBuffer of the given length.
     */
    public static function random(int $length, int $timeout, bool $verify = true, array $options = []): static
    {
        return new static(ByteBuffer::makeRandom($length), $timeout, $verify, $options);
    }
}
