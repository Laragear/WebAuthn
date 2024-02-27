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
        public array $properties = []
    ) {
        $this->timeout = Date::now()->addSeconds($this->timeout)->getTimestamp();
    }

    /**
     * Check if the current challenge has expired in time and no longer valid.
     */
    public function hasExpired(): bool
    {
        return Date::createFromTimestamp($this->timeout)->isPast();
    }

    /**
     * Creates a new Challenge instance using a random ByteBuffer of the given length.
     *
     * @throws \Random\RandomException
     */
    public static function random(int $length, int $timeout, bool $verify = true, array $options = []): static
    {
        return new static(ByteBuffer::makeRandom($length), $timeout, $verify, $options);
    }
}
