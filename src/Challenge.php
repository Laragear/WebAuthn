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
        public int $milliseconds = 0,
    ) {
        $this->milliseconds = $this->timeout * 1000;
        $this->timeout = Date::now()->addSeconds($this->timeout)->getTimestamp();
    }

    /**
     * Check if the current challenge has not expired.
     */
    public function isValid(): bool
    {
        return Date::createFromTimestamp($this->timeout)->isFuture();
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
     *
     * @throws \Random\RandomException
     */
    public static function random(int $length, int $timeout, bool $verify = true, array $options = []): static
    {
        return new static(ByteBuffer::makeRandom($length), $timeout, $verify, $options);
    }
}
