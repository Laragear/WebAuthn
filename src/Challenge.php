<?php

namespace Laragear\WebAuthn;

use Illuminate\Support\Facades\Date;
use Illuminate\Support\InteractsWithTime;

class Challenge
{
    use InteractsWithTime;

    /**
     * Create a new Challenge instance.
     *
     * @param  \Laragear\WebAuthn\ByteBuffer  $data
     * @param  int  $timeout
     * @param  bool  $verify
     * @param  array  $properties
     */
    public function __construct(
        public ByteBuffer $data,
        public int $timeout,
        public bool $verify = true,
        public array $properties = []
    ) {
        $this->timeout = Date::now()->addSeconds($this->timeout)->getTimestamp();
    }

    /**
     * Check if the current challenge has expired in time and no longer valid.
     *
     * @return bool
     */
    public function hasExpired(): bool
    {
        return Date::createFromTimestamp($this->timeout)->isPast();
    }

    /**
     * Creates a new Challenge instance using a random ByteBuffer of the given length.
     *
     * @param  int<1, max>  $length
     * @param  int  $timeout
     * @param  bool  $verify
     * @param  array  $options
     * @return self
     */
    public static function random(int $length, int $timeout, bool $verify = true, array $options = []): self
    {
        return new self(ByteBuffer::makeRandom($length), $timeout, $verify, $options);
    }
}
