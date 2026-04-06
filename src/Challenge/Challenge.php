<?php

namespace Laragear\WebAuthn\Challenge;

use DateTimeInterface;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Support\Facades\Date;
use JsonSerializable;
use Laragear\WebAuthn\ByteBuffer;

use function json_encode;

class Challenge implements JsonSerializable, Arrayable, Jsonable
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
        // If the expiration timestamp was set, use that, otherwise initialize it based on the timeout.
        if ($this->expiresAt < 1) {
            $this->expiresAt = Date::now()->getTimestamp() + $this->timeout;
        }
    }

    /**
     * Returns the expiration time as a DateTime interface instance.
     */
    public function expiresAt(): DateTimeInterface
    {
        return Date::createFromTimestamp($this->expiresAt);
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

    /**
     * Creates a new Challenge instance using a binary string and timeout.
     */
    public static function make(string $binary, int $timeout): static
    {
        return new static(new ByteBuffer($binary), $timeout);
    }

    /**
     * @inheritDoc
     *
     * @return array{data: string, timeout: int, verify: bool, properties: array, expires_at: int}
     */
    public function toArray(): array
    {
        return [
            'data' => $this->data->toHex(),
            'timeout' => $this->timeout,
            'verify' => $this->verify,
            'properties' => $this->properties,
            'expires_at' => $this->expiresAt,
        ];
    }

    /**
     * @inheritDoc
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * @inheritDoc
     */
    public function toJson($options = 0): string
    {
        return json_encode($this->jsonSerialize(), $options);
    }

    /**
     * Creates a new instance from an array.
     *
     * @param  array{data: string, timeout: int, verify: bool, properties: array, expires_at: int}  $array
     */
    public static function fromArray(array $array): static
    {
        return new static(
            ByteBuffer::fromHex($array['data']),
            $array['timeout'],
            $array['verify'],
            $array['properties'],
            $array['expires_at'],
        );
    }
}
