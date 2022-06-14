<?php

namespace Laragear\WebAuthn;

use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Arr;
use JsonSerializable;
use Stringable;
use function json_encode;

/**
 * This class will help us build JSON responses by setting and checking for its keys.
 *
 * @internal
 */
class JsonTransport implements Arrayable, Jsonable, JsonSerializable, Stringable, Responsable
{
    /**
     * Create a new JSON transport.
     *
     * @param  array  $json
     */
    public function __construct(public array $json = [])
    {
        //
    }

    /**
     * Adds a value to the underlying JSON array.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return void
     */
    public function set(string $key, mixed $value): void
    {
        Arr::set($this->json, $key, $value);
    }

    /**
     * Retrieves a value from the underlying JSON array.
     *
     * @param  string  $key
     * @param  string|int|null  $default
     * @return string|int|null
     */
    public function get(string $key, string|int $default = null): string|int|null
    {
        return Arr::get($this->json, $key, $default);
    }

    /**
     * Convert the object to its JSON representation.
     *
     * @param  int  $options
     * @return string
     */
    public function toJson($options = 0): string
    {
        return json_encode($this->jsonSerialize(), JSON_THROW_ON_ERROR | $options);
    }

    /**
     * Get the instance as an array.
     *
     * @return array<string, int|string|\Laragear\WebAuthn\ByteBuffer>
     */
    public function toArray()
    {
        return $this->json;
    }

    /**
     * Specify data which should be serialized to JSON.
     *
     * @return array
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Returns a string representation of the object.
     *
     * @return string
     */
    public function __toString(): string
    {
        return $this->toJson();
    }

    /**
     * Create an HTTP response that represents the object.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function toResponse($request): JsonResponse
    {
        return new JsonResponse($this);
    }
}
