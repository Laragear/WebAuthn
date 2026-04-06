<?php

namespace Tests\Challenge;

use Closure;
use Illuminate\Contracts\Session\Session as SessionContract;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;
use Laragear\WebAuthn\Challenge\SessionChallengeRepository;
use Mockery;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

use function now;

class SessionChallengeRepositoryTest extends TestCase
{
    public static function providesCeremony(): array
    {
        return [
            [fn () => Mockery::mock(AttestationValidation::class)],
            [fn () => Mockery::mock(AssertionValidation::class)],
        ];
    }

    #[DataProvider('providesCeremony')]
    public function test_pulls_valid_challenge_from_array(Closure $generator): void
    {
        $ceremony = $generator();

        $this->mock(SessionContract::class)
            ->expects('pull')
            ->with('_webauthn')
            ->andReturn([
                'data' => $hex = '4e2a8f1c93b0d2e5',
                'timeout' => 10,
                'verify' => true,
                'properties' => ['foo' => 'bar'],
                'expires_at' => $expires = now()->addMinutes(10)->getTimestamp(),
            ]);

        $challenge = $this->app->make(SessionChallengeRepository::class)->pull($ceremony);

        static::assertSame($hex, $challenge->data->toHex());
        static::assertSame(10, $challenge->timeout);
        static::assertSame(true, $challenge->verify);
        static::assertSame(['foo' => 'bar'], $challenge->properties);
        static::assertSame($expires, $challenge->expiresAt);
    }

    #[DataProvider('providesCeremony')]
    public function test_pulls_invalid_challenge_from_array(Closure $generator): void
    {
        $ceremony = $generator();

        $this->mock(SessionContract::class)
            ->expects('pull')
            ->with('_webauthn')
            ->andReturn([
                'data' => '4e2a8f1c93b0d2e5',
                'timeout' => 10,
                'verify' => true,
                'properties' => ['foo' => 'bar'],
                'expires_at' => now()->subSeconds(10)->getTimestamp(),
            ]);

        $challenge = $this->app->make(SessionChallengeRepository::class)->pull($ceremony);

        static::assertNull($challenge);
    }
}
