<?php

namespace Tests;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Laragear\WebAuthn\WebAuthnServiceProvider;
use Orchestra\Testbench\TestCase as BaseTestCase;
use function class_exists;
use function function_exists;
use function realpath;

abstract class TestCase extends BaseTestCase
{
    use RefreshDatabase;

    protected function defineDatabaseMigrations(): void
    {
        if (!class_exists('Orchestra\Testbench\Attributes\WithMigration')) {
            $this->loadLaravelMigrations();
        }

        $this->loadMigrationsFrom(
            function_exists('Orchestra\Testbench\package_path')
                ? \Orchestra\Testbench\package_path('database/migrations')
                : realpath(__DIR__ . '/../database/migrations')
        );
    }

    protected function getPackageProviders($app): array
    {
        return [WebAuthnServiceProvider::class];
    }
}
