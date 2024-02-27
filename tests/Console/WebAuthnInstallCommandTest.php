<?php

namespace Tests\Console;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use SplFileInfo;
use Tests\TestCase;

class WebAuthnInstallCommandTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->deleteInstalledFiles();
    }

    protected function tearDown(): void
    {
        $this->deleteInstalledFiles();

        parent::tearDown();
    }

    protected function deleteInstalledFiles(): void
    {
        $migrations = Collection::make(File::files($this->app->databasePath('migrations')))
            ->filter(static function (SplFileInfo $file): bool {
                return Str::endsWith($file->getRealPath(), 'create_webauthn_credentials.php');
            })->map->getRealPath();

        File::delete($migrations->toArray());

        File::delete($this->app->configPath('webauthn.php'));
        File::delete($this->app->path('Http/Controllers/WebAuthn'));
    }

    public function test_publishes_all_files(): void
    {
        $this->artisan('webauthn:install');

        Collection::make(File::files($this->app->databasePath('migrations')))
            ->each(static function (SplFileInfo $file): void {
                static::assertTrue(Str::endsWith($file->getFilename(), 'create_webauthn_credentials.php'));
            });

        static::assertFileExists($this->app->configPath('webauthn.php'));
        static::assertFileExists($this->app->path('Http/Controllers/WebAuthn/WebAuthnLoginController.php'));
        static::assertFileExists($this->app->path('Http/Controllers/WebAuthn/WebAuthnRegisterController.php'));
    }
}
