<?php

namespace Laragear\WebAuthn\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Console\Kernel as ConsoleContract;
use Laragear\WebAuthn\WebAuthnServiceProvider;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * @internal
 */
#[AsCommand('webauthn:install')]
class WebAuthnInstallCommand extends Command
{
    /**
     * The console command name.
     *
     * @var string
     */
    protected $signature = 'webauthn:install
                            {--force : Install the files even if these exist }';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Publish this package files in one command.';

    /**
     * Indicates whether the command should be shown in the Artisan command list.
     *
     * @var bool
     */
    protected $hidden = true;

    /**
     * Execute the console command.
     */
    public function handle(ConsoleContract $console): void
    {
        $console->call('vendor:publish', [
            '--provider' => WebAuthnServiceProvider::class,
            '--force' => $this->option('force'),
            '--tag' => ['migrations', 'config', 'controllers'],
        ]);
    }
}
