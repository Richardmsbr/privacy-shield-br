<?php

declare(strict_types=1);

namespace PrivacyShield\Laravel;

use Illuminate\Support\ServiceProvider;
use PrivacyShield\Privacy;

class PrivacyShieldServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../../config/privacy-shield.php',
            'privacy-shield'
        );

        $this->app->singleton('privacy-shield', function ($app) {
            return new Privacy(config('privacy-shield', []));
        });

        $this->app->alias('privacy-shield', Privacy::class);
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../../config/privacy-shield.php' => config_path('privacy-shield.php'),
            ], 'privacy-shield-config');
        }

        // Registra middleware
        $this->app['router']->aliasMiddleware('privacy.mask', Middleware\MaskSensitiveData::class);
        $this->app['router']->aliasMiddleware('privacy.log', Middleware\SanitizeLogging::class);
    }

    /**
     * Get the services provided by the provider.
     */
    public function provides(): array
    {
        return ['privacy-shield', Privacy::class];
    }
}
