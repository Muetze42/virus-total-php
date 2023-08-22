<?php

namespace NormanHuth\VirusTotal\Providers;

use Illuminate\Support\ServiceProvider as Provider;

class ServiceProvider extends Provider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../../config/virus-total.php',
            'virus-total'
        );
    }

    /**
     * Bootstrap any package services.
     */
    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../../config/virus-total.php' => config_path('virus-total.php'),
        ]);
    }
}
