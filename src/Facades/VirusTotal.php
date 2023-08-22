<?php

namespace NormanHuth\VirusTotal\Facades;

use Illuminate\Support\Facades\Facade;

class VirusTotal extends Facade
{
    /**
     * Get the registered name of the component.
     */
    protected static function getFacadeAccessor(): string
    {
        return \NormanHuth\VirusTotal\Services\VirusTotalLaravel::class;
    }
}
