<?php

namespace NormanHuth\VirusTotal\Services;

use NormanHuth\VirusTotal\Clients\VirusTotalApiClient;

class VirusTotalLaravel extends VirusTotalApiClient
{
    public function __construct()
    {
        $this->apiKey = config('virus-total.api-key');
        $this->httpErrors = config('virus-total.http_errors');
        $this->timeout = config('virus-total.timeout', 0);

        parent::__construct();
    }
}
