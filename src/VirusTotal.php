<?php

namespace NormanHuth\VirusTotal;

use NormanHuth\VirusTotal\Clients\VirusTotalApiClient;

class VirusTotal extends VirusTotalApiClient
{
    public function __construct(string $apiKey, bool $httpErrors = false, int $timeout = 30)
    {
        $this->apiKey = $apiKey;
        $this->httpErrors = $httpErrors;
        $this->timeout = $timeout;

        parent::__construct();
    }
}
