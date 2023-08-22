<?php

namespace NormanHuth\VirusTotal\Traits;

trait PopularThreatCategoryTrait
{
    /**
     * Get a list of popular threat categories.
     *
     * @link https://developers.virustotal.com/reference/popular_threat_categories
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function getAListOfPopularThreatCategories(): array
    {
        $response = $this->client->get('popular_threat_categories');

        return $this->getFormattedResponse($response);
    }
}
