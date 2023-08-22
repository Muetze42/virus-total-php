<?php

namespace NormanHuth\VirusTotal\Traits;

use JetBrains\PhpStorm\ExpectedValues;

trait AnalysesTrait
{
    /**
     * Get a URL / file analysis.
     *
     * @link https://developers.virustotal.com/reference/analysis
     *
     * @param string $id
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function getAURLOrFileAnalysis(string $id): array
    {
        $response = $this->client->get('analyses/' . $id);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get objects related to an analysis.
     *
     * @link https://developers.virustotal.com/reference/analysesidrelationship-1
     *
     * @param string $id
     * @param string $relationship
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function getObjectsRelatedToAnAnalysis(
        string $id,
        #[ExpectedValues(values: [
            'item',
        ])]
        string $relationship = 'item'
    ): array {
        $response = $this->client->get('analyses/' . $id . '/' . $relationship);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get object descriptors related to an analysis.
     *
     * @link https://developers.virustotal.com/reference/analysesidrelationshipsrelationship-1
     *
     * @param string $id
     * @param string $relationship
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function getObjectDescriptorsRelatedToAnAnalysis(
        string $id,
        #[ExpectedValues(values: [
            'item',
        ])]
        string $relationship = 'item'
    ): array {
        $response = $this->client->get('analyses/' . $id . '/relationships/' . $relationship);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get a submission object.
     *
     * @link https://developers.virustotal.com/reference/get-submission
     *
     * @param string $id
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function getASubmissionObject(string $id): array
    {
        $response = $this->client->get('submission/' . $id);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get an operation object.
     *
     * @link https://developers.virustotal.com/reference/get-operations-id
     *
     * @param string $id
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function getAnOperationObject(string $id): array
    {
        $response = $this->client->get('operations/' . $id);

        return $this->getFormattedResponse($response);
    }
}
