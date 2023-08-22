<?php

namespace NormanHuth\VirusTotal\Traits;

use JetBrains\PhpStorm\ExpectedValues;

trait FileBehaviourTrait
{
    /**
     * Get a summary of all behavior reports for a file.
     *
     * @link https://developers.virustotal.com/reference/file-all-behaviours-summary
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
    public function getASummaryOfAllBehaviorReportsForAFile(string $id): array
    {
        $response = $this->client->get('files/' . $id . '/behaviour_summary');

        return $this->getFormattedResponse($response);
    }

    /**
     * Get a summary of all MITRE ATT&CK techniques observed in a file.
     *
     * @link https://developers.virustotal.com/reference/file-all-behaviours-summary
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function getASummaryOfAllMITREATTnCKTechniquesObservedInAFile(string $id): array
    {
        $response = $this->client->get('files/' . $id . '/behaviour_summary');

        return $this->getFormattedResponse($response);
    }

    /**
     * Get all behavior reports for a file.
     *
     * @link https://developers.virustotal.com/reference/get-all-behavior-reports-for-a-file
     *
     * @param string $id
     *
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getAllBehaviorReportsForAFile(string $id): array
    {
        $response = $this->client->get('files/' . $id . '/behaviours');

        return $this->getFormattedResponse($response);
    }

    /**
     * Get a file behavior report from a sandbox.
     *
     * @link https://developers.virustotal.com/reference/get-file-behaviour-id
     *
     * @param string $sandboxId
     *
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getAFileBehaviorReportFromASandbox(string $sandboxId): array
    {
        $response = $this->client->get('file_behaviours/' . $sandboxId);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get objects related to a behaviour report.
     *
     * @link https://developers.virustotal.com/reference/file_behaviourssandbox_idrelationship
     *
     * @param string      $sandboxId
     * @param string      $relationship
     * @param string|null $cursor
     * @param int         $limit
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function getObjectsRelatedToABehaviourReport(
        string $sandboxId,
        #[ExpectedValues(values: [
            'file',
            'attack_techniques',
        ])]
        string $relationship,
        ?string $cursor = null,
        int $limit = 40
    ): array {
        $response = $this->client->get('file_behaviours/' . $sandboxId . '/' . $relationship, [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get object descriptors related to a behaviour report.
     *
     * @link https://developers.virustotal.com/reference/file_behaviourssandbox_idrelationshipsrelationship
     *
     * @param string      $sandboxId
     * @param string      $relationship
     * @param string|null $cursor
     * @param int         $limit
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function getObjectDescriptorsRelatedToABehaviourReport(
        string $sandboxId,
        #[ExpectedValues(values: [
            'file',
            'attack_techniques',
        ])]
        string $relationship,
        ?string $cursor = null,
        int $limit = 40
    ): array {
        $response = $this->client->get('file_behaviours/' . $sandboxId . '/relationships/' . $relationship, [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get a detailed HTML behaviour report.
     *
     * @link https://developers.virustotal.com/reference/get-file-behaviour-html
     *
     * @param string $sandboxId
     *
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getADetailedHTMLBehaviourReport(string $sandboxId): array
    {
        $response = $this->client->get('file_behaviours/' . $sandboxId . '/html');

        return $this->getFormattedResponse($response);
    }

    /**
     * Get the EVTX file generated during a file’s behavior analysis.
     *
     * @link https://developers.virustotal.com/reference/file-behaviour-evtx
     *
     * @param string $sandboxId
     *
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getTheEVTXFileGeneratedDuringAFilesBehaviorAnalysis(string $sandboxId): array
    {
        $response = $this->client->get('file_behaviours/' . $sandboxId . '/evtx');

        return $this->getFormattedResponse($response);
    }

    /**
     * Get the PCAP file generated during a file’s behavior analysis.
     *
     * @link https://developers.virustotal.com/reference/file_behaviours_pcap
     *
     * @param string $sandboxId
     *
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getThePCAPFileGeneratedDuringAFilesBehaviorAnalysis(string $sandboxId): array
    {
        $response = $this->client->get('file_behaviours/' . $sandboxId . '/pcap');

        return $this->getFormattedResponse($response);
    }

    /**
     * Get the memdump file generated during a file’s behavior analysis.
     *
     * @link https://developers.virustotal.com/reference/file-behaviour-memdump
     *
     * @param string $sandboxId
     *
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getTheMemdumpFileGeneratedDuringAFilesBehaviorAnalysis(string $sandboxId): array
    {
        $response = $this->client->get('file_behaviours/' . $sandboxId . '/memdump');

        return $this->getFormattedResponse($response);
    }
}
