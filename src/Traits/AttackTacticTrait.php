<?php

namespace NormanHuth\VirusTotal\Traits;

use JetBrains\PhpStorm\ExpectedValues;

trait AttackTacticTrait
{
    /**
     * Get an attack tactic object.
     *
     * @link https://developers.virustotal.com/reference/attack_tacticsid
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
    public function getAnAttackTacticObject(string $id): array
    {
        $response = $this->client->get('attack_tactics/' . $id);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get objects related to an attack tactic.
     *
     * @link https://developers.virustotal.com/reference/attack_tacticsidrelationship
     *
     * @param string      $id
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
    public function getObjectsRelatedToAnAttackTactic(
        string $id,
        #[ExpectedValues(values: [
            'comments',
            'communicating_files',
            'downloaded_files',
            'graphs',
            'historical_ssl_certificates',
            'historical_whois',
            'related_comments',
            'related_references',
            'related_threat_actors',
            'referrer_files',
            'resolutions',
            'urls',
        ])]
        string $relationship,
        ?string $cursor = null,
        int $limit = 40
    ): array {
        $response = $this->client->get('attack_tactics/' . $id . '/' . $relationship, [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get object descriptors related to an attack tactic.
     *
     * @link https://developers.virustotal.com/reference/attack_tacticsidrelationshipsrelationship
     *
     * @param string      $id
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
    public function getObjectDescriptorsRelatedToAnAttackTactic(
        string $id,
        #[ExpectedValues(values: [
            'comments',
            'communicating_files',
            'downloaded_files',
            'graphs',
            'historical_ssl_certificates',
            'historical_whois',
            'related_comments',
            'related_references',
            'related_threat_actors',
            'referrer_files',
            'resolutions',
            'urls',
        ])]
        string $relationship,
        ?string $cursor = null,
        int $limit = 40
    ): array {
        $response = $this->client->get('attack_tactics/' . $id . '/relationships/' . $relationship, [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }
}
