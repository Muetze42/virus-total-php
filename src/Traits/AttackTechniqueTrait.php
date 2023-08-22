<?php

namespace NormanHuth\VirusTotal\Traits;

use JetBrains\PhpStorm\ExpectedValues;

trait AttackTechniqueTrait
{
    /**
     * Get an attack technique object.
     *
     * @link  https://developers.virustotal.com/reference/attack_techniqueid
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
    public function getAnAttackTechniqueObject(string $id): array
    {
        $response = $this->client->get('attack_techniques/' . $id);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get objects related to an attack technique.
     *
     * @link https://developers.virustotal.com/reference/attack_techniqueidrelationship
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
    public function getObjectsRelatedToAnAttackTechnique(
        string $id,
        #[ExpectedValues(values: [
            'attack_tactics',
            'parent_technique',
            'revoking_technique',
            'subtechniques',
            'threat_actors',
        ])]
        string $relationship,
        ?string $cursor = null,
        int $limit = 40
    ): array {
        $response = $this->client->get('attack_techniques/' . $id . '/' . $relationship, [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get object descriptors related to an attack technique.
     *
     * @link https://developers.virustotal.com/reference/attack_techniquesidrelationshipsrelationship
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
    public function getObjectDescriptorsRelatedToAnAttackTechnique(
        string $id,
        #[ExpectedValues(values: [
            'attack_tactics',
            'parent_technique',
            'revoking_technique',
            'subtechniques',
            'threat_actors',
        ])]
        string $relationship,
        ?string $cursor = null,
        int $limit = 40
    ): array {
        $response = $this->client->get('attack_techniques/' . $id . '/relationships/' . $relationship, [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }
}
