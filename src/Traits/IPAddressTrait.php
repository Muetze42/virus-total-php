<?php

namespace NormanHuth\VirusTotal\Traits;

use JetBrains\PhpStorm\ExpectedValues;

trait IPAddressTrait
{
    /**
     * Get an IP address report.
     *
     * @link https://developers.virustotal.com/reference/ip-info
     *
     * @param string $ip
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array{
     *      attributes: array{
     *          as_owner: string,
     *          asn: int,
     *          continent: string,
     *          country: string,
     *          jarm: string,
     *          last_analysis_date: int,
     *          last_analysis_results: array{array-key,
     *              category: string,
     *              engine_name: string,
     *              method: string,
     *              result: string,
     *          },
     *          last_analysis_stats: array{
     *              harmless: int,
     *              malicious: int,
     *              suspicious: int,
     *              timeout: int,
     *              undetected: int,
     *          },
     *          last_modification_date: int,
     *          network: string,
     *          regional_internet_registry: string,
     *          reputation: int,
     *          total_votes: array{
     *              harmless: int,
     *              malicious: int,
     *          },
     *          tags: array{string},
     *          whois: string,
     *          whois_date: int,
     *      },
     *     id: string,
     *     links: array{self: string},
     *     type: 'ip_address',
     *  }
     * }
     */
    public function getAnIPAddressReport(string $ip): array
    {
        $response = $this->client->get('ip_addresses/' . $ip);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get comments on an IP address.
     *
     * @link https://developers.virustotal.com/reference/ip-comments-get
     *
     * @param string      $ip
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
    public function getCommentsOnAnIPAddress(string $ip, ?string $cursor = null, int $limit = 40): array
    {
        $response = $this->client->get('ip_addresses/' . $ip . '/comments', [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Add a comment to an IP address.
     *
     * @link https://developers.virustotal.com/reference/ip-comments-post
     *
     * @param string $ip
     * @param string $text
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function addACommentToAnIPAddress(string $ip, string $text): array
    {
        $response = $this->client->post('ip_addresses/' . $ip . '/comments', [
            'body' => json_encode([
                'data' => [
                    'type' => 'comment',
                    'attributes' => [
                        'text' => $text
                    ]
                ]
            ]),
            'headers' => ['content-type' => 'application/json']
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get objects related to an IP address.
     *
     * @link https://developers.virustotal.com/reference/ip-relationships
     *
     * @param string      $ip
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
    public function getObjectsRelatedToAnIPAddress(
        string $ip,
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
        $response = $this->client->get('ip_addresses/' . $ip . '/' . $relationship, [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get object descriptors related to an IP address.
     *
     * @link https://developers.virustotal.com/reference/ip-relationships-ids
     *
     * @param string      $ip
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
    public function getObjectDescriptorsRelatedToAnIPAddress(
        string $ip,
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
        $response = $this->client->get('ip_addresses/' . $ip . '/relationships/' . $relationship, [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get votes on an IP address.
     *
     * @link https://developers.virustotal.com/reference/ip-votes
     *
     * @param string $ip
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function getVotesOnAnIPAddress(string $ip): array
    {
        $response = $this->client->get('ip_addresses/' . $ip . '/vote');

        return $this->getFormattedResponse($response);
    }

    /**
     * Add a vote to an IP address.
     *
     * @link https://developers.virustotal.com/reference/ip-votes-post
     *
     * @param string $ip
     * @param string $verdict
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function addAVoteToAnIPAddress(string $ip, string $verdict): array
    {
        $response = $this->client->post('ip_addresses/' . $ip . '/votes', [
            'body' => json_encode([
                'data' => [
                    'type' => 'vote',
                    'attributes' => [
                        'verdict' => $verdict
                    ]
                ]
            ]),
            'headers' => ['content-type' => 'application/json']
        ]);

        return $this->getFormattedResponse($response);
    }
}
