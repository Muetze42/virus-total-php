<?php

namespace NormanHuth\VirusTotal\Traits;

use JetBrains\PhpStorm\ExpectedValues;

trait URLTrait
{
    /**
     * Scan URL.
     *
     * @link https://developers.virustotal.com/reference/scan-url
     *
     * @param string $url
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array{
     *      type: 'analysis',
     *      id: string,
     *      links: array{self: string},
     *  }
     * }
     */
    public function scanURL(string $url): array
    {
        $response = $this->client->post('urls', [
            'query' => [
                'url' => $url
            ]
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get a URL analysis report.
     *
     * @link https://developers.virustotal.com/reference/url-info
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
    public function getAURLAnalysisReport(string $id): array
    {
        $response = $this->client->get('urls/' . $id);

        return $this->getFormattedResponse($response);
    }

    /**
     * Request a URL rescan (re-analyze).
     *
     * @link https://developers.virustotal.com/reference/urls-analyse
     *
     * @param string $id
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array{
     *          id: string,
     *          type: 'analysis',
     *      }
     * }
     */
    public function requestAURLRescan(string $id): array
    {
        $response = $this->client->post('urls/' . $id . '/analyse');

        return $this->getFormattedResponse($response);
    }

    /**
     * Get comments on a URL.
     *
     * @link https://developers.virustotal.com/reference/urls-comments-get
     *
     * @param string      $id
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
    public function getCommentsOnAURL(string $id, ?string $cursor = null, int $limit = 40): array
    {
        $response = $this->client->get('urls/' . $id . '/comments', [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Add a comment on a URL.
     *
     * @link https://developers.virustotal.com/reference/urls-comments-post
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
    public function addACommentOnAURL(string $ip, string $text): array
    {
        $response = $this->client->post('urls/' . $ip . '/comments', [
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
     * Get objects related to a URL.
     *
     * @link https://developers.virustotal.com/reference/urls-relationships
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
    public function getObjectsRelatedToAURL(
        string $id,
        #[ExpectedValues(values: [
            'analyses',
            'comments',
            'communicating_files',
            'contacted_domains',
            'contacted_ips',
            'downloaded_files',
            'graphs',
            'last_serving_ip_address',
            'network_location',
            'referrer_files',
            'referrer_urls',
            'redirecting_urls',
            'redirects_to',
            'related_comments',
            'related_references',
            'related_threat_actors',
            'submissions',
        ])]
        string $relationship,
        ?string $cursor = null,
        int $limit = 40
    ): array {
        $response = $this->client->get('urls/' . $id . '/' . $relationship, [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get object descriptors related to a URL.
     *
     * @link https://developers.virustotal.com/reference/ip-relationships-ids
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
    public function getObjectDescriptorsRelatedToAURL(
        string $id,
        #[ExpectedValues(values: [
            'analyses',
            'comments',
            'communicating_files',
            'contacted_domains',
            'contacted_ips',
            'downloaded_files',
            'graphs',
            'last_serving_ip_address',
            'network_location',
            'referrer_files',
            'referrer_urls',
            'redirecting_urls',
            'redirects_to',
            'related_comments',
            'related_references',
            'related_threat_actors',
            'submissions',
        ])]
        string $relationship,
        ?string $cursor = null,
        int $limit = 40
    ): array {
        $response = $this->client->get('urls/' . $id . '/relationships/' . $relationship, [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get votes on a URL.
     *
     * @link https://developers.virustotal.com/reference/urls-votes-get
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
    public function getVotesOnAURL(string $id): array
    {
        $response = $this->client->get('urls/' . $id . '/vote');

        return $this->getFormattedResponse($response);
    }

    /**
     * Add a vote on a URL.
     *
     * @link https://developers.virustotal.com/reference/urls-votes-post
     *
     * @param string $id
     * @param string $verdict
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function addAVoteOnAURL(string $id, string $verdict): array
    {
        $response = $this->client->post('urls/' . $id . '/votes', [
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
