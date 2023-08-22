<?php

namespace NormanHuth\VirusTotal\Traits;

use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Request;
use JetBrains\PhpStorm\ExpectedValues;
use Psr\Http\Message\ResponseInterface;

trait FileTrait
{
    /**
     * Upload a file.
     *
     * @link https://developers.virustotal.com/reference/files-scan
     *
     * @param string      $file
     * @param string|null $password
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
    public function uploadAFile(string $file, ?string $password = null): array
    {
        $multipart = [];

        if ($password) {
            $multipart[] = [
                'name' => 'password',
                'contents' => $password
            ];
        }

        $multipart[] = [
            'name' => 'file',
            'filename' => basename($file),
            'contents' => file_get_contents($file),
            'headers' => [
                'Content-Type' => mime_content_type($file)
            ]
        ];

        $response = $this->client->post('files', [
            'multipart' => $multipart,
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get a URL for uploading large files.
     *
     * @link https://developers.virustotal.com/reference/files-upload-url
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: string
     * }
     */
    public function getAURLForUploadingLargeFiles(): array
    {
        $response = $this->client->get('files/upload_url');

        return $this->getFormattedResponse($response);
    }


    /**
     * Upload a large file.
     *
     * @link https://developers.virustotal.com/reference/files-upload-url
     *
     * @param string      $url
     * @param string      $file
     * @param string|null $password
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
    public function uploadALargeFile(string $url, string $file, ?string $password = null): array
    {
        if (!str_contains($url, 'virustotal.com')) {
            $url = 'https://www.virustotal.com/_ah/upload/' . ltrim($url, '/');
        }

        $multipart = [];
        if ($password) {
            $multipart[] = [
                'name' => 'password',
                'contents' => $password
            ];
        }

        $multipart[] = [
            'name' => 'file',
            'filename' => basename($file),
            'contents' => file_get_contents($file),
            'headers' => [
                'Content-Type' => mime_content_type($file)
            ]
        ];

        $response = $this->client->post($url, [
            'multipart' => $multipart,
        ]);


        return $this->getFormattedResponse($response);
    }

    /**
     * Request a file rescan (re-analyze).
     *
     * @link https://developers.virustotal.com/reference/files-analyse
     *
     * @param string $id
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array{
     *      type: 'analysis',
     *      id: string
     *  }
     * }
     */
    public function requestAFileRescan(string $id): array
    {
        $response = $this->client->post('files/' . $id . '/analyse');

        return $this->getFormattedResponse($response);
    }

    /**
     * Get a file’s download URL.
     *
     * @link https://developers.virustotal.com/reference/files-download-url
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: string
     * }
     */
    public function getAFilesDownloadURL(string $id): array
    {
        $response = $this->client->get('files/' . $id . '/download_url');

        return $this->getFormattedResponse($response);
    }

    /**
     * Download a file.
     *
     * @link https://developers.virustotal.com/reference/files-download
     *
     * @param string $id
     * @param string $target
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function downloadAFile(string $id, string $target): ResponseInterface
    {
        return $this->client->get('files/' . $id . '/download', ['sink' => $target]);
    }

    /**
     * Get comments on a file.
     *
     * @link https://developers.virustotal.com/reference/files-comments-get
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
    public function getCommentsOnAFile(string $id, ?string $cursor = null, int $limit = 40): array
    {
        $response = $this->client->get('files/' . $id . '/comments', [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Add a comment to a file.
     *
     * @link https://developers.virustotal.com/reference/ip-comments-post
     *
     * @param string $id
     * @param string $text
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function addACommentToAFile(string $id, string $text): array
    {
        $response = $this->client->post('files/' . $id . '/comments', [
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
     * Get objects related to a file.
     *
     * @link https://developers.virustotal.com/reference/files-relationships
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
    public function getObjectsRelatedToAFile(
        string $id,
        #[ExpectedValues(values: [
            'analyses',
            'behaviours',
            'bundled_files',
            'carbonblack_children',
            'carbonblack_parents',
            'ciphered_bundled_files',
            'ciphered_parents',
            'clues',
            'collections',
            'comments',
            'compressed_parents',
            'contacted_domains',
            'contacted_ips',
            'contacted_urls',
            'dropped_files',
            'email_attachments',
            'email_parents',
            'embedded_domains',
            'embedded_ips',
            'embedded_urls',
            'execution_parents',
            'graphs',
            'itw_domains',
            'itw_ips',
            'itw_urls',
            'overlay_children',
            'overlay_parents',
            'pcap_children',
            'pcap_parents',
            'pe_resource_children',
            'pe_resource_parents',
            'related_references',
            'related_threat_actors',
            'similar_files',
            'submissions',
            'screenshots',
            'votes',
        ])]
        string $relationship,
        ?string $cursor = null,
        int $limit = 40
    ): array {
        $response = $this->client->get('files/' . $id . '/' . $relationship, [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get object descriptors related to a file.
     *
     * @link https://developers.virustotal.com/reference/files-relationships-ids
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
    public function getObjectDescriptorsRelatedToAFile(
        string $id,
        #[ExpectedValues(values: [
            'analyses',
            'behaviours',
            'bundled_files',
            'carbonblack_children',
            'carbonblack_parents',
            'ciphered_bundled_files',
            'ciphered_parents',
            'clues',
            'collections',
            'comments',
            'compressed_parents',
            'contacted_domains',
            'contacted_ips',
            'contacted_urls',
            'dropped_files',
            'email_attachments',
            'email_parents',
            'embedded_domains',
            'embedded_ips',
            'embedded_urls',
            'execution_parents',
            'graphs',
            'itw_domains',
            'itw_ips',
            'itw_urls',
            'overlay_children',
            'overlay_parents',
            'pcap_children',
            'pcap_parents',
            'pe_resource_children',
            'pe_resource_parents',
            'related_references',
            'related_threat_actors',
            'similar_files',
            'submissions',
            'screenshots',
            'votes',
        ])]
        string $relationship,
        ?string $cursor = null,
        int $limit = 40
    ): array {
        $response = $this->client->get('ip_addresses/' . $id . '/relationships/' . $relationship, [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get a crowdsourced Sigma rule object.
     *
     * @link https://developers.virustotal.com/reference/get-sigma-rules
     *
     * @param string      $id
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function getACrowdsourcedSigmaRuleObject(string $id): array
    {
        $response = $this->client->get('sigma_rules/' . $id);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get a crowdsourced YARA ruleset.
     *
     * @link https://developers.virustotal.com/reference/get-yara-rulesets
     *
     * @param string      $id
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function getACrowdsourcedYARARuleset(string $id): array
    {
        $response = $this->client->get('yara_rulesets/' . $id);

        return $this->getFormattedResponse($response);
    }


    /**
     * Get votes on a file.
     *
     * @link https://developers.virustotal.com/reference/files-votes-get
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
    public function getVotesOnAFile(string $id): array
    {
        $response = $this->client->get('files/' . $id . '/vote');

        return $this->getFormattedResponse($response);
    }

    /**
     * Add a vote on a file.
     *
     * @link https://developers.virustotal.com/reference/files-votes-post
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
    public function addAVoteOnAFile(string $id, string $verdict): array
    {
        $response = $this->client->post('files/' . $id . '/votes', [
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
