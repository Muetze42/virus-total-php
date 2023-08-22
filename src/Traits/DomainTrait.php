<?php

namespace NormanHuth\VirusTotal\Traits;

use JetBrains\PhpStorm\ExpectedValues;

trait DomainTrait
{
    /**
     * Get a domain report.
     *
     * @link https://developers.virustotal.com/reference/domain-info
     *
     * @param string $domain
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array{
     *      attributes: array{
     *          categories: array{array-key, string},
     *          creation_date: int,
     *          favicon: array{array-key, string},
     *          jarm: string,
     *          last_analysis_date: int,
     *          last_analysis_results: array{array-key, array{
     *              category: string,
     *              engine_name: string,
     *              method: string,
     *              result: string
     *          }},
     *          last_analysis_stats: array{
     *              harmless: int,
     *              malicious: int,
     *              suspicious: int,
     *              timeout: int,
     *              undetected: int
     *          },
     *          last_dns_records: array{array-key, array{
     *              expire: int,
     *              flag: int,
     *              minimum: int,
     *              priority: int,
     *              refresh: int,
     *              rname: int,
     *              retry: int,
     *              serial: int,
     *              tag: string,
     *              ttl: int,
     *              type: string,
     *              value: string
     *          }},
     *          last_dns_records_date: int,
     *          last_https_certificate: array,
     *          last_https_certificate_date: int,
     *          last_modification_date: int,
     *          last_update_date: int,
     *          popularity_ranks: array{array-key, array{
     *              rank: int,
     *              timestamp: int
     *          }},
     *          registrar: string,
     *          reputation: int,
     *          tags: array{string},
     *          total_votes: array{
     *              harmless: int,
     *              malicious: int,
     *          },
     *          whois: string,
     *          whois_date: int,
     *      },
     *     id: string,
     *     links: array{self: string},
     *     type: 'domain',
     *  }
     * }
     */
    public function getADomainReport(string $domain): array
    {
        if (!str_contains($domain, '//')) {
            $domain = 'https://' . $domain;
        }

        $response = $this->client->get('domains/' . parse_url($domain, PHP_URL_HOST));

        return $this->getFormattedResponse($response);
    }

    /**
     * Get comments on a domain.
     *
     * @link https://developers.virustotal.com/reference/domains-comments-get
     *
     * @param string      $domain
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
    public function getCommentsOnADomain(string $domain, ?string $cursor = null, int $limit = 40): array
    {
        $response = $this->client->get('domains/' . $domain . '/comments', [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Add a comment to a domain.
     *
     * @link https://developers.virustotal.com/reference/domains-comments-post
     *
     * @param string $domain
     * @param string $text
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function addACommentToADomain(string $domain, string $text): array
    {
        $response = $this->client->post('domains/' . $domain . '/comments', [
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
     * Get objects related to a domain.
     *
     * @link https://developers.virustotal.com/reference/domains-relationships
     *
     * @param string      $domain
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
    public function getObjectsRelatedToADomain(
        string $domain,
        #[ExpectedValues(values: [
            'caa_records',
            'cname_records',
            'comments',
            'communicating_files',
            'downloaded_files',
            'graphs',
            'historical_ssl_certificates',
            'historical_whois',
            'immediate_parent',
            'mx_records',
            'ns_records',
            'parent',
            'referrer_files',
            'related_comments',
            'related_references',
            'related_threat_actors',
            'resolutions',
            'soa_records',
            'siblings',
            'subdomains',
            'urls',
            'user_votes',
        ])]
        string $relationship,
        ?string $cursor = null,
        int $limit = 40
    ): array {
        $response = $this->client->get('domains/' . $domain . '/' . $relationship, [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get object descriptors related to a domain
     *
     * @link https://developers.virustotal.com/reference/domains-relationships-ids
     *
     * @param string      $domain
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
    public function getObjectDescriptorsRelatedToADomain(
        string $domain,
        #[ExpectedValues(values: [
            'caa_records',
            'cname_records',
            'comments',
            'communicating_files',
            'downloaded_files',
            'graphs',
            'historical_ssl_certificates',
            'historical_whois',
            'immediate_parent',
            'mx_records',
            'ns_records',
            'parent',
            'referrer_files',
            'related_comments',
            'related_references',
            'related_threat_actors',
            'resolutions',
            'soa_records',
            'siblings',
            'subdomains',
            'urls',
            'user_votes',
        ])]
        string $relationship,
        ?string $cursor = null,
        int $limit = 40
    ): array {
        $response = $this->client->get('domains/' . $domain . '/relationships/' . $relationship, [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get a DNS resolution object.
     *
     * @link https://developers.virustotal.com/reference/get-resolution-by-id
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
    public function getADNSResolutionObject(string $id): array
    {
        $response = $this->client->get('resolutions/' . $id);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get votes on a domain.
     *
     * @link https://developers.virustotal.com/reference/domains-votes-get
     *
     * @param string $domain
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function getVotesOnADomain(string $domain): array
    {
        $response = $this->client->get('domains/' . $domain . '/vote');

        return $this->getFormattedResponse($response);
    }

    /**
     * Add a vote to a domain.
     *
     * @link https://developers.virustotal.com/reference/domain-votes-post
     *
     * @param string $domain
     * @param string $verdict
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function addAVoteToADomain(string $domain, string $verdict): array
    {
        $response = $this->client->post('domains/' . $domain . '/votes', [
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
