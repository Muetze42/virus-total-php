<?php

namespace NormanHuth\VirusTotal\Clients;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Response;
use NormanHuth\VirusTotal\Exceptions\VirusTotalApiException;
use NormanHuth\VirusTotal\Traits\AnalysesTrait;
use NormanHuth\VirusTotal\Traits\AttackTacticTrait;
use NormanHuth\VirusTotal\Traits\AttackTechniqueTrait;
use NormanHuth\VirusTotal\Traits\CommentTrait;
use NormanHuth\VirusTotal\Traits\DomainTrait;
use NormanHuth\VirusTotal\Traits\FileBehaviourTrait;
use NormanHuth\VirusTotal\Traits\FileTrait;
use NormanHuth\VirusTotal\Traits\IPAddressTrait;
use NormanHuth\VirusTotal\Traits\PopularThreatCategoryTrait;
use NormanHuth\VirusTotal\Traits\URLTrait;
use Psr\Http\Message\ResponseInterface;

class VirusTotalApiClient
{
    use AnalysesTrait;
    use AttackTacticTrait;
    use AttackTechniqueTrait;
    use CommentTrait;
    use DomainTrait;
    use FileBehaviourTrait;
    use FileTrait;
    use IPAddressTrait;
    use PopularThreatCategoryTrait;
    use URLTrait;

    /**
     * The Client instance.
     *
     * @var \GuzzleHttp\Client
     */
    protected Client $client;

    /**
     * @var string
     */
    protected string $apiKey;

    /**
     * @var int
     */
    protected int $timeout = 30;

    /**
     * @var bool
     */
    protected bool $httpErrors = false;

    /**
     * @throws \NormanHuth\VirusTotal\Exceptions\VirusTotalApiException
     */
    protected function __construct()
    {
        if (empty($this->apiKey)) {
            throw new VirusTotalApiException('Missing VirusTotal API Key.');
        }

        $this->client = new Client([
            'base_uri' => 'https://www.virustotal.com/api/v3/',
            'timeout'  => $this->timeout,
            'http_errors' => $this->httpErrors,
            'headers' => [
                'x-apikey' => $this->apiKey,
                'accept' => 'application/json'
            ]
        ]);
    }

    /**
     * @param \GuzzleHttp\Psr7\Response|\Psr\Http\Message\ResponseInterface $response
     *
     * @return array
     */
    protected function getFormattedResponse(Response|ResponseInterface $response): array
    {
        $content = json_decode($response->getBody(), true);
        $statusCode = $response->getStatusCode();

        return [
            'status' => $statusCode,
            'successful' => $statusCode >= 200 && $statusCode < 300,
            'data' => isset($content['data']) && count($content) == 1 ? $content['data'] : $content
        ];
    }

    /**
     * Gets file size in MB.
     *
     * @param $file
     *
     * @return float
     */
    public static function getFilesizeMB($file): float
    {
        return (float)sprintf('%4.2f', filesize($file) / 1048576);
    }

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
    public function scanIP(string $ip): array
    {
        return $this->getAnIPAddressReport($ip);
    }

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
    public function scanDomain(string $domain): array
    {
        return $this->getADomainReport($domain);
    }

    /**
     * Upload a (large) file.
     *
     * @link https://developers.virustotal.com/reference/files-scan
     * @link https://developers.virustotal.com/reference/files-upload-url
     *
     * @param string      $file
     * @param string|null $password
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \NormanHuth\VirusTotal\Exceptions\VirusTotalApiException
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
    public function scanFile(string $file, ?string $password = null): array
    {
        $filesize = self::getFilesizeMB($file);

        if ($filesize < 32) {
            return $this->uploadAFile($file, $password);
        }

        $url = $this->getAURLForUploadingLargeFiles();
        if (!$url['successful'] || empty($url['data']) || !is_string($url['data'])) {
            throw new VirusTotalApiException('Invalid Request. Stacktrace: ' . print_r($url, true));
        }

        return $this->uploadALargeFile($url['data'], $file, $password);
    }

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
    public function analyseUrlOrFile(string $id): array
    {
        return $this->getAURLOrFileAnalysis($id);
    }
}
