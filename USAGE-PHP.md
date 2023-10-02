# PHP

## Usage

### Examples

#### Scan A File

```php
use NormanHuth\VirusTotal\VirusTotal;

$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$upload = $client->scanFile('/path/to-file');
$analysisId = $upload['data']['id'];

$result = $client->analyseUrlOrFile($analysisId);
```

#### Scan A URL

```php
use NormanHuth\VirusTotal\VirusTotal;

$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$url = $client->scanURL('https://huth.it/coffee');
$analysisId = $url['data']['id']

$result = $client->analyseUrlOrFile($analysisId);
```

#### Scan A Domain

```php
use NormanHuth\VirusTotal\VirusTotal;

$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$result = $client->scanDomain('/path/to-file');

return $result['data'];
```

### All Endpoints

#### IP addresses

##### Get an IP address report.

Reference: https://developers.virustotal.com/reference/ip-info

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getAnIPAddressReport(string $ip): array
```

##### Get comments on an IP address.

Reference: https://developers.virustotal.com/reference/ip-comments-get

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getCommentsOnAnIPAddress(string $ip, ?string $cursor, int $limit): array
```

##### Add a comment to an IP address.

Reference: https://developers.virustotal.com/reference/ip-comments-post

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->addACommentToAnIPAddress(string $ip, string $text): array
```

##### Get objects related to an IP address.

Reference: https://developers.virustotal.com/reference/ip-relationships

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getObjectsRelatedToAnIPAddress(string $ip, string $relationship, ?string $cursor, int $limit): array
```

##### Get object descriptors related to an IP address.

Reference: https://developers.virustotal.com/reference/ip-relationships-ids

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getObjectDescriptorsRelatedToAnIPAddress(string $ip, string $relationship, ?string $cursor, int $limit): array
```

##### Get votes on an IP address.

Reference: https://developers.virustotal.com/reference/ip-votes

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getVotesOnAnIPAddress(string $ip): array
```

##### Add a vote to an IP address.

Reference: https://developers.virustotal.com/reference/ip-votes-post

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->addAVoteToAnIPAddress(string $ip, string $verdict): array
```

#### Domains & Resolutions

##### Get a domain report.

Reference: https://developers.virustotal.com/reference/domain-info

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getADomainReport(string $domain): array
```

##### Get comments on a domain.

Reference: https://developers.virustotal.com/reference/domains-comments-get

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getCommentsOnADomain(string $domain, ?string $cursor, int $limit): array
```

##### Add a comment to a domain.

Reference: https://developers.virustotal.com/reference/domains-comments-post

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->addACommentToADomain(string $domain, string $text): array
```

##### Get objects related to a domain.

Reference: https://developers.virustotal.com/reference/domains-relationships

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getObjectsRelatedToADomain(string $domain, string $relationship, ?string $cursor, int $limit): array
```

##### Get object descriptors related to a domain

Reference: https://developers.virustotal.com/reference/domains-relationships-ids

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getObjectDescriptorsRelatedToADomain(string $domain, string $relationship, ?string $cursor, int $limit): array
```

##### Get a DNS resolution object.

Reference: https://developers.virustotal.com/reference/get-resolution-by-id

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getADNSResolutionObject(string $id): array
```

##### Get votes on a domain.

Reference: https://developers.virustotal.com/reference/domains-votes-get

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getVotesOnADomain(string $domain): array
```

##### Add a vote to a domain.

Reference: https://developers.virustotal.com/reference/domain-votes-post

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->addAVoteToADomain(string $domain, string $verdict): array
```

#### Files

##### Upload a file.

Reference: https://developers.virustotal.com/reference/files-scan

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->uploadAFile(string $file, ?string $password): array
```

##### Get a URL for uploading large files.

Reference: https://developers.virustotal.com/reference/files-upload-url

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getAURLForUploadingLargeFiles(): array
```

##### Upload a large file.

Reference: https://developers.virustotal.com/reference/files-upload-url

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->uploadALargeFile(string $url, string $file, ?string $password): array
```

##### Request a file rescan (re-analyze).

Reference: https://developers.virustotal.com/reference/files-analyse

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->requestAFileRescan(string $id): array
```

##### Get a file’s download URL.

Reference: https://developers.virustotal.com/reference/files-download-url

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getAFilesDownloadURL(string $id): array
```

##### Download a file.

Reference: https://developers.virustotal.com/reference/files-download

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->downloadAFile(string $id, string $target): \Psr\Http\Message\ResponseInterface
```

##### Get comments on a file.

Reference: https://developers.virustotal.com/reference/files-comments-get

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getCommentsOnAFile(string $id, ?string $cursor, int $limit): array
```

##### Add a comment to a file.

Reference: https://developers.virustotal.com/reference/ip-comments-post

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->addACommentToAFile(string $id, string $text): array
```

##### Get objects related to a file.

Reference: https://developers.virustotal.com/reference/files-relationships

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getObjectsRelatedToAFile(string $id, string $relationship, ?string $cursor, int $limit): array
```

##### Get object descriptors related to a file.

Reference: https://developers.virustotal.com/reference/files-relationships-ids

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getObjectDescriptorsRelatedToAFile(string $id, string $relationship, ?string $cursor, int $limit): array
```

##### Get a crowdsourced Sigma rule object.

Reference: https://developers.virustotal.com/reference/get-sigma-rules

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getACrowdsourcedSigmaRuleObject(string $id): array
```

##### Get a crowdsourced YARA ruleset.

Reference: https://developers.virustotal.com/reference/get-yara-rulesets

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getACrowdsourcedYARARuleset(string $id): array
```

##### Get votes on a file.

Reference: https://developers.virustotal.com/reference/files-votes-get

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getVotesOnAFile(string $id): array
```

##### Add a vote on a file.

Reference: https://developers.virustotal.com/reference/files-votes-post

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->addAVoteOnAFile(string $id, string $verdict): array
```

#### URLs

##### Scan URL.

Reference: https://developers.virustotal.com/reference/scan-url

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->scanURL(string $url): array
```

##### Get a URL analysis report.

Reference: https://developers.virustotal.com/reference/url-info

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getAURLAnalysisReport(string $id): array
```

##### Request a URL rescan (re-analyze).

Reference: https://developers.virustotal.com/reference/urls-analyse

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->requestAURLRescan(string $id): array
```

##### Get comments on a URL.

Reference: https://developers.virustotal.com/reference/urls-comments-get

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getCommentsOnAURL(string $id, ?string $cursor, int $limit): array
```

##### Add a comment on a URL.

Reference: https://developers.virustotal.com/reference/urls-comments-post

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->addACommentOnAURL(string $ip, string $text): array
```

##### Get objects related to a URL.

Reference: https://developers.virustotal.com/reference/urls-relationships

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getObjectsRelatedToAURL(string $id, string $relationship, ?string $cursor, int $limit): array
```

##### Get object descriptors related to a URL.

Reference: https://developers.virustotal.com/reference/ip-relationships-ids

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getObjectDescriptorsRelatedToAURL(string $id, string $relationship, ?string $cursor, int $limit): array
```

##### Get votes on a URL.

Reference: https://developers.virustotal.com/reference/urls-votes-get

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getVotesOnAURL(string $id): array
```

##### Add a vote on a URL.

Reference: https://developers.virustotal.com/reference/urls-votes-post

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->addAVoteOnAURL(string $id, string $verdict): array
```

#### Comments

##### Get latest comments.

Reference: https://developers.virustotal.com/reference/get-comments

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getLatestComments(?string $filter, ?string $cursor, int $limit): array
```

##### Get a comment object.

Reference: https://developers.virustotal.com/reference/get-comment

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getACommentObject(string $id, ?string $relationships): array
```

##### Update a comment.

Reference: https://developers.virustotal.com/reference/comment-id-patch

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->updateAComment(string $id, mixed $data): array
```

##### Delete a comment.

Reference: https://developers.virustotal.com/reference/comment-id-delete

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->deleteAComment(string $id): array
```

##### Get objects related to a comment.

Reference: https://developers.virustotal.com/reference/comments-relationships

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getObjectsRelatedToAComment(string $id, string $relationship): array
```

##### Get object descriptors related to a comment.

Reference: https://developers.virustotal.com/reference/comments-relationships-ids

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getObjectDescriptorsRelatedToAComment(string $id, string $relationship, ?string $cursor, int $limit): array
```

##### Add a vote to a comment.

Reference: https://developers.virustotal.com/reference/vote-comment

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->addAVoteToAComment(string $id, mixed $data): array
```

#### Analyses, Submissions & Operations

##### Get a URL / file analysis.

Reference: https://developers.virustotal.com/reference/analysis

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getAURLOrFileAnalysis(string $id): array
```

##### Get objects related to an analysis.

Reference: https://developers.virustotal.com/reference/analysesidrelationship-1

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getObjectsRelatedToAnAnalysis(string $id, string $relationship): array
```

##### Get object descriptors related to an analysis.

Reference: https://developers.virustotal.com/reference/analysesidrelationshipsrelationship-1

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getObjectDescriptorsRelatedToAnAnalysis(string $id, string $relationship): array
```

##### Get a submission object.

Reference: https://developers.virustotal.com/reference/get-submission

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getASubmissionObject(string $id): array
```

##### Get an operation object.

Reference: https://developers.virustotal.com/reference/get-operations-id

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getAnOperationObject(string $id): array
```

#### Attack Tactics

##### Get an attack tactic object.

Reference: https://developers.virustotal.com/reference/attack_tacticsid

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getAnAttackTacticObject(string $id): array
```

##### Get objects related to an attack tactic.

Reference: https://developers.virustotal.com/reference/attack_tacticsidrelationship

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getObjectsRelatedToAnAttackTactic(string $id, string $relationship, ?string $cursor, int $limit): array
```

##### Get object descriptors related to an attack tactic.

Reference: https://developers.virustotal.com/reference/attack_tacticsidrelationshipsrelationship

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getObjectDescriptorsRelatedToAnAttackTactic(string $id, string $relationship, ?string $cursor, int $limit): array
```

#### Attack Techniques

##### Get an attack technique object.

Reference: https://developers.virustotal.com/reference/attack_techniqueid

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getAnAttackTechniqueObject(string $id): array
```

##### Get objects related to an attack technique.

Reference: https://developers.virustotal.com/reference/attack_techniqueidrelationship

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getObjectsRelatedToAnAttackTechnique(string $id, string $relationship, ?string $cursor, int $limit): array
```

##### Get object descriptors related to an attack technique.

Reference: https://developers.virustotal.com/reference/attack_techniquesidrelationshipsrelationship

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getObjectDescriptorsRelatedToAnAttackTechnique(string $id, string $relationship, ?string $cursor, int $limit): array
```

#### Popular Threat Categories

##### Get a list of popular threat categories.

Reference: https://developers.virustotal.com/reference/popular_threat_categories

```php
$client = new VirusTotal($apiKey, $httpErrors = false, $timeout = 0);

$client->getAListOfPopularThreatCategories(): array
```
