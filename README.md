# VirusTotal API for PHP & Laravel

This package is a wrapper for the [VirusTotal.com API V3](https://developers.virustotal.com/reference/overview).

## Installation

```
composer require norman-huth/virus-total-php
```

### Instruction

This wrapper have a method for each API endpoint with title in `camelCase` format.

The following alias methods have been defined to allow a more comfortable handling:

| Method               | Alias for                                                                                                       |
|----------------------|-----------------------------------------------------------------------------------------------------------------|
| `scanIP()`           | `getAnIPAddressReport()`                                                                                        |
| `scanDomain()`       | `getADomainReport()`                                                                                            |
| `scanFile()`         | Depending on the file size (determined automatically): <br>`uploadAFile()` or `getAURLForUploadingLargeFiles()` |
| `analyseUrlOrFile()` | `getAURLOrFileAnalysis()`                                                                                       |

The endpoints are output in the following array:

````php
return [
    'status' => 'int',       # Response HTTP status code
    'successful' => 'bool'   # True if the response HTTP status code is between 200 & 299,
    'data' => 'array|string' # The content from the API. If the response have a single `data` key, then the `data` content returns
];
````

**Notice: If you disable `http_errors`, an exception will be thrown on unsuccessful requests.**

### Usages

* [PHP Usage](USAGE-PHP.md)
* [Laravel Usage](USAGE-LARAVEL.md)
