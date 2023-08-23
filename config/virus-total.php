<?php

return [

    /*
    |--------------------------------------------------------------------------
    | VirusTotal API Key
    |--------------------------------------------------------------------------
    |
    | Your personal VirusTotal API key to be used for API requests.
    | Get the key from the VirusTotal Website:
    | https://www.virustotal.com/gui/user/<username>/apikey
    |
    */

   'api-key' => env('VIRUS_TOTAL_API_KEY', ''),

    /*
    |--------------------------------------------------------------------------
    | Client Timeout
    |--------------------------------------------------------------------------
    |
    | Float describing the total timeout of the request in seconds.
    | Use 0 to wait indefinitely (the default behavior).
    |
    */

   'timeout' => 30,


    /*
    |--------------------------------------------------------------------------
    | Client HTTP Errors
    |--------------------------------------------------------------------------
    |
    | Set to false to disable throwing exceptions on an HTTP protocol errors
    | (i.e., 4xx and 5xx responses). Exceptions are thrown by default when
    | HTTP protocol errors are encountered.
    |
    */

   'http_errors' => false,

];
