<?php

namespace NormanHuth\VirusTotal\Traits;

use JetBrains\PhpStorm\ExpectedValues;

trait CommentTrait
{
    /**
     * Get latest comments.
     *
     * @link https://developers.virustotal.com/reference/get-comments
     *
     * @param string|null $filter
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
    public function getLatestComments(string $filter = null, ?string $cursor = null, int $limit = 40): array
    {
        $response = $this->client->get('comments', [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get a comment object.
     *
     * @link https://developers.virustotal.com/reference/get-comment
     *
     * @param string      $id
     * @param string|null $relationships
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function getACommentObject(string $id, ?string $relationships = null): array
    {
        $response = $this->client->get('comments/' . $id, [
            'query' => array_filter([
                'relationships' => $relationships
            ])
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Update a comment.
     *
     * @link https://developers.virustotal.com/reference/comment-id-patch
     *
     * @param string             $id
     * @param array|string|mixed $data
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     */
    public function updateAComment(string $id, mixed $data): array
    {
        if (!is_string($data)) {
            $data = json_encode($data);
        }

        $response = $this->client->patch('comments/' . $id, ['body' => $data]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Delete a comment.
     *
     * @link https://developers.virustotal.com/reference/comment-id-delete
     *
     * @param string $id
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: string
     * }
     */
    public function deleteAComment(string $id): array
    {
        $response = $this->client->delete('comments/' . $id);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get objects related to a comment.
     *
     * @link https://developers.virustotal.com/reference/comments-relationships
     *
     * @param string $id
     * @param string $relationship
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @return array
     */
    public function getObjectsRelatedToAComment(
        string $id,
        #[ExpectedValues(values: [
            'author',
            'item',
        ])]
        string $relationship
    ): array {
        $response = $this->client->get('comments/' . $id . '/' . $relationship);

        return $this->getFormattedResponse($response);
    }

    /**
     * Get object descriptors related to a comment.
     *
     * @link https://developers.virustotal.com/reference/comments-relationships-ids
     *
     * @param string      $id
     * @param string      $relationship
     * @param string|null $cursor
     * @param int         $limit
     *
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getObjectDescriptorsRelatedToAComment(
        string $id,
        #[ExpectedValues(values: [
            'author',
            'item',
        ])]
        string $relationship,
        ?string $cursor = null,
        int $limit = 40
    ): array {
        $response = $this->client->get('comments/' . $id . '/relationships/' . $relationship, [
            'query' => array_filter([
                'limit' => $limit,
                'cursor' => $cursor,
            ])
        ]);

        return $this->getFormattedResponse($response);
    }

    /**
     * Add a vote to a comment.
     *
     * @link https://developers.virustotal.com/reference/vote-comment
     *
     * @param string             $id
     * @param string|array|mixed $data
     *
     * @return array{
     *     status: int,
     *     successful: bool,
     *     data: array
     * }
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function addAVoteToAComment(string $id, mixed $data): array
    {
        if (!is_string($data)) {
            $data = json_encode($data);
        }

        $response = $this->client->post('comments/' . $id . '/vote', [
            'form_params' => [
                'data' => $data,
            ],
            'headers' => ['content-type' => 'application/json']
        ]);

        return $this->getFormattedResponse($response);
    }
}
