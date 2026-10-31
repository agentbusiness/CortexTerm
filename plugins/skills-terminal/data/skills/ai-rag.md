Diagnose document ingestion, embeddings, vector indexing, filters and RAG retrieval quality.

## Inspect

Follow one known document or job through source access, extraction, chunking, embedding, index write and retrieval. Inspect bounded nonsecret metadata and relevant errors. Do not place whole private documents in the model context merely to check pipeline state.

Establish embedding model identity, vector dimension, distance metric, index/collection and filters. Changing embedding models can require re-embedding even when dimensions match. Index presence does not prove the latest document revision was ingested. A successful model answer does not prove it used retrieved evidence.

## Propose

Correct the observed stage. Reindexing, re-embedding and deleting collections are user-run changes with cost and data consequences. Preview scope and preserve the prior index or recoverable source. Do not create another vector database or local embedding runtime without checking existing services and memory capacity.

## Verify

Use a small known query and inspect retrieved source IDs, relevant passages and permissions before judging the generated answer. Separate extraction quality, retrieval relevance and answer quality. Report missing evidence and stale results precisely; do not grade retrieval from confidence or fluent prose alone.
