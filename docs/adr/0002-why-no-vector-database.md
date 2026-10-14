# 0002. Why no vector database

## Context

The knowledge base stores glossary notes, schema docs, and other uploaded text, then appends a few matching snippets to the model prompt. Retrieval has to work in the demo with no extra service, no model download, and no native library. The warehouse database is a separate file and is never opened for this index.

## Decision

Chunks and vectors live in a SQLite file under `data/knowledge/`. Search is cosine similarity in NumPy. The default embedder hashes tokens on this machine, so the index does not need an API key. OpenRouter embeddings are optional.

That is enough at demo scale: files are capped at 2 MB, chunks are capped, and a question asks for a handful of snippets. Chroma and FAISS are not used.

`src/knowledge/store.py` is the seam. Another engine would replace that store, not the routing map, the SQL allowlist, or the warehouse connection.

## Consequences

- The demo installs from `requirements.txt` and runs with no vector service beside it.
- Search quality is the hashed-token embedder, or whatever OpenRouter model is configured. It is not a tuned retrieval stack.
- Swapping the engine later means re-indexing. Vectors from two embedders are not mixed: search filters on `embedding_id`.
- The knowledge base cannot widen the table allowlist. Notes are text in the prompt, after routing has already picked one permitted table.

## Alternatives rejected

- **Chroma or FAISS.** Either one pulls in a native dependency or a separate process for a corpus this demo does not have. SQLite plus NumPy already stores the vectors and ranks them. The cost of those libraries shows up on day one; the benefit does not, at this size.
- **A hosted vector database.** That adds an account, a network hop, and a second place where uploaded notes live. The demo is meant to run from the repo.
- **Putting the vectors in the warehouse file.** Uploaded text would then sit next to revenue and DAU, on the connection the question path opens. The index stays in its own SQLite file so a note cannot be queried as a warehouse table.
