# RAG (Retrieval Augmented Generation) Setup Guide

This guide explains how to set up and use RAG with OpenAI's vector store in the Gmail Agent.

## What is RAG?

RAG enables the agent to retrieve relevant context from a knowledge base before responding to user queries. Instead of sending all knowledge to the LLM every time (expensive and limited by context window), RAG:

1. **Searches** the vector store for the most relevant chunks based on semantic similarity
2. **Filters** results by a minimum score threshold
3. **Injects** only the top relevant chunks into the LLM context
4. **Scales** to millions of documents while keeping token costs low

## Setup Steps

### 1. Prepare Your Knowledge Base

The current setup uses `it_tickets_knowledge.txt` with IT help tickets. The text format you have is ideal for vector embeddings:

```plaintext
Ticket ID: INC-1001
Created At: 2026-03-02T08:12:00
Priority: P1
Status: Open
Summary: VPN login failure
Details: User unable to connect to corporate VPN from home network. Error code 812.
Solution: Reset VPN profile and reissued credentials.
Created By: John Smith
Email: john.smith@company.com
Role: Manager
Department: Finance
Location: Houston
```

**Tips for best results:**
- Keep tickets as natural language blocks (not raw CSV)
- Each ticket should be a self-contained chunk (~200-500 words)
- Include key metadata in the text itself (ticket ID, priority, etc.)
- Use consistent formatting across all tickets

### 2. Create and Populate the Vector Store

Run the setup script:

```bash
cd agent-ui
node setup-vector-store.js ../it_tickets_knowledge.txt
```

Or use the npm script:

```bash
npm run setup-vector-store ../it_tickets_knowledge.txt
```

The script will:
1. Create a new vector store on OpenAI
2. Upload your knowledge base file
3. Wait for indexing to complete
4. Display your `OPENAI_VECTOR_STORE_ID`

**Example output:**
```
✅ VECTOR STORE SETUP COMPLETE!
======================================================================

📋 Configuration:
   Vector Store ID: vs_abc123xyz789
   File ID: file-xyz789
   Status: completed

🔧 Next Steps:
   1. Add this to your .env file:
      OPENAI_VECTOR_STORE_ID=vs_abc123xyz789
      RAG_TOP_K=5
      RAG_MIN_SCORE=0.6
```

### 3. Configure Environment Variables

Add to your `.env` file or export:

```bash
export OPENAI_VECTOR_STORE_ID=vs_abc123xyz789
export RAG_TOP_K=5
export RAG_MIN_SCORE=0.6
```

**Configuration parameters:**

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_VECTOR_STORE_ID` | (none) | The vector store ID from setup script. RAG is disabled if not set. |
| `RAG_TOP_K` | 5 | Number of chunks to retrieve per query. Range: 1-10. Higher = more context but more tokens. |
| `RAG_MIN_SCORE` | 0.6 | Minimum similarity score (0.0-1.0). Higher = stricter filtering. Start at 0.6 and tune based on results. |

### 4. Restart the Agent

```bash
npm run dev
```

The agent will now retrieve relevant context from your knowledge base before responding to queries.

## How It Works

When a user asks a question:

1. **Query stage**: The agent sends the user's question to the vector store
2. **Retrieval stage**: OpenAI returns the top K most similar chunks with similarity scores
3. **Filtering stage**: Only chunks with `score >= RAG_MIN_SCORE` are kept
4. **Injection stage**: Retrieved chunks are formatted and added to the message history as system messages
5. **Chat stage**: The LLM processes the request with the retrieved context available

**Code flow in agent.js:**
```javascript
// 1. Retrieve from vector store
const searchRes = await openai.vectorStores.search(vectorStoreId, {
  query: requirement,
  limit: topK
});

// 2. Filter by score
const hits = searchRes?.data.filter(h => h.score >= minScore);

// 3. Format context
const ragContext = hits.map(h => `[Source: ${h.filename}]\n${h.content}`).join("\n\n");

// 4. Inject into messages
messages.push({
  role: "system",
  content: `Retrieved knowledge base context:\n\n${ragContext}`
});

// 5. Call LLM with context
const response = await openai.chat.completions.create({ messages, tools });
```

## Testing

Test with queries related to your knowledge base:

```bash
# Via CLI
node src/cli.js "What's the solution for VPN issues?"

# Via Web UI
Open http://localhost:3300 and ask:
"How do I fix email sync problems on mobile?"
```

**With DEBUG=true**, you'll see RAG logs:
```
[agent-ui][debug] RAG retrieval started { vectorStoreId: 'vs_...', topK: 5, minScore: 0.6 }
[agent-ui][debug] RAG retrieval successful { chunks: 2 }
```

## Updating the Knowledge Base

To add or update tickets:

1. Edit `it_tickets_knowledge.txt`
2. Upload the new file to your existing vector store:

```javascript
const file = await openai.files.create({
  file: fs.createReadStream("it_tickets_knowledge.txt"),
  purpose: "assistants"
});

await openai.beta.vectorStores.files.create(vectorStoreId, { 
  file_id: file.id 
});
```

Or simply re-run the setup script—it will create a new vector store with a new ID.

## Tuning Parameters

### RAG_TOP_K

- **Too low (1-2)**: May miss relevant context
- **Too high (10+)**: Wastes tokens on irrelevant chunks
- **Sweet spot**: 3-5 for focused domains, 5-8 for broad knowledge bases

### RAG_MIN_SCORE

- **Too low (< 0.5)**: Noisy results, irrelevant chunks included
- **Too high (> 0.8)**: May filter out useful results
- **Sweet spot**: 0.55-0.70 for most use cases

**How to tune:**
1. Enable `DEBUG=true`
2. Run test queries
3. Check retrieved chunks and scores in logs
4. Adjust thresholds based on what you see

## Troubleshooting

### No chunks retrieved

**Symptoms:** Debug shows `chunks: 0`

**Causes:**
- `RAG_MIN_SCORE` is too high
- Query doesn't semantically match your knowledge base
- Vector store is still processing

**Fixes:**
- Lower `RAG_MIN_SCORE` to 0.5
- Try more specific queries
- Wait a few minutes and retry

### Too many irrelevant chunks

**Symptoms:** LLM responses include unrelated ticket info

**Causes:**
- `RAG_MIN_SCORE` is too low
- `RAG_TOP_K` is too high

**Fixes:**
- Increase `RAG_MIN_SCORE` to 0.7
- Reduce `RAG_TOP_K` to 3

### Vector store search fails

**Symptoms:** "RAG retrieval failed" in debug logs

**Causes:**
- Invalid `OPENAI_VECTOR_STORE_ID`
- Vector store was deleted
- OpenAI API error

**Fixes:**
- Verify vector store ID at https://platform.openai.com/storage/vector_stores
- Re-run setup script to create a new store
- Check OpenAI API status

## Cost Considerations

**Vector store costs:**
- Storage: ~$0.10/GB/day
- Search: ~$0.0004 per search request

For 15 tickets (~6KB):
- Storage: ~$0.0006/day (negligible)
- 1000 searches/month: ~$0.40

**Token savings:**
Without RAG, sending all 15 tickets every request: ~1,500 tokens input × $0.0025/1K = ~$0.00375 per query

With RAG, sending 3 relevant tickets: ~300 tokens input × $0.0025/1K = ~$0.00075 per query

**Savings: ~80% reduction in context tokens**

As your knowledge base grows to 500+ tickets, RAG becomes essential—direct feeding would exceed context limits entirely.

## Comparison with Alternatives

### RAG vs. Direct Feeding

| Aspect | RAG | Direct Feeding |
|--------|-----|----------------|
| Setup complexity | Medium (one-time vector store setup) | Low (just paste into prompt) |
| Token cost | Low (only relevant chunks) | High (all data every time) |
| Scalability | Excellent (millions of docs) | Poor (limited by context window) |
| Relevance | High (semantic search) | Mixed (LLM sees everything) |
| Update process | Upload new files | Change code |

### RAG vs. OpenAI Assistants API

| Aspect | Manual RAG | Assistants API |
|--------|------------|----------------|
| Control | Full (you filter & format) | Automatic (OpenAI decides) |
| Integration | Works with existing chat completions | Requires thread-based architecture refactor |
| Tool calling | Compatible with your MCP tools | Requires bridging assistant tools to MCP |
| State management | Stateless (your current design) | Stateful (threads persist) |
| Flexibility | High | Lower |

For this project, manual RAG is the right choice—minimal code change and full compatibility with your existing MCP integration.

## Next Steps

1. **Run the setup script** to create your vector store
2. **Test basic queries** to verify retrieval works
3. **Tune parameters** based on your use case
4. **Monitor costs** in the OpenAI dashboard
5. **Scale up** by adding more knowledge base files as needed

For questions or issues, check the debug logs with `DEBUG=true` or review the OpenAI vector stores dashboard.
