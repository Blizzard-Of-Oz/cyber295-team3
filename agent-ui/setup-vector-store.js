#!/usr/bin/env node
/**
 * Vector Store Setup Script
 * 
 * This script creates an OpenAI vector store and uploads your knowledge base files.
 * Run once to set up, then use the returned OPENAI_VECTOR_STORE_ID in your .env file.
 * 
 * Usage:
 *   node setup-vector-store.js <path-to-knowledge-file>
 * 
 * Example:
 *   node setup-vector-store.js ../it_tickets_knowledge.txt
 */

import { OpenAI } from "openai";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";

// Load environment variables from .env file
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function setupVectorStore(filePath) {
  const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

  if (!openai.apiKey) {
    console.error("❌ Error: OPENAI_API_KEY not found");
    console.error("   Add it to your .env file:");
    console.error("   OPENAI_API_KEY=your-api-key");
    console.error("   Or set it as an environment variable:");
    console.error("   export OPENAI_API_KEY=your-api-key");
    process.exit(1);
  }

  // Resolve file path
  const absolutePath = path.resolve(process.cwd(), filePath);
  if (!fs.existsSync(absolutePath)) {
    console.error(`❌ Error: File not found: ${absolutePath}`);
    process.exit(1);
  }

  console.log("🚀 Starting vector store setup...\n");
  console.log(`📄 File to upload: ${absolutePath}`);
  console.log(`   Size: ${(fs.statSync(absolutePath).size / 1024).toFixed(2)} KB\n`);

  // Check if vector store already exists in .env
  const existingVectorStoreId = process.env.OPENAI_VECTOR_STORE_ID;
  let vectorStore = null;
  let isNewStore = false;

  try {
    if (existingVectorStoreId) {
      console.log("1️⃣  Using existing vector store...");
      try {
        vectorStore = await openai.vectorStores.retrieve(existingVectorStoreId);
        console.log(`   ✅ Connected to vector store: ${vectorStore.id}\n`);
      } catch (error) {
        console.error(`   ⚠️  Vector store ${existingVectorStoreId} not found or inaccessible`);
        console.error("   Creating a new vector store instead...\n");
        vectorStore = await createNewVectorStore(openai);
        isNewStore = true;
      }
    } else {
      console.log("1️⃣  Creating new vector store...");
      vectorStore = await createNewVectorStore(openai);
      isNewStore = true;
    }

    // Step 2: Upload the file
    console.log("2️⃣  Uploading knowledge base file...");
    const file = await openai.files.create({
      file: fs.createReadStream(absolutePath),
      purpose: "assistants"
    });
    console.log(`   ✅ File uploaded: ${file.id}\n`);

    // Step 3: Add file to vector store
    console.log("3️⃣  Adding file to vector store...");
    const vectorStoreFile = await openai.vectorStores.files.create(
      vectorStore.id,
      { file_id: file.id }
    );
    console.log(`   ✅ File added to vector store\n`);

    // Step 4: Wait for processing to complete
    console.log("4️⃣  Processing file (this may take a few seconds)...");
    let status = vectorStoreFile.status;
    let attempts = 0;
    const maxAttempts = 30;

    while (status === "in_progress" && attempts < maxAttempts) {
      await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds
      const fileStatus = await openai.vectorStores.files.list(vectorStore.id);
      // Find the file in the list
      const foundFile = fileStatus.data?.find(f => f.id === vectorStoreFile.id);
      if (foundFile) {
        status = foundFile.status;
      }
      attempts++;
      process.stdout.write(".");
    }
    console.log();

    if (status === "completed") {
      console.log("   ✅ File processing completed\n");
    } else if (status === "failed") {
      console.log("   ❌ File processing failed");
      console.log(`   Status: ${status}`);
      process.exit(1);
    } else {
      console.log(`   ⚠️  File processing status: ${status}`);
      console.log("   The file may still be processing. Check the OpenAI dashboard.\n");
    }

    // Step 5: Display success message and configuration
    console.log("=" .repeat(70));
    console.log("✅ VECTOR STORE SETUP COMPLETE!");
    console.log("=" .repeat(70));
    console.log("\n📋 Configuration:");
    console.log(`   Vector Store ID: ${vectorStore.id}`);
    console.log(`   File ID: ${file.id}`);
    console.log(`   Status: ${status}`);
    console.log(`   ${isNewStore ? "NEW store created" : "File appended to existing store"}\n`);
    
    if (isNewStore) {
      console.log("🔧 Next Steps:");
      console.log("   1. Add this to your .env file:");
      console.log(`      OPENAI_VECTOR_STORE_ID=${vectorStore.id}`);
      console.log(`      RAG_TOP_K=5`);
      console.log(`      RAG_MIN_SCORE=0.6\n`);
    } else {
      console.log("✅ File appended to existing vector store!");
      console.log(`   Your OPENAI_VECTOR_STORE_ID remains: ${vectorStore.id}\n`);
    }

    console.log("   2. Restart your agent application");
    console.log("   3. Test with a query like: 'What's the solution for VPN issues?'\n");
    
    console.log("💡 Tips:");
    console.log("   - To add more files, run this script again with different files");
    console.log("   - Files will be appended to the same vector store automatically");
    console.log("   - Adjust RAG_TOP_K (1-10) to control how many chunks are retrieved");
    console.log("   - Adjust RAG_MIN_SCORE (0.0-1.0) to filter low-relevance results");
    console.log("   - View your vector stores at: https://platform.openai.com/storage/vector_stores\n");

    // Update .env file if new store
    if (isNewStore) {
      updateEnvFile(vectorStore.id);
    }

  } catch (error) {
    console.error("\n❌ Setup failed:", error.message);
    if (error.response) {
      console.error("   Status:", error.response.status);
      console.error("   Details:", JSON.stringify(error.response.data, null, 2));
    }
    process.exit(1);
  }
}

async function createNewVectorStore(openai) {
  const vectorStore = await openai.vectorStores.create({
    name: "IT Tickets Knowledge Base",
    expires_after: {
      anchor: "last_active_at",
      days: 365
    }
  });
  console.log(`   ✅ Vector store created: ${vectorStore.id}\n`);
  return vectorStore;
}

function updateEnvFile(vectorStoreId) {
  const envPath = path.join(__dirname, ".env");
  let envContent = "";

  // Read existing .env file if it exists
  if (fs.existsSync(envPath)) {
    envContent = fs.readFileSync(envPath, "utf-8");
    
    // Check if OPENAI_VECTOR_STORE_ID already exists
    if (envContent.includes("OPENAI_VECTOR_STORE_ID=")) {
      // Replace existing value
      envContent = envContent.replace(
        /OPENAI_VECTOR_STORE_ID=.*/,
        `OPENAI_VECTOR_STORE_ID=${vectorStoreId}`
      );
    } else {
      // Append new variable
      if (!envContent.endsWith("\n")) {
        envContent += "\n";
      }
      envContent += `\n# RAG (Retrieval Augmented Generation) Configuration\nOPENAI_VECTOR_STORE_ID=${vectorStoreId}\nRAG_TOP_K=5\nRAG_MIN_SCORE=0.6\n`;
    }
  } else {
    // Create new .env file
    envContent = `OPENAI_API_KEY=your_openai_key\n\n# RAG (Retrieval Augmented Generation) Configuration\nOPENAI_VECTOR_STORE_ID=${vectorStoreId}\nRAG_TOP_K=5\nRAG_MIN_SCORE=0.6\n`;
  }

  // Write updated content
  fs.writeFileSync(envPath, envContent, "utf-8");
  console.log(`\n📝 Updated .env file with OPENAI_VECTOR_STORE_ID=${vectorStoreId}`);
}

// Main execution
const args = process.argv.slice(2);
if (args.length === 0) {
  console.log("Usage: node setup-vector-store.js <path-to-knowledge-file>");
  console.log("\nExample:");
  console.log("  node setup-vector-store.js ../it_tickets_knowledge.txt");
  process.exit(1);
}

const filePath = args[0];
setupVectorStore(filePath);
