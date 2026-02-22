# Demo Project for Team 3

## AI Bot for Gmail Mailbox Management

This project is an AI-powered bot designed to help manage a Gmail mailbox.

It is built on top of the **Gmail MCP Server**:  
https://github.com/fldc/Gmail-MCP-Server.git, which is a fork from
https://github.com/GongRzhe/Gmail-MCP-Server

### Architecture Overview

- **MCP Server Base**  
  The core functionality comes from the Gmail MCP Server.

- **HTTP Wrapper**  
  An HTTP wrapper is added on top of the MCP server to:
  - Expose MCP capabilities via HTTP APIs  
  - Extend functionality beyond the base MCP server  
  - Write audit logs to a database
  - Policy Enforcement
    An **OPA (Open Policy Agent) policy server** is integrated. The request will be evaluated based on the policies in opa-polices folder

- **Web UI / AI Agent / MCP Client**  
  The Web UI acts as:
  - An interactive user interface  
  - The AI agent that interprets user intent  
  - An MCP client that communicates with the MCP server via the HTTP wrapper  
  - The orchestration layer by calling the OpenAI API to plan and execute actions

### Summary

The project combines:
- Gmail MCP Server  
- A custom HTTP wrapper with auditing  
- A Web UI that functions as the AI agent, MCP client, and orchestration layer using the OpenAI API  
- Policy enforcement via OPA  

## How to setup development environment locally
Before starting the application components, ensure the following services are installed and running:
### 0. Prerequisites

  - OPA + OPAL

    The easiest way to set up OPA and OPAL is via Docker Compose.

    Follow the official quickstart guide:
    https://docs.opal.ac/getting-started/quickstart/opal-playground/run-server-and-client

    After cloning the OPAL Docker Compose setup, modify the OPAL server environment variables to point to this policy repository:

    ```
      - OPAL_POLICY_REPO_URL=https://github.com/yaoyaozong/cyber295-team3.git
      - OPAL_POLICY_REPO_MAIN_BRANCH=main
      - OPAL_POLICY_SUBSCRIPTION_DIRS=opa_policies
      - OPAL_BUNDLE_IGNORE=**/*_test.rego
    ```
    Make sure OPAL is running and successfully syncing policies before proceeding.

  - immuDB

    Download and run immuDB locally by following the official documentation:
    https://docs.immudb.io/master/running/download
    
    Ensure immuDB is running and accessible from your local environment.

  - Microsoft Entra ID (Authentication)

    You will need:
    - Azure Tenant ID
    - Client ID
    - Client Secret

    Make sure your application registration is properly configured in Entra ID.

### 1. WebUI and Agent
  - Step 1: Create Environment File

    ```
    cd agent-ui
    cp .env.example .env
    ```

  - Step 2: Configure Environment Variables

    Edit the `.env` file and configure the following:

    ```env
    OPENAI_API_KEY=your_openai_key
    AZURE_TENANT_ID=your-tenant-id
    AZURE_CLIENT_ID=your-client-id
    AZURE_CLIENT_SECRET=your-client-secret
    ```
  - Step 3: Install Dependencies and Start

    ```bash
    npm install
    npm start
    ```

  The Web UI and Agent should now be running locally.

### 2. HTTP Wrapper and MCP server
  - Build GMAIL MCP server
    ```
    # Fetch code for submodule
    git submodule update --init --recursive

    # Build GMAIL MCP server
    cd mcp-server/gmail
    npm install
    npm run build
    ```

  - Build and run HTTP Wrapper
    ```
    cd gmail-mcp-http
    cp .env.example .env
    ```

    Modify the created `.env` file to match the local immuDB and OPA setup. 
    
    Then install dependenicies and start 

    ```
    npm install
    npm start
    ```
### 3. Logviewer

  ```
  cd logviewer
  cp .env.example .env
  ```

  Modify the created .env file to match the local immuDB setup. Then install dependenicies and start 
  
  ```
  npm install
  npm start
  ```

