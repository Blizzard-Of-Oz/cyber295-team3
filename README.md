# Demo Project for Team 3

## AI Bot for Gmail Mailbox Management

This project is an AI-powered bot designed to help manage a Gmail mailbox.

It is built on top of the **Gmail MCP Server**:  
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
- Future policy enforcement via OPA  

