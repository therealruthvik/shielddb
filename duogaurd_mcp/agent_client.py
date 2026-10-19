import asyncio
import os
import sys
import json
import logging
from typing import Dict, Any, List

# Ensure parent directory is in path so absolute imports work
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", stream=sys.stderr)
logger = logging.getLogger("ShieldDBAgent")

# Try to load environment variables from .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Check for API key
api_key = os.environ.get("GROQ_API_KEY")
if not api_key:
    logger.error("=" * 60)
    logger.error("⚠️  MISSING GROQ API KEY!")
    logger.error("Please create a '.env' file in the root directory and add:")
    logger.error("  GROQ_API_KEY=gsk_...")
    logger.error("You can get a free API key from the Groq Console (https://console.groq.com/keys)")
    logger.error("=" * 60)
    sys.exit(1)

# Import Groq client and MCP components
try:
    from duogaurd_mcp.groq_client import chat_completion, GROQ_CHAT_MODEL
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError as ie:
    logger.error(f"Failed to import required libraries: {ie}. Run 'uv sync' or 'pip install' first.")
    sys.exit(1)


async def run_mcp_agent():
    # 1. Configure the MCP server parameters to run our ShieldDB server in the background
    # This launches 'python -m duogaurd_mcp.main run' as a subprocess stdio channel
    logger.info("Initializing ShieldDB MCP Secure Gateway in background...")
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "duogaurd_mcp.main", "run"]
    )
    
    # 2. Connect to the MCP server
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            
            # 3. Retrieve the available tools exposed by our ShieldDB MCP server
            logger.info("Discovering secure database tools...")
            tools_list = await session.list_tools()
            available_tools = {tool.name: tool for tool in tools_list.tools}
            logger.info(f"Connected! Secure tools discovered: {list(available_tools.keys())}")
            
            # 4. Describe the ShieldDB tools as function declarations so the model knows how to use them
            chat_tools = [
                {
                    "type": "function",
                    "function": {
                        "name": t_name,
                        "description": t_val.description,
                        "parameters": t_val.inputSchema
                    }
                }
                for t_name, t_val in available_tools.items()
            ]
            
            # 5. Define an interactive chat loop
            print("\n" + "=" * 60)
            print("🤖 WELCOME TO THE SECURED AI DATABASE WORKSTATION!")
            print("Ask the agent questions about the database in plain English.")
            print("ShieldDB will automatically block injections and scrub outbound PII.")
            print("Type 'exit' or 'quit' to close the workstation.")
            print("=" * 60 + "\n")
            
            # Create a simple chat history
            chat_context = " ".join([
                "You are an expert database administrator.",
                "You have access to a secure MongoDB database gateway called 'ShieldDB'.",
                "ShieldDB automatically intercepts your queries to protect against malicious injections",
                "and automatically masks sensitive user credentials (SSN, credit cards) before you see them.",
                "When asked to query, write, or drop database items, ALWAYS use the secure tools available.",
                "Always present the database documents clearly to the user, highlighting that PII was securely redacted."
            ])
            
            while True:
                try:
                    user_prompt = input("\n👤 User: ").strip()
                    if not user_prompt:
                        continue
                    if user_prompt.lower() in ["exit", "quit"]:
                        print("Terminating secure database session. Goodbye!")
                        break
                        
                    print("🤖 Agent is thinking...")
                    
                    # 5. Ask the model what it wants to do. It decides whether to call a tool or chat directly.
                    messages = [
                        {"role": "system", "content": chat_context},
                        {"role": "user", "content": user_prompt}
                    ]
                    response = chat_completion({
                        "model": GROQ_CHAT_MODEL,
                        "messages": messages,
                        "tools": chat_tools,
                        "temperature": 0.1
                    })
                    
                    # 6. Handle tool calls requested by the model
                    if response.get("tool_calls"):
                        messages.append({"role": "assistant", "content": response.get("content") or "", "tool_calls": response["tool_calls"]})
                        for call in response["tool_calls"]:
                            tool_name = call["function"]["name"]
                            tool_args = json.loads(call["function"]["arguments"] or "{}")
                            
                            print(f"   [ShieldDB Gateway] Intercepting tool call: {tool_name} with arguments {json.dumps(tool_args)}")
                            
                            # Execute the secure tool call on our MCP server!
                            tool_result = await session.call_tool(tool_name, tool_args)
                            result_text = tool_result.content[0].text
                            messages.append({"role": "tool", "tool_call_id": call["id"], "content": result_text})
                            
                        print("   [ShieldDB Gateway] Safety audit complete. Forwarding sanitized results to the agent.")
                        
                        # Let the model process the secure redacted output and formulate the final answer to the user
                        final_response = chat_completion({
                            "model": GROQ_CHAT_MODEL,
                            "messages": messages,
                            "temperature": 0.1
                        })
                        
                        print(f"\n🤖 Agent: {final_response.get('content')}")
                    else:
                        print(f"\n🤖 Agent: {response.get('content')}")
                        
                except Exception as e:
                    print(f"\n⚠️ Error during processing: {e}")

def main():
    try:
        asyncio.run(run_mcp_agent())
    except KeyboardInterrupt:
        print("\nSession aborted by user. Exiting secure gateway.")

if __name__ == "__main__":
    main()
