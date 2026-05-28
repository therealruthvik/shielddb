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
api_key = os.environ.get("GEMINI_API_KEY")
if not api_key:
    logger.error("=" * 60)
    logger.error("⚠️  MISSING GOOGLE GEMINI API KEY!")
    logger.error("Please create a '.env' file in the root directory and add:")
    logger.error("  GEMINI_API_KEY=AIzaSy...")
    logger.error("You can get a free API key from Google AI Studio (https://aistudio.google.com)")
    logger.error("=" * 60)
    sys.exit(1)

# Import google-genai SDK and MCP components
try:
    from google import genai
    from google.genai import types
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError as ie:
    logger.error(f"Failed to import required libraries: {ie}. Run 'uv sync' or 'pip install' first.")
    sys.exit(1)


def clean_schema(schema):
    """Recursively removes 'additionalProperties' and 'additional_properties' from JSON schemas for Gemini compatibility."""
    if not isinstance(schema, dict):
        return schema
    cleaned = {}
    for k, v in schema.items():
        if k in ["additionalProperties", "additional_properties"]:
            continue
        if isinstance(v, dict):
            cleaned[k] = clean_schema(v)
        elif isinstance(v, list):
            cleaned[k] = [clean_schema(item) if isinstance(item, dict) else item for item in v]
        else:
            cleaned[k] = v
    return cleaned

async def run_gemini_mcp_agent():
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
            
            # 4. Initialize the Google GenAI Client
            logger.info("Initializing Google Gemini AI Client...")
            client = genai.Client(api_key=api_key)
            
            # 5. Define an interactive chat loop
            print("\n" + "=" * 60)
            print("🤖 WELCOME TO THE SECURED GEMINI DATABASE WORKSTATION!")
            print("Ask Gemini questions about the database in plain English.")
            print("ShieldDB will automatically block injections and scrub outbound PII.")
            print("Type 'exit' or 'quit' to close the workstation.")
            print("=" * 60 + "\n")
            
            # Create a simple chat history
            chat_context = [
                "You are an expert database administrator powered by Google Gemini.",
                "You have access to a secure MongoDB database gateway called 'ShieldDB'.",
                "ShieldDB automatically intercepts your queries to protect against malicious injections",
                "and automatically masks sensitive user credentials (SSN, credit cards) before you see them.",
                "When asked to query, write, or drop database items, ALWAYS use the secure tools available.",
                "Always present the database documents clearly to the user, highlighting that PII was securely redacted."
            ]
            
            while True:
                try:
                    user_prompt = input("\n👤 User: ").strip()
                    if not user_prompt:
                        continue
                    if user_prompt.lower() in ["exit", "quit"]:
                        print("Terminating secure database session. Goodbye!")
                        break
                        
                    print("🤖 Gemini is thinking...")
                    
                    # 6. Ask Gemini what it wants to do. We pass the ShieldDB tools as function declarations!
                    # Gemini will decide whether to call a tool or chat directly.
                    # We describe the tools so Gemini knows how to use them.
                    gemini_tools = []
                    for t_name, t_val in available_tools.items():
                        gemini_tools.append(
                            types.FunctionDeclaration(
                                name=t_name,
                                description=t_val.description,
                                parameters=clean_schema(t_val.inputSchema)
                            )
                        )
                    
                    # Call Gemini
                    response = client.models.generate_content(
                        model='gemini-3.5-flash',
                        contents=[*chat_context, f"User request: {user_prompt}"],
                        config=types.GenerateContentConfig(
                            tools=[types.Tool(function_declarations=gemini_tools)],
                            temperature=0.1
                        )
                    )
                    
                    # 7. Handle tool calls requested by Gemini
                    if response.function_calls:
                        for call in response.function_calls:
                            tool_name = call.name
                            tool_args = call.args
                            
                            print(f"   [ShieldDB Gateway] Intercepting tool call: {tool_name} with arguments {json.dumps(tool_args)}")
                            
                            # Execute the secure tool call on our MCP server!
                            tool_result = await session.call_tool(tool_name, tool_args)
                            result_text = tool_result.content[0].text
                            
                            print("   [ShieldDB Gateway] Safety audit complete. Forwarding sanitized results to Gemini.")
                            
                            # Let Gemini process the secure redacted output and formulate the final answer to the user
                            final_response = client.models.generate_content(
                                model='gemini-3.5-flash',
                                contents=[
                                    *chat_context,
                                    f"User request: {user_prompt}",
                                    f"Action executed: Called tool '{tool_name}' with args {json.dumps(tool_args)}",
                                    f"Sanitized tool output: {result_text}"
                                ]
                            )
                            
                            print(f"\n🤖 Gemini: {final_response.text}")
                    else:
                        print(f"\n🤖 Gemini: {response.text}")
                        
                except Exception as e:
                    print(f"\n⚠️ Error during processing: {e}")

def main():
    try:
        asyncio.run(run_gemini_mcp_agent())
    except KeyboardInterrupt:
        print("\nSession aborted by user. Exiting secure gateway.")

if __name__ == "__main__":
    main()
