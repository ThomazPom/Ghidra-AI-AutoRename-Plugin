# -*- coding: utf-8 -*-
"""
handleOpenAi.py
===============
This script interacts with the OpenAI API to fetch renamed symbols for Ghidra.
It reads the current function context, sends it to OpenAI, and writes the results
as JSON to `symbols.renamed.json`.

"""

import argparse
import os
import json
import logging
import time
from openai import OpenAI
from tqdm import tqdm

# Constants
DEFAULT_MODEL_NAME = "gpt-4o-mini"
DEFAULT_MAX_TOKENS = 10000
DEFAULT_TEMPERATURE = 0.2
OUTPUT_FILE = "symbols.renamed.json"

# Pricing per 1M tokens (USD) — update when switching models
MODEL_PRICING = {
    "gpt-4o-mini":  {"input": 0.15,  "cached_input": 0.075,  "output": 0.60},
    "gpt-4o":       {"input": 2.50,  "cached_input": 1.25,   "output": 10.00},
    "gpt-4.1":      {"input": 2.00,  "cached_input": 0.50,   "output": 8.00},
    "gpt-4.1-mini": {"input": 0.40,  "cached_input": 0.10,   "output": 1.60},
    "gpt-4.1-nano": {"input": 0.10,  "cached_input": 0.025,  "output": 0.40},
    "o4-mini":      {"input": 1.10,  "cached_input": 0.275,  "output": 4.40},
    "o3":           {"input": 2.00,  "cached_input": 0.50,   "output": 8.00},
    "o3-mini":      {"input": 1.10,  "cached_input": 0.275,  "output": 4.40},
    "o1":           {"input": 15.00, "cached_input": 7.50,   "output": 60.00},
    "o1-mini":      {"input": 1.10,  "cached_input": 0.55,   "output": 4.40},
}

# Model ID prefixes we consider relevant for chat completions
CHAT_MODEL_PREFIXES = ("gpt-4", "gpt-3.5", "o1", "o3", "o4")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_api_key(api_key_path):
    """Load the OpenAI API key from a .secret file."""
    try:
        script_dir = os.path.dirname(os.path.realpath(__file__))
        secret_file_path = os.path.join(script_dir, api_key_path)
        with open(secret_file_path, "r", encoding="utf-8") as secret_file:
            secrets = json.load(secret_file)
            return secrets.get("OPENAI_API_KEY")
    except Exception as e:
        raise RuntimeError(f"Failed to load API key from .secret file: {e}")

def list_available_models(client):
    """Query the OpenAI API for available models, filter to chat-relevant ones,
    and return a list of dicts with model id and pricing info."""
    models = client.models.list()
    relevant = []
    for m in sorted(models.data, key=lambda x: x.id):
        mid = m.id
        # Only keep base chat models, skip fine-tunes, snapshots, audio, realtime, etc.
        if not mid.startswith(CHAT_MODEL_PREFIXES):
            continue
        if any(skip in mid for skip in ("realtime", "audio", "search", "instruct", "vision", "preview")):
            continue
        pricing = MODEL_PRICING.get(mid)
        relevant.append({
            "id": mid,
            "input":        pricing["input"]        if pricing else None,
            "cached_input": pricing["cached_input"] if pricing else None,
            "output":       pricing["output"]       if pricing else None,
        })
    return relevant

def fetch_renamed_symbols(client, system_prompt, user_prompt, model, max_tokens, temperature):
    """Send a prompt to OpenAI Chat API and fetch renamed symbols.

    Returns a tuple (json_string, usage_dict) where usage_dict contains
    prompt_tokens, completion_tokens, and cached_tokens.
    """
    retries = 3
    for attempt in range(retries):
        try:
            logging.info("Sending prompt to OpenAI (Attempt {}/{}).".format(attempt + 1, retries))
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ],
                max_tokens=max_tokens,
                temperature=temperature,
                response_format={"type": "json_object"},
            )
            logging.info("Received response from OpenAI.")

            raw_text = response.choices[0].message.content.strip()
            logging.info(f"OpenAI raw response: {raw_text}")

            # Gather usage stats
            usage = {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "cached_tokens": 0,
            }
            if hasattr(response.usage, 'prompt_tokens_details') and response.usage.prompt_tokens_details:
                usage["cached_tokens"] = getattr(response.usage.prompt_tokens_details, 'cached_tokens', 0)
            logging.info(f"Tokens — prompt: {usage['prompt_tokens']} (cached: {usage['cached_tokens']}), completion: {usage['completion_tokens']}")

            parsed_json = json.loads(raw_text)
            if not isinstance(parsed_json, dict):
                raise ValueError("Response JSON is not a dictionary.")
            return json.dumps(parsed_json), usage
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse JSON response: {e}")
            if attempt == retries - 1:
                raise ValueError("Invalid response format: JSON object not found or malformed.")
        except Exception as e:
            logging.error(f"Error querying OpenAI: {e}")
            if attempt == retries - 1:
                raise
            time.sleep(2)  # Wait before retrying

def load_context_file(context_file_path):
    """Load the context file containing decompiled code and function details."""
    try:
        with open(context_file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise RuntimeError(f"Failed to load context file: {e}")

def main():
    """Main function to handle OpenAI interaction and write results."""
    parser = argparse.ArgumentParser(description="Fetch renamed symbols using OpenAI.")
    parser.add_argument("context_file_path", type=str, nargs="?", default=None, help="Path to the context file containing function details.")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL_NAME, help="OpenAI model to use.")
    parser.add_argument("--max_tokens", type=int, default=DEFAULT_MAX_TOKENS, help="Maximum number of tokens for the OpenAI model.")
    parser.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE, help="Sampling temperature for the OpenAI model.")
    parser.add_argument("--api_key_path", type=str, default=".secret", help="Path to the .secret file containing the OpenAI API key.")
    parser.add_argument("--sleep", type=int, default=3, help="Time to sleep between each request to avoid rate limiting.")
    parser.add_argument("--output_file", type=str, default=OUTPUT_FILE, help="Path to the output file where renamed symbols will be saved.")
    parser.add_argument("--add_description", action="store_true", default=False, help="Ask the AI to also return a one-line description of each function.")
    parser.add_argument("--long_description", action="store_true", default=False, help="Ask for a longer, detailed description instead of one-line.")
    parser.add_argument("--desc_insight", action="store_true", default=False, help="Include insight on why the function is important in the program.")
    parser.add_argument("--send_context_code", action="store_true", default=False, help="Include full decompiled code of callers/callees in the prompt instead of just names.")
    parser.add_argument("--retype_globals", action="store_true", default=False, help="Suggest C types for undefined global variables instead of renaming.")
    parser.add_argument("--annotate_block", action="store_true", default=False, help="Analyze orphan assembly blocks and suggest descriptions and function names.")
    parser.add_argument("--list_models", action="store_true", default=False, help="List available chat models with pricing and exit. Output is JSON on stdout.")

    args = parser.parse_args()

    # Load API key
    api_key = load_api_key(args.api_key_path)
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not found in .secret file.")

    # Initialize OpenAI client
    client = OpenAI(api_key=api_key)

    # --list_models mode: print models JSON and exit
    if args.list_models:
        available = list_available_models(client)
        print(json.dumps(available))
        return

    # Load context
    context = load_context_file(args.context_file_path)

    # --retype_globals mode: suggest types for undefined globals
    if args.retype_globals:
        retype_context = context.get("__retype_globals__", context)
        retype_system = (
            "You are a reverse-engineering assistant that determines C data types.\n"
            "You will receive a list of global variables from a decompiled binary.\n"
            "Each variable has a name (possibly already renamed to be meaningful),\n"
            "its current placeholder type (e.g. undefined4 = 4 unknown bytes),\n"
            "its stored value, and the functions that reference it.\n\n"
            "Based on the variable name and value, suggest the most appropriate C type.\n"
            "The new type MUST have the same byte size as the original:\n"
            "  undefined1 -> 1-byte type (char, uint8_t, bool, byte)\n"
            "  undefined2 -> 2-byte type (short, uint16_t, int16_t)\n"
            "  undefined4 -> 4-byte type (int, uint32_t, float, void*)\n"
            "  undefined8 -> 8-byte type (long, uint64_t, double)\n\n"
            "If the name suggests a pointer (contains ptr, buf, addr, str, etc.), use void*.\n"
            "If unsure, prefer int for undefined4, short for undefined2, byte for undefined1.\n\n"
            "Respond with a JSON object: {\"variable_name\": \"c_type\", ...}\n"
        )
        user_prompt = "Global variables to retype:\n\n"
        for var_name, info in retype_context.items():
            user_prompt += "- {}: current_type={}, value={}, used_in={}\n".format(
                var_name, info["current_type"], info["value"], info["used_in_functions"])

        response, usage = fetch_renamed_symbols(client, retype_system, user_prompt, args.model, args.max_tokens, args.temperature)
        parsed = json.loads(response)
        output_file_path = os.path.abspath(args.output_file)
        with open(output_file_path, "w", encoding="utf-8") as f:
            json.dump({"__retype_globals__": parsed}, f, indent=4)
        logging.info(f"Retype suggestions written to {output_file_path}")

        pricing = MODEL_PRICING.get(args.model, {"input": 0, "cached_input": 0, "output": 0})
        uncached = usage["prompt_tokens"] - usage["cached_tokens"]
        cost = ((uncached / 1_000_000) * pricing["input"]
                + (usage["cached_tokens"] / 1_000_000) * pricing["cached_input"]
                + (usage["completion_tokens"] / 1_000_000) * pricing["output"])
        logging.info(f"Retype cost: ${cost:.4f}")
        return

    # --annotate_block mode: describe orphan assembly and suggest names
    if args.annotate_block:
        blocks_context = context.get("__annotate_blocks__", context)
        block_system = (
            "You are a reverse-engineering assistant analyzing orphan assembly code blocks.\n"
            "These are instruction sequences found in an executable that are not part of\n"
            "any recognized function.  For each block you receive the raw disassembly listing.\n\n"
            "For each block provide:\n"
            "1. A concise description of what the code appears to do.\n"
            "2. A suggested function name (valid C identifier) if this block were named.\n\n"
            "Respond with a JSON object:\n"
            "{\n"
            "  \"<address>\": {\n"
            "    \"description\": \"<what this code block does>\",\n"
            "    \"suggested_name\": \"<meaningful_function_name>\"\n"
            "  },\n"
            "  ...\n"
            "}\n"
        )
        user_prompt = "Orphan code blocks to analyze:\n\n"
        for addr_hex, info in blocks_context.items():
            user_prompt += f"--- Block at {addr_hex} ---\n{info['disassembly']}\n\n"

        response, usage = fetch_renamed_symbols(client, block_system, user_prompt, args.model, args.max_tokens, args.temperature)
        parsed = json.loads(response)
        output_file_path = os.path.abspath(args.output_file)
        with open(output_file_path, "w", encoding="utf-8") as f:
            json.dump({"__annotate_blocks__": parsed}, f, indent=4)
        logging.info(f"Block annotations written to {output_file_path}")

        pricing = MODEL_PRICING.get(args.model, {"input": 0, "cached_input": 0, "output": 0})
        uncached = usage["prompt_tokens"] - usage["cached_tokens"]
        cost = ((uncached / 1_000_000) * pricing["input"]
                + (usage["cached_tokens"] / 1_000_000) * pricing["cached_input"]
                + (usage["completion_tokens"] / 1_000_000) * pricing["output"])
        logging.info(f"Annotate cost: ${cost:.4f}")
        return

    # System prompt — identical across all calls.
    # OpenAI automatically caches this prefix after the first request,
    # giving a 50 % discount on input tokens for subsequent calls.
    system_prompt = (
        "You are a reverse-engineering assistant that renames decompiled symbols.\n"
        "Analyze the function provided by the user and rename its elements:\n"
        "1. Rename the target function to a meaningful name that reflects its purpose.\n"
        "2. Rename its parameters to descriptive names that indicate their roles.\n"
        "3. Rename its local variables to clear and concise names that represent their usage.\n"
        "4. Rename all generic global variables encountered in the excerpts to meaningful names.\n"
        "5. Rename labels, classes, namespaces, enums, structs, and typedefs to appropriate names that align with their functionality.\n"
        "Some symbols might have already been named from previous calls. Unless you are absolutely sure about a new better name, you may ignore them.\n"
    )

    if args.add_description:
        if args.long_description:
            system_prompt += (
                "6. Provide a detailed multi-line description of the function in a \"description\" field.\n"
                "   Cover: purpose, parameters, return value, side effects, and key logic.\n"
            )
        else:
            system_prompt += (
                "6. Provide a concise one-line description of what the function does in a \"description\" field.\n"
            )
        if args.desc_insight:
            system_prompt += (
                "7. At the end of the description, add a line starting with 'Role:' that explains\n"
                "   why this function is important and how its used within the larger program, based on its callers\n"
                "   and callees context.\n"
            )

    json_schema = (
        "{\n  \"<function_name>\": {\n    \"function\": \"<string for new name>\",\n"
    )
    if args.add_description:
        if args.long_description:
            json_schema += "    \"description\": \"<detailed multi-line description>\",\n"
        else:
            json_schema += "    \"description\": \"<one-line summary of what the function does>\",\n"
    json_schema += (
        "    \"parameters\": {\"old\": \"new\", ...},\n"
        "    \"locals\": {\"old\": \"new\", ...},\n"
        "    \"globals\": {\"old\": \"new\", ...},\n"
        "    \"labels\": {\"old\": \"new\", ...},\n"
        "    \"classes\": {\"old\": \"new\", ...},\n"
        "    \"namespaces\": {\"old\": \"new\", ...},\n"
        "    \"enums\": {\"old\": \"new\", ...},\n"
        "    \"structs\": {\"old\": \"new\", ...},\n"
        "    \"typedefs\": {\"old\": \"new\", ...}\n  }\n}\n"
    )

    system_prompt += "Respond strictly with a JSON object (no surrounding text):\n" + json_schema

    renamed_symbols = {}
    total_prompt_tokens = 0
    total_completion_tokens = 0
    total_cached_tokens = 0

    for func_name, details in tqdm(context.items(), desc="Processing functions"):
        # User prompt — only the function-specific context (variable part)
        user_prompt = f"### Function: {func_name}\n"
        user_prompt += f"Decompiled Code:\n{details['decompiled_code']}\n"

        if args.send_context_code:
            # Send full decompiled code for callers and callees
            if details.get('callers'):
                user_prompt += "\n### Callers (decompiled):\n"
                for name, code in details['callers'].items():
                    user_prompt += f"--- {name} ---\n{code}\n"
            if details.get('callees'):
                user_prompt += "\n### Callees (decompiled):\n"
                for name, code in details['callees'].items():
                    user_prompt += f"--- {name} ---\n{code}\n"
        else:
            # Send only names
            user_prompt += f"Callers: {', '.join(details['callers'])}\n"
            user_prompt += f"Callees: {', '.join(details['callees'])}\n"

        if 'global_variables' in details:
            user_prompt += "Global Variables:\n"
            for var_name, var_details in details['global_variables'].items():
                user_prompt += f"  {var_name}: {var_details}\n"

        try:
            response, usage = fetch_renamed_symbols(client, system_prompt, user_prompt, args.model, args.max_tokens, args.temperature)
            total_prompt_tokens += usage["prompt_tokens"]
            total_completion_tokens += usage["completion_tokens"]
            total_cached_tokens += usage["cached_tokens"]

            parsed_response = json.loads(response)

            # Ensure the response is flattened and avoid double nesting
            if func_name in parsed_response:
                renamed_symbols[func_name] = parsed_response[func_name]
            else:
                renamed_symbols[func_name] = parsed_response

            logging.info(f"Successfully renamed symbols for function: {func_name}")
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON response for function {func_name}: {e}")
        except Exception as e:
            logging.error(f"Failed to fetch renamed symbols for function {func_name}: {e}")

        time.sleep(args.sleep)

    logging.info("Writing renamed symbols to file...")
    output_file_path = os.path.abspath(args.output_file)
    with open(output_file_path, "w", encoding="utf-8") as f:
        json.dump(renamed_symbols, f, indent=4)

    logging.info(f"Renamed symbols written to {output_file_path}.")

    # ---- Cost summary ----
    pricing = MODEL_PRICING.get(args.model, {"input": 0, "cached_input": 0, "output": 0})
    uncached_input = total_prompt_tokens - total_cached_tokens
    input_cost    = (uncached_input    / 1_000_000) * pricing["input"]
    cached_cost   = (total_cached_tokens / 1_000_000) * pricing["cached_input"]
    output_cost   = (total_completion_tokens / 1_000_000) * pricing["output"]
    total_cost    = input_cost + cached_cost + output_cost

    logging.info("========== TOKEN & COST SUMMARY ==========")
    logging.info(f"Model:             {args.model}")
    logging.info(f"Prompt tokens:     {total_prompt_tokens:,}  (cached: {total_cached_tokens:,})")
    logging.info(f"Completion tokens: {total_completion_tokens:,}")
    logging.info(f"Input cost:        ${input_cost:.4f}  (uncached) + ${cached_cost:.4f}  (cached)")
    logging.info(f"Output cost:       ${output_cost:.4f}")
    logging.info(f"TOTAL COST:        ${total_cost:.4f}")
    logging.info("===========================================")

if __name__ == "__main__":
    main()
