# -*- coding: utf-8 -*-
# @author ChatGPT
# @category AI-Symbol-Renaming
# @menupath Tools.AI Assisted Renamer


"""
AIGhidra.py
===========

Purpose:
---------
This script is designed to enhance the process of symbol renaming within the Ghidra environment using AI assistance. Ghidra is a powerful reverse engineering tool, but manual renaming of symbols such as functions, parameters, locals, globals, labels, classes, namespaces, enums, structs, and typedefs can be time-consuming and error-prone. This script leverages OpenAI's capabilities to automate and improve the renaming process, ensuring that symbols are renamed to meaningful and descriptive names that align with their functionality.

How It Works:
-------------
1. **Decompilation and Context Preparation**:
   - The script decompiles functions within the Ghidra project to obtain their C-like representation.
   - It gathers additional context for each function, including its callers, callees, and global variables used.
   - This context is prepared in JSON format and passed to an external Python script (`handleOpenAi.py`) for processing.

2. **Integration with OpenAI**:
   - The external script interacts with the OpenAI API to fetch renaming suggestions based on the provided context.
   - OpenAI analyzes the function's decompiled code and its context to suggest meaningful names for symbols.

3. **Symbol Renaming**:
   - The script applies the renaming suggestions to various symbol types within the Ghidra project.
   - It ensures that the new names are applied consistently and accurately, avoiding conflicts or errors.

4. **Error Handling and Logging**:
   - Robust error handling is implemented to manage issues such as decompilation failures, invalid JSON responses, and external script errors.
   - The script logs key actions and errors to assist with debugging and monitoring.

Why Use This Script:
--------------------
- **Efficiency**: Automates the tedious process of renaming symbols, saving time and effort.
- **Accuracy**: Ensures that symbols are renamed to meaningful and descriptive names, improving code readability and understanding.
- **Scalability**: Can handle large Ghidra projects with numerous functions and symbols.
- **Integration**: Seamlessly integrates with Ghidra and OpenAI, leveraging the strengths of both tools.

Requirements:
-------------
- Ghidra environment with Python 2.7 scripting engine.
- Python 3.x installed on the system for running the external script (`handleOpenAi.py`).
- OpenAI API key stored in a `.secret` file.
- Dependencies for the external script, including the OpenAI Python package.

Usage:
------
1. Place this script in the Ghidra scripts directory.
2. Ensure that the external script (`handleOpenAi.py`) is configured correctly and accessible.
3. Run the script within the Ghidra environment to start the AI-assisted renaming process.
4. Monitor the logs for progress and any errors.

Important Notes:
----------------
- This script is intended to be run within the Ghidra environment and may not function correctly outside of it.
- The external script (`handleOpenAi.py`) must be compatible with Python 3.x and have the required dependencies installed.
- The `PYTHON3_EXECUTABLE` constant specifies the path to the Python 3.x executable. Update this path if necessary.

String Formatting:
------------------
- All string formatting in this script uses `.format()` for compatibility and consistency.
"""

import os
import json
import time
import tempfile
import logging
import subprocess
import sys
import re
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.symbol import SourceType, SymbolType
from ghidra.program.model.listing import CodeUnit
from ghidra.util.task import ConsoleTaskMonitor, TaskMonitor
from collections import OrderedDict
from ghidra.program.model.pcode import HighFunctionDBUtil

# Constants
REQUEST_TIMEOUT = 45
DECOMPILE_TIMEOUT = 30
RENAMED_SYMBOLS_FILE = os.path.join(tempfile.gettempdir(), "symbols.renamed.json")  # Default file path in temp directory
PYTHON_EXECUTABLE = "python"  # Path to Python executable for Python 3
OPENAI_CONNECTOR_SCRIPT = r"C:\Users\PWDK8402\Code\AIGhidra\handleOpenAi.py"  # External script for OpenAI API calls

# Constants for prefixes
RECEIVED_PREFIX = ""  # Prefix for function names received from OpenAI

# Constants for call tree depth
CALL_TREE_DEPTH_UP = 1  # Number of levels up (n-x)
CALL_TREE_DEPTH_DOWN = 1  # Number of levels down (n+x)
GLOBAL_RETYPE_THRESHOLD = 30  # Batch retype after this many undefined globals collected
ANNOTATE_BLOCK_BATCH_SIZE = 1  # Max orphan blocks per AI call
ORPHAN_BLOCK_MIN_SIZE = 1000   # Min disassembly chars to annotate an orphan block

# Constants for whitelisted function names
WHITELISTED_FUNCTIONS = ["entry", "processEntry"]

# Tag inserted as a plate comment to mark functions already processed by AI
AI_RENAMED_TAG = "[AI-RENAMED]"

# Runtime options set interactively at startup
OPT_ENABLE_TAGGING = True    # Add AI_RENAMED_TAG to processed functions (always on)
OPT_SKIP_TAGGED    = False   # Skip AI call for already-tagged functions (traversal still continues)
OPT_SKIP_AFTER_N   = 0       # If >0, skip functions renamed this many times or more (0 = no limit)
OPT_DONT_SKIP_SHORT_DESC = 0 # If >0, don't skip tagged functions whose description is <= this many chars
OPT_FORCE_RENAME_PATTERN = None  # Regex: never skip functions whose name matches this pattern
OPT_BOTTOM_UP      = False   # Process leaf functions first, then work upward
OPT_ADD_DESCRIPTION = False  # Ask the AI to generate a one-line function summary as plate comment
OPT_LONG_DESCRIPTION = False  # Ask for a longer, more detailed description
OPT_DESC_INSIGHT    = False   # Include insight on why the function matters in the program
OPT_MODEL          = "gpt-4o-mini"  # Selected model for OpenAI API calls
OPT_RESUME         = False   # Resume from a previous run (skip tagged + enable tagging)
OPT_SEND_CONTEXT_CODE = False  # Send decompiled code of callers/callees to the AI
OPT_RETYPE_GLOBALS  = False   # Batch-retype undefined globals after threshold
OPT_ANNOTATE_ORPHANS = False  # Annotate orphan code blocks with AI descriptions
OPT_ORPHAN_MIN_SIZE  = 1000   # Min disassembly chars for an orphan block to be annotated
OPT_LOG_LEVEL      = logging.INFO  # User-selected log level

monitor = ConsoleTaskMonitor()

# Accumulates undefined globals for batch retyping: {addr_hex: {name, type, value, funcs}}
_undefined_globals = {}

# Shared DecompInterface instance — created once, reused for all decompilations
_decomp_iface = None

def get_decomp_iface():
    """Return the shared DecompInterface, creating it on first call."""
    global _decomp_iface
    if _decomp_iface is None:
        _decomp_iface = DecompInterface()
        _decomp_iface.setOptions(DecompileOptions())
        _decomp_iface.openProgram(currentProgram)
    return _decomp_iface

# Simplified logging configuration with proper filter class
RAW = 5
logging.addLevelName(RAW, "RAW")

class ExcludeErrorsFilter(logging.Filter):
    def filter(self, record):
        return record.levelno < logging.ERROR

stdout_handler = logging.StreamHandler(sys.stdout)
stderr_handler = logging.StreamHandler(sys.stderr)

stdout_handler.setLevel(RAW)
stderr_handler.setLevel(logging.ERROR)

stdout_handler.addFilter(ExcludeErrorsFilter())

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
stdout_handler.setFormatter(formatter)
stderr_handler.setFormatter(formatter)

_logger = logging.getLogger()
_logger.setLevel(RAW)
# Prevent duplicate handlers on re-run within the same Ghidra session
if not _logger.handlers:
    _logger.addHandler(stdout_handler)
    _logger.addHandler(stderr_handler)

# Cache of decompiled code keyed by function entry point address
_decompile_cache = {}

def decompile_function(func):
    """Return the C-like decompilation of a function (cached)."""
    if not func:
        logging.log(RAW, "No function provided for decompilation.")
        return ""
    key = func.getEntryPoint()
    if key in _decompile_cache:
        logging.log(RAW, "Cache hit for function: {}".format(func.getName()))
        return _decompile_cache[key]
    iface = get_decomp_iface()
    logging.log(RAW, "Decompiling function: {}".format(func.getName()))
    res = iface.decompileFunction(func, DECOMPILE_TIMEOUT, monitor)
    if res and res.getDecompiledFunction():
        logging.log(RAW, "Decompilation successful for function: {}".format(func.getName()))
        code = res.getDecompiledFunction().getC()
        _decompile_cache[key] = code
        return code
    logging.log(RAW, "Decompilation failed for function: {}".format(func.getName()))
    _decompile_cache[key] = ""
    return ""

def commit_parameters_and_return_values(func, decomp_result):
    """Commit parameters and return values using HighFunctionDBUtil."""
    tx = currentProgram.startTransaction("Commit Params/Return")
    try:
        high_func = decomp_result.getHighFunction()  # Retrieve HighFunction from the decompilation result
        source_type = SourceType.USER_DEFINED if func.getSignatureSource() == SourceType.USER_DEFINED else SourceType.ANALYSIS
        HighFunctionDBUtil.commitParamsToDatabase(high_func, True, HighFunctionDBUtil.ReturnCommitOption.COMMIT, source_type)
        HighFunctionDBUtil.commitLocalNamesToDatabase(high_func, SourceType.USER_DEFINED);
        currentProgram.endTransaction(tx, True)
        logging.log(RAW, "Parameters and return values committed successfully for function: {}".format(func.getName()))
    except Exception as e:
        logging.error("Failed to commit parameters and return values for function '{}': {}".format(func.getName(), e))
        currentProgram.endTransaction(tx, False)
        return None

def decompile_function_with_commit(func):
    """Decompile a function and commit its parameters and return values."""
    if not func:
        logging.log(RAW, "No function provided for decompilation.")
        return None

    iface = get_decomp_iface()
    logging.log(RAW, "Decompiling function: {}".format(func.getName()))
    res = iface.decompileFunction(func, DECOMPILE_TIMEOUT, monitor)

    if res and res.getDecompiledFunction():
        logging.log(RAW, "Decompilation successful for function: {}".format(func.getName()))
        commit_parameters_and_return_values(func, res)
        return res.getDecompiledFunction().getC()

    logging.log(RAW, "Decompilation failed for function: {}".format(func.getName()))
    return None

def callers_of(func, depth=CALL_TREE_DEPTH_UP):
    seen, out = set(), []
    current_level = [func]

    for _ in range(depth):
        next_level = []
        for f in current_level:
            for ref in getReferencesTo(f.getEntryPoint()):
                caller = getFunctionContaining(ref.getFromAddress())
                if caller and caller.getEntryPoint() not in seen:
                    # Skip external calls
                    if caller.isExternal() or caller.getName() in WHITELISTED_FUNCTIONS:
                        continue
                    seen.add(caller.getEntryPoint())
                    out.append(caller)
                    next_level.append(caller)
        current_level = next_level

    return out


def callees_of(func, depth=CALL_TREE_DEPTH_DOWN):
    """Retrieve callees of a function by scanning the full function body."""
    seen, out = set(), []
    current_level = [func]

    for _ in range(depth):
        next_level = []
        for f in current_level:
            for callee in f.getCalledFunctions(monitor):
                if callee and callee.getEntryPoint() not in seen:
                    if callee.isExternal() or callee.getName() in WHITELISTED_FUNCTIONS:
                        continue
                    seen.add(callee.getEntryPoint())
                    out.append(callee)
                    next_level.append(callee)
        current_level = next_level

    return out

def display_progress_bar(analyzed_count, total_count, current_index=None):
    """Display a progress bar for analyzed functions with optional current index."""
    if total_count == 0:
        return
    percentage = (float(analyzed_count) / total_count) * 100
    progress_blocks = int((percentage / 100) * 30)
    progress_bar = "X" * progress_blocks + "_" * (30 - progress_blocks)
    logging.info("Progress: [{:<30}] {:.2f}% (Function {}/{} analyzed)".format(progress_bar, percentage, analyzed_count, total_count))
   
def get_ai_rename_count(func):
    """Return how many times the function has been AI-renamed (0 if never)."""
    comment = currentProgram.getListing().getComment(CodeUnit.PLATE_COMMENT, func.getEntryPoint())
    if comment is None:
        return 0
    m = re.search(r'\[AI-RENAMED(?:\s+(\d+))?\]', comment)
    if not m:
        return 0
    return int(m.group(1)) if m.group(1) else 1

def has_ai_tag(func):
    """Return True if the function already has the AI-renamed plate comment."""
    return get_ai_rename_count(func) > 0

def get_ai_description(func):
    """Return the plate comment text excluding the [AI-RENAMED] tag line(s)."""
    comment = currentProgram.getListing().getComment(CodeUnit.PLATE_COMMENT, func.getEntryPoint())
    if not comment:
        return ""
    lines = comment.split("\n")
    desc_lines = [l for l in lines if not re.match(r'\s*\[AI-RENAMED(?:\s+\d+)?\]\s*$', l)]
    return "\n".join(desc_lines).strip()

def set_ai_tag(func):
    """Increment the AI-renamed count tag in the function's plate comment."""
    listing = currentProgram.getListing()
    existing = listing.getComment(CodeUnit.PLATE_COMMENT, func.getEntryPoint()) or ""
    count = get_ai_rename_count(func)
    new_count = count + 1
    if new_count == 1:
        new_tag = "[AI-RENAMED]"
    else:
        new_tag = "[AI-RENAMED {}]".format(new_count)
    # Remove any previous AI-RENAMED tag
    cleaned = re.sub(r'\[AI-RENAMED(?:\s+\d+)?\]', '', existing).strip()
    new_comment = (cleaned + "\n" + new_tag).strip() if cleaned else new_tag
    tx = currentProgram.startTransaction("Set AI tag")
    try:
        listing.setComment(func.getEntryPoint(), CodeUnit.PLATE_COMMENT, new_comment)
        currentProgram.endTransaction(tx, True)
    except Exception as e:
        currentProgram.endTransaction(tx, False)
        logging.error("Failed to set AI tag for {}: {}".format(func.getName(), e))

def set_function_description(func, description):
    """Set the AI-generated description as the function's plate comment.

    Preserves any existing plate comment content and the [AI-RENAMED] tag.
    """
    listing = currentProgram.getListing()
    existing = listing.getComment(CodeUnit.PLATE_COMMENT, func.getEntryPoint()) or ""
    # Remove any previous AI description (everything before the tag)
    lines = existing.split("\n")
    kept = [l for l in lines if re.match(r'\[AI-RENAMED(?:\s+\d+)?\]', l.strip())]
    new_comment = description
    if kept:
        new_comment = description + "\n" + "\n".join(kept)
    tx = currentProgram.startTransaction("Set AI description")
    try:
        listing.setComment(func.getEntryPoint(), CodeUnit.PLATE_COMMENT, new_comment.strip())
        currentProgram.endTransaction(tx, True)
        logging.debug("Set description for {}: {}".format(func.getName(), description))
    except Exception as e:
        currentProgram.endTransaction(tx, False)
        logging.error("Failed to set description for {}: {}".format(func.getName(), e))

def ensure_unique_function_name(func, new_name):
    """Ensure the function name is unique by appending a numeric suffix if needed."""
    suffix = 1
    unique_name = new_name
    while any(f.getName() == unique_name for f in currentProgram.getFunctionManager().getFunctions(True)):
        unique_name = "{}_{}".format(new_name, suffix)
        suffix += 1
    return unique_name

def ensure_unique_local_name(func, new_name, exclude_var=None):
    """Ensure the local variable name is unique within the function by appending a numeric suffix if needed."""
    existing = set(l.getName() for l in func.getLocalVariables() if l != exclude_var)
    existing.update(p.getName() for p in func.getParameters() if p != exclude_var)
    suffix = 1
    unique_name = new_name
    while unique_name in existing:
        unique_name = "{}_{}".format(new_name, suffix)
        suffix += 1
    return unique_name

def sanitize_symbol_name(name):
    """Sanitize a name so it is a valid Ghidra symbol identifier.

    Strips C type prefixes the AI sometimes returns (e.g. 'ushort *ptr'),
    removes invalid characters, and ensures the name starts with a letter or
    underscore.
    """
    # If the AI returned something like "type *name", keep only the last token
    if ' ' in name:
        name = name.split()[-1]
    # Strip leading pointer/reference markers
    name = name.lstrip('*&')
    # Replace any remaining invalid chars with underscores
    name = re.sub(r'[^A-Za-z0-9_]', '_', name)
    # Ensure it starts with a letter or underscore
    if name and not re.match(r'^[A-Za-z_]', name):
        name = '_' + name
    return name

def apply_function_renames(func, spec):
    new_name = spec.get("function")
    renamed_params = []
    renamed_locals = []
    if new_name:
        new_name = sanitize_symbol_name(RECEIVED_PREFIX + new_name)
        new_name = ensure_unique_function_name(func, new_name)
        old_name = func.getName()
        if new_name != old_name:
            func.setName(new_name, SourceType.USER_DEFINED)

    for p in func.getParameters():
        tgt = spec.get("parameters", {}).get(p.getName())
        if tgt and tgt != p.getName():
            try:
                old_p = p.getName()
                tgt = sanitize_symbol_name(tgt)
                tgt = ensure_unique_local_name(func, tgt, exclude_var=p)
                p.setName(tgt, SourceType.USER_DEFINED)
                renamed_params.append((old_p, tgt))
            except Exception as e:
                logging.warning("Param {} rename failed: {}".format(p.getName(), e))

    for l in func.getLocalVariables():
        tgt = spec.get("locals", {}).get(l.getName())
        if tgt and tgt != l.getName():
            try:
                old_l = l.getName()
                tgt = sanitize_symbol_name(tgt)
                tgt = ensure_unique_local_name(func, tgt, exclude_var=l)
                l.setName(tgt, SourceType.USER_DEFINED)
                renamed_locals.append((old_l, tgt))
            except Exception as e:
                logging.warning("Local {} rename failed: {}".format(l.getName(), e))

    # Return counts for the recap
    return renamed_params, renamed_locals

def apply_symbol_renames(symbol_type, symbol_map):
    """Apply renames to various symbol types. Returns list of (old, new) tuples."""
    if not symbol_map:
        return []

    type_filter = {
        "label":     SymbolType.LABEL,
        "class":     SymbolType.CLASS,
        "namespace": SymbolType.NAMESPACE,
    }

    st = currentProgram.getSymbolTable()
    renamed = []

    for old, new in symbol_map.items():
        if new == old:
            continue
        for sym in st.getSymbols(old):
            try:
                expected = type_filter.get(symbol_type)
                if expected is not None and sym.getSymbolType() != expected:
                    continue
                sym.setName(new, SourceType.USER_DEFINED)
                renamed.append((old, new))
            except Exception as e:
                logging.error("{} rename failed: {} -> {}: {}".format(symbol_type, old, new, e))

    return renamed


def get_global_variables_used_by_function(func):
    """Retrieve global variables used by a specific function."""
    global_vars = {}
    # Iterate all instructions in the function body to collect references
    body = func.getBody()
    listing = currentProgram.getListing()
    references = []
    for instr in listing.getInstructions(body, True):
        for ref in instr.getReferencesFrom():
            references.append(ref)

    for ref in references:
        to_addr = ref.getToAddress()
        data = getDataAt(to_addr)
        if data is None:
            continue
        symbol = getSymbolAt(to_addr)
        if symbol is None:
            continue
        try:
            dt = data.getDataType()
            dt_name = dt.getName() if dt else "unknown"
            val = data.getValue()
            global_vars[symbol.getName()] = {
                "type": dt_name,
                "value": str(val) if val is not None else ""
            }
            logging.debug("Global variable found: {} (type={}, value={})".format(symbol.getName(), dt_name, val))
            # Track undefined globals for batch retyping
            if OPT_RETYPE_GLOBALS and dt_name.startswith("undefined"):
                addr_hex = str(to_addr)
                if addr_hex not in _undefined_globals:
                    _undefined_globals[addr_hex] = {
                        "name": symbol.getName(),
                        "type": dt_name,
                        "value": str(val) if val is not None else "",
                        "funcs": []
                    }
                _undefined_globals[addr_hex]["name"] = symbol.getName()
                if func.getName() not in _undefined_globals[addr_hex]["funcs"]:
                    _undefined_globals[addr_hex]["funcs"].append(func.getName())
        except Exception as e:
            logging.warning("Failed to retrieve details for global variable '{}': {}".format(symbol.getName(), e))

    return global_vars

def resolve_data_type(type_name):
    """Resolve a C type name string to a Ghidra DataType, or None."""
    from ghidra.program.model.data import (
        IntegerDataType, UnsignedIntegerDataType,
        LongDataType, UnsignedLongDataType,
        ShortDataType, UnsignedShortDataType,
        CharDataType, ByteDataType,
        FloatDataType, DoubleDataType,
        BooleanDataType, PointerDataType
    )
    t = type_name.strip()
    if t.endswith("*"):
        return PointerDataType()
    mapping = {
        "int": IntegerDataType, "int32_t": IntegerDataType, "signed int": IntegerDataType,
        "uint32_t": UnsignedIntegerDataType, "unsigned int": UnsignedIntegerDataType,
        "long": LongDataType, "unsigned long": UnsignedLongDataType,
        "short": ShortDataType, "int16_t": ShortDataType,
        "unsigned short": UnsignedShortDataType, "uint16_t": UnsignedShortDataType,
        "char": CharDataType, "int8_t": CharDataType,
        "byte": ByteDataType, "uint8_t": ByteDataType, "unsigned char": ByteDataType,
        "float": FloatDataType, "double": DoubleDataType,
        "bool": BooleanDataType, "boolean": BooleanDataType,
    }
    cls = mapping.get(t.lower())
    return cls() if cls else None

def batch_retype_globals():
    """Send accumulated undefined globals to AI for type suggestions and apply them."""
    global _undefined_globals
    if not _undefined_globals:
        return
    logging.info("Batch retyping {} undefined globals...".format(len(_undefined_globals)))
    context = {"__retype_globals__": {}}
    for addr_hex, info in _undefined_globals.items():
        context["__retype_globals__"][info["name"]] = {
            "address": addr_hex,
            "current_type": info["type"],
            "value": info["value"],
            "used_in_functions": info["funcs"]
        }
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w")
    tmp.write(json.dumps(context, indent=4))
    tmp.close()
    process = subprocess.Popen(
        [PYTHON_EXECUTABLE, OPENAI_CONNECTOR_SCRIPT, tmp.name,
         "--output_file", RENAMED_SYMBOLS_FILE,
         "--model", OPT_MODEL,
         "--retype_globals"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )
    for line in process.stdout:
        line = line.strip()
        if "- error -" in line.lower():
            logging.error(line)
        else:
            logging.log(RAW, line)
    process.wait()
    try:
        os.remove(tmp.name)
    except OSError:
        pass
    if process.returncode != 0:
        logging.error("Global retyping script failed with exit code {}.".format(process.returncode))
        _undefined_globals.clear()
        return
    with open(os.path.abspath(RENAMED_SYMBOLS_FILE), "r") as f:
        try:
            results = json.load(f)
        except ValueError:
            logging.error("Failed to parse retyping response.")
            _undefined_globals.clear()
            return
    type_results = results.get("__retype_globals__", results)
    applied = 0
    tx = currentProgram.startTransaction("Retype globals")
    try:
        for var_name, suggested_type in type_results.items():
            addr_hex = None
            for a, info in _undefined_globals.items():
                if info["name"] == var_name:
                    addr_hex = a
                    break
            if not addr_hex:
                continue
            dt = resolve_data_type(suggested_type)
            if dt is None:
                logging.warning("Unknown type '{}' for {}, skipping".format(suggested_type, var_name))
                continue
            orig_type = _undefined_globals[addr_hex]["type"]
            m = re.match(r"undefined(\d+)", orig_type)
            if m:
                orig_size = int(m.group(1))
                if dt.getLength() != orig_size:
                    logging.warning("Size mismatch for {}: {} bytes vs {} bytes, skipping".format(
                        var_name, orig_size, dt.getLength()))
                    continue
            addr = toAddr(addr_hex)
            try:
                clearListing(addr, addr.add(dt.getLength() - 1))
                createData(addr, dt)
                applied += 1
                logging.debug("  Retyped {} -> {}".format(var_name, suggested_type))
            except Exception as e:
                logging.warning("Failed to retype {}: {}".format(var_name, e))
    finally:
        currentProgram.endTransaction(tx, True)
    logging.info("Retyped {}/{} undefined globals".format(applied, len(type_results)))
    _undefined_globals.clear()

def prepare_context_for_openai(func):
    """Prepare decompiled code, function context, and global variables for a single function."""
    func_name = func.getName()
    decompiled_code = decompile_function(func)
    
    # Include decompiled code for callers
    callers = {
        caller.getName(): decompile_function(caller) for caller in callers_of(func)
    }
    
    # Include decompiled code for callees
    callees = {
        callee.getName(): decompile_function(callee) for callee in callees_of(func)
    }
    
    global_vars = get_global_variables_used_by_function(func)

    context = {
        func_name: {
            "decompiled_code": decompiled_code,
            "callers": callers,
            "callees": callees,
            "global_variables": global_vars,
        }
    }

    # Write context to a temporary file
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w")
    tmp.write(json.dumps(context, indent=4))
    tmp.close()

    return tmp.name

def run_external_script_with_context(func):
    """Run the external script with context for a single function and flush events after renaming."""
    try:
        if OPT_SKIP_TAGGED and has_ai_tag(func):
            # Force re-process if name or description matches the user-supplied regex
            if OPT_FORCE_RENAME_PATTERN and (
                OPT_FORCE_RENAME_PATTERN.search(func.getName()) or
                OPT_FORCE_RENAME_PATTERN.search(get_ai_description(func))
            ):
                logging.info("Re-processing tagged function {} (matches force pattern '{}')".format(
                    func.getName(), OPT_FORCE_RENAME_PATTERN.pattern))
            # Re-process when the description is too short
            elif OPT_DONT_SKIP_SHORT_DESC > 0:
                desc = get_ai_description(func)
                if len(desc) <= OPT_DONT_SKIP_SHORT_DESC:
                    logging.info("Re-processing tagged function {} (description is {} chars, threshold is {})".format(
                        func.getName(), len(desc), OPT_DONT_SKIP_SHORT_DESC))
                else:
                    logging.info("Skipping AI call for already-tagged function: {}".format(func.getName()))
                    return
            else:
                logging.info("Skipping AI call for already-tagged function: {}".format(func.getName()))
                return

        if OPT_SKIP_AFTER_N > 0:
            rename_count = get_ai_rename_count(func)
            if rename_count >= OPT_SKIP_AFTER_N:
                logging.info("Skipping function {} (already renamed {} time(s), limit is {})".format(
                    func.getName(), rename_count, OPT_SKIP_AFTER_N))
                return

        context_file = prepare_context_for_openai(func)
        logging.log(RAW, "Context file created at: {}".format(context_file))
        logging.log(RAW, "Running external script: {} with context file {}...".format(OPENAI_CONNECTOR_SCRIPT, context_file))

        process = subprocess.Popen(
            [PYTHON_EXECUTABLE, OPENAI_CONNECTOR_SCRIPT, context_file,
             "--output_file", RENAMED_SYMBOLS_FILE,
             "--model", OPT_MODEL]
            + (["--add_description"] if OPT_ADD_DESCRIPTION else [])
            + (["--long_description"] if OPT_LONG_DESCRIPTION else [])
            + (["--desc_insight"] if OPT_DESC_INSIGHT else [])
            + (["--send_context_code"] if OPT_SEND_CONTEXT_CODE else []),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Merge stdout and stderr
            universal_newlines=True
        )

        for line in process.stdout:
            line = line.strip()
            if "- error -" in line.lower():
                logging.error(line)
            else:
                logging.log(RAW, line)

        process.wait()

        # Clean up temp context file
        try:
            os.remove(context_file)
        except OSError:
            pass

        if process.returncode != 0:
            logging.error("External script failed with exit code {}.".format(process.returncode))
            return

        logging.log(RAW, "External script executed successfully.")
        # Parse the response and apply renames
        renamed_symbols_path = os.path.abspath(RENAMED_SYMBOLS_FILE)
        with open(renamed_symbols_path, "r") as f:
            try:
                renamed_symbols = json.load(f)
            except ValueError as e:
                logging.error("Failed to parse JSON: {}".format(e))
                renamed_symbols = {}

        # Extract the function-specific data using the key-based structure
        func_key = func.getName()
        func_renames = renamed_symbols.get(func_key, {})
        transaction = currentProgram.startTransaction("Rename Variables")
        try:
            renamed_params, renamed_locals = apply_function_renames(func, func_renames)
            renamed_globals    = apply_symbol_renames("global",    func_renames.get("globals", {}))
            renamed_labels     = apply_symbol_renames("label",     func_renames.get("labels", {}))
            renamed_classes    = apply_symbol_renames("class",     func_renames.get("classes", {}))
            renamed_namespaces = apply_symbol_renames("namespace", func_renames.get("namespaces", {}))
            renamed_enums      = apply_symbol_renames("enum",      func_renames.get("enums", {}))
            renamed_structs    = apply_symbol_renames("struct",    func_renames.get("structs", {}))
            renamed_typedefs   = apply_symbol_renames("typedef",   func_renames.get("typedefs", {}))
        finally:
            currentProgram.endTransaction(transaction, True)
        # Invalidate cache so future callers/callees see updated names
        _decompile_cache.pop(func.getEntryPoint(), None)

        # Build a prominent banner for the rename result
        new_name = func_renames.get("function", "")
        desc = func_renames.get("description", "") if OPT_ADD_DESCRIPTION else ""
        banner_line = "#### {} -> {}".format(func_key, new_name if new_name else func.getName())
        if desc:
            banner_line += "  |  {}".format(desc)
        logging.info("####################################################################")
        logging.info(banner_line)
        logging.info("####################################################################")

        # Clean DEBUG recap of all renames
        def _recap(category, items):
            for old, new in items:
                logging.debug("  {:>12}  {} -> {}".format(category, old, new))

        _recap("param",     renamed_params)
        _recap("local",     renamed_locals)
        _recap("global",    renamed_globals)
        _recap("label",     renamed_labels)
        _recap("class",     renamed_classes)
        _recap("namespace", renamed_namespaces)
        _recap("enum",      renamed_enums)
        _recap("struct",    renamed_structs)
        _recap("typedef",   renamed_typedefs)

        total_renames = (len(renamed_params) + len(renamed_locals) + len(renamed_globals)
                         + len(renamed_labels) + len(renamed_classes) + len(renamed_namespaces)
                         + len(renamed_enums) + len(renamed_structs) + len(renamed_typedefs))
        if total_renames > 0:
            logging.debug("  ----------  {} symbol(s) renamed total".format(total_renames))
        else:
            logging.debug("  (no symbols renamed)")

        if desc:
            set_function_description(func, desc)
        if OPT_ENABLE_TAGGING:
            set_ai_tag(func)
    
    except Exception as e:
        logging.error("Error running external script: {}".format(e))
        return

    # exit(0)
def log_program_info():
    """Log detailed information about the current program at startup."""
    try:
        logging.debug("Program Information:")
        logging.debug("Program Name: {}".format(currentProgram.getName()))
        logging.debug("Program Image Base: {}".format(currentProgram.getImageBase()))
        logging.debug("Program Creation Date: {}".format(currentProgram.getCreationDate()))
        fm = currentProgram.getFunctionManager()
        internal_count = len(list(fm.getFunctions(True)))
        external_count = len(list(fm.getExternalFunctions()))
        logging.info("Functions: {} internal + {} external ({} total) | Symbols: {} | Memory Blocks: {}".format(
            internal_count,
            external_count,
            internal_count + external_count,
            len(list(currentProgram.getSymbolTable().getAllSymbols(True))),
            len(list(currentProgram.getMemory().getBlocks()))
        ))
    except Exception as e:
        logging.error("Failed to retrieve program information: {}".format(e))

def count_outgoing_calls(func):
    """Return the number of distinct non-external, non-whitelisted functions called."""
    count = 0
    for callee in func.getCalledFunctions(monitor):
        if not callee.isExternal() and callee.getName() not in WHITELISTED_FUNCTIONS:
            count += 1
    return count

def collect_call_tree(root_func):
    """Build the full call tree iteratively and return the list of functions.

    The returned list is in discovery order (root first, leaves last).
    Reverse it for bottom-up processing.
    """
    visited = set()
    ordered = []
    stack = [root_func]

    while stack:
        current_func = stack.pop()
        addr = current_func.getEntryPoint()
        if addr in visited or current_func.isExternal() or current_func.getName() in WHITELISTED_FUNCTIONS:
            continue
        visited.add(addr)
        ordered.append(current_func)
        for callee in callees_of(current_func):
            if callee.getEntryPoint() not in visited:
                stack.append(callee)

    return ordered

def traverse_and_analyze_functions(func_list):
    """Analyze a list of functions.

    If OPT_BOTTOM_UP is set, the list is sorted by fewest outgoing calls
    so leaf functions are processed first.
    """
    total_functions = len(func_list)

    if OPT_BOTTOM_UP:
        func_list.sort(key=lambda f: count_outgoing_calls(f))
        logging.info("Processing order: bottom-up (sorted by fewest outgoing calls, {} functions)".format(len(func_list)))
    else:
        logging.info("Processing order: top-down (root first, {} functions)".format(len(func_list)))

    # Use entry point addresses for tracking — Ghidra returns different
    # proxy objects from each iterator, so object identity comparisons fail.
    analyzed_addresses = set()
    for current_func in func_list:
        addr = current_func.getEntryPoint()
        if addr in analyzed_addresses:
            continue
        logging.log(RAW, "Analyzing function: {}".format(current_func.getName()))
        decompile_function_with_commit(current_func)
        run_external_script_with_context(current_func)
        analyzed_addresses.add(addr)
        logging.log(RAW, "Function {} analyzed. Total analyzed: {}".format(current_func.getName(), len(analyzed_addresses)))
        display_progress_bar(len(analyzed_addresses), total_functions)

        # Check if we should batch retype undefined globals
        if OPT_RETYPE_GLOBALS and len(_undefined_globals) >= GLOBAL_RETYPE_THRESHOLD:
            batch_retype_globals()

    return analyzed_addresses

def annotate_orphan_code_blocks():
    """Find orphan code blocks and annotate them with AI-generated plate comments.

    Walks executable memory, groups consecutive instructions not covered by
    any function into blocks, sends their disassembly to the AI, and writes
    plate comments with a description and suggested function name.
    No program structure is altered — only comments are added.
    """
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()

    blocks = []  # list of (start_addr, end_addr, disassembly_text)

    for mem_block in currentProgram.getMemory().getBlocks():
        if not mem_block.isExecute():
            continue
        current_block_start = None
        current_block_end = None
        current_block_lines = []
        skip_current_block = False

        for instr in listing.getInstructions(mem_block.getStart(), True):
            if instr.getMinAddress().compareTo(mem_block.getEnd()) > 0:
                break
            if fm.getFunctionContaining(instr.getMinAddress()) is None:
                if skip_current_block:
                    continue
                if current_block_start is None:
                    # Skip blocks already annotated
                    existing = listing.getComment(CodeUnit.PLATE_COMMENT, instr.getMinAddress())
                    if existing and "[ORPHAN CODE BLOCK]" in existing:
                        skip_current_block = True
                        continue
                    current_block_start = instr.getMinAddress()
                current_block_end = instr.getMaxAddress()
                current_block_lines.append("{} {}".format(instr.getMinAddress(), instr))
            else:
                if current_block_start is not None:
                    blocks.append((current_block_start, current_block_end, "\n".join(current_block_lines)))
                current_block_start = None
                current_block_end = None
                current_block_lines = []
                skip_current_block = False

        if current_block_start is not None:
            blocks.append((current_block_start, current_block_end, "\n".join(current_block_lines)))

    if not blocks:
        logging.info("No orphan code blocks found.")
        return

    # Filter out small blocks
    before_filter = len(blocks)
    blocks = [(addr, end, disasm) for addr, end, disasm in blocks if len(disasm) >= OPT_ORPHAN_MIN_SIZE]
    logging.info("Found {} orphan code block(s), {} meet min size of {} chars".format(
        before_filter, len(blocks), OPT_ORPHAN_MIN_SIZE))

    if not blocks:
        return

    total_applied = 0
    total_blocks = len(blocks)
    for batch_start in range(0, total_blocks, ANNOTATE_BLOCK_BATCH_SIZE):
        batch = blocks[batch_start:batch_start + ANNOTATE_BLOCK_BATCH_SIZE]
        batch_num = (batch_start // ANNOTATE_BLOCK_BATCH_SIZE) + 1
        total_batches = (total_blocks + ANNOTATE_BLOCK_BATCH_SIZE - 1) // ANNOTATE_BLOCK_BATCH_SIZE
        display_progress_bar(batch_start, total_blocks)
        logging.info("Orphan batch {}/{} ({} blocks)".format(batch_num, total_batches, len(batch)))
        context = {"__annotate_blocks__": {}}
        for start_addr, end_addr, disasm in batch:
            # Gather context: callees, callers, and strings
            callees_names = []
            callers_names = []
            strings_found = []
            for instr in listing.getInstructions(start_addr, True):
                if instr.getMinAddress().compareTo(end_addr) > 0:
                    break
                for ref in instr.getReferencesFrom():
                    target = ref.getToAddress()
                    target_func = fm.getFunctionAt(target)
                    if target_func and target_func.getName() not in callees_names:
                        callees_names.append(target_func.getName())
                    # Check for string references
                    data = getDataAt(target)
                    if data and data.hasStringValue():
                        s = str(data.getValue())
                        if s and len(s) > 1 and s not in strings_found:
                            strings_found.append(s)
            # Find who references into this block
            for ref in getReferencesTo(start_addr):
                caller = getFunctionContaining(ref.getFromAddress())
                if caller and caller.getName() not in callers_names:
                    callers_names.append(caller.getName())

            block_info = {"disassembly": disasm}
            if callees_names:
                block_info["calls"] = callees_names
            if callers_names:
                block_info["called_by"] = callers_names
            if strings_found:
                block_info["strings"] = strings_found[:20]  # cap at 20
            context["__annotate_blocks__"][str(start_addr)] = block_info

        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w")
        tmp.write(json.dumps(context, indent=4))
        tmp.close()

        process = subprocess.Popen(
            [PYTHON_EXECUTABLE, OPENAI_CONNECTOR_SCRIPT, tmp.name,
             "--output_file", RENAMED_SYMBOLS_FILE,
             "--model", OPT_MODEL,
             "--annotate_block"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        for line in process.stdout:
            line = line.strip()
            if "- error -" in line.lower():
                logging.error(line)
            else:
                logging.log(RAW, line)
        process.wait()

        try:
            os.remove(tmp.name)
        except OSError:
            pass

        if process.returncode != 0:
            logging.error("Block annotation failed with exit code {}.".format(process.returncode))
            continue

        with open(os.path.abspath(RENAMED_SYMBOLS_FILE), "r") as f:
            try:
                results = json.load(f)
            except ValueError:
                logging.error("Failed to parse annotation response.")
                continue

        annotations = results.get("__annotate_blocks__", results)
        tx = currentProgram.startTransaction("Annotate orphan blocks")
        try:
            for addr_hex, info in annotations.items():
                desc = info.get("description", "")
                name = info.get("suggested_name", "")
                if not desc and not name:
                    continue
                comment = "[ORPHAN CODE BLOCK]"
                if desc:
                    comment += "\n{}".format(desc)
                if name:
                    comment += "\nSuggested function name: {}".format(name)
                addr = toAddr(addr_hex)
                listing.setComment(addr, CodeUnit.PLATE_COMMENT, comment)
                total_applied += 1
                logging.info("Annotated block at {}: {} -> {}".format(
                    addr_hex, name, desc[:80] if desc else ""))
        finally:
            currentProgram.endTransaction(tx, True)

    display_progress_bar(total_blocks, total_blocks)
    logging.info("Annotated {}/{} orphan code blocks".format(total_applied, total_blocks))

def garbage_collect_unanalyzed_functions(analyzed_addresses):
    """Analyze functions that were not covered during traversal."""
    for func in currentProgram.getFunctionManager().getFunctions(True):
        addr = func.getEntryPoint()
        if addr not in analyzed_addresses and not func.isExternal() and func.getName() not in WHITELISTED_FUNCTIONS:
            logging.info("Garbage collecting function: {}".format(func.getName()))
            newly_analyzed = traverse_and_analyze_functions(collect_call_tree(func))
            analyzed_addresses.update(newly_analyzed)

def fetch_available_models():
    """Call handleOpenAi.py --list_models to get available models with pricing."""
    try:
        process = subprocess.Popen(
            [PYTHON_EXECUTABLE, OPENAI_CONNECTOR_SCRIPT, "--list_models"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            logging.error("Failed to fetch models: {}".format(stderr.strip()))
            return None
        return json.loads(stdout.strip())
    except Exception as e:
        logging.error("Error fetching models: {}".format(e))
        return None

def build_model_selection_prompt(models):
    """Build choice labels with inline pricing for the askChoice dropdown."""
    choices = []       # Display labels for the dropdown
    model_ids = []     # Raw model IDs to resolve after selection
    for m in models:
        mid = m["id"]
        if m["input"] is not None:
            label = "{} | in ${:.3f} | cached ${:.3f} | out ${:.3f}".format(
                mid, m["input"], m["cached_input"], m["output"])
        else:
            label = "{} | pricing N/A".format(mid)
        choices.append(label)
        model_ids.append(mid)
    return choices, model_ids

def check_python_available():
    """Check whether the configured Python executable is reachable."""
    try:
        process = subprocess.Popen(
            [PYTHON_EXECUTABLE, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        process.communicate()
        return process.returncode == 0
    except Exception:
        return False

def main():
    global OPT_ENABLE_TAGGING, OPT_SKIP_TAGGED, OPT_SKIP_AFTER_N, OPT_DONT_SKIP_SHORT_DESC, OPT_FORCE_RENAME_PATTERN, OPT_BOTTOM_UP, OPT_ADD_DESCRIPTION, OPT_LONG_DESCRIPTION, OPT_DESC_INSIGHT, OPT_MODEL, OPT_RESUME, OPT_SEND_CONTEXT_CODE, OPT_RETYPE_GLOBALS, OPT_ANNOTATE_ORPHANS, OPT_ORPHAN_MIN_SIZE, OPT_LOG_LEVEL
    try:
        logging.info("Starting the AI-assisted renaming process...")

        if not check_python_available():
            popup("Python executable '{}' was not found.\n\n"
                  "Please install Python 3 or update the PYTHON_EXECUTABLE\n"
                  "constant at the top of AIGhidra.py to point to your\n"
                  "Python 3 interpreter.".format(PYTHON_EXECUTABLE))
            return

        if currentProgram is None:
            logging.error("No program is open. Please open a binary in Ghidra first.")
            return

        log_level_input = askString(
            "Log Level",
            "Enter log level (RAW, DEBUG, INFO, WARNING, ERROR):",
            "INFO"
        )
        level_map = {"RAW": RAW, "DEBUG": logging.DEBUG, "INFO": logging.INFO, "WARNING": logging.WARNING, "ERROR": logging.ERROR}
        OPT_LOG_LEVEL = level_map.get(log_level_input.strip().upper(), logging.INFO)
        logging.getLogger().setLevel(OPT_LOG_LEVEL)
        stdout_handler.setLevel(OPT_LOG_LEVEL)

        OPT_RESUME = askYesNo(
            "Resume",
            "Resume from a previous run?\n\n"
            "YES = Skip functions already marked [AI-RENAMED].\n"
            "Functions with short or missing descriptions can still\n"
            "be re-processed (you will be asked next).\n\n"
            "NO = Process all functions from scratch."
        )

        if OPT_RESUME:
            OPT_SKIP_TAGGED = True
            logging.info("Resume mode: skip tagged ON")

            skip_n_input = askString(
                "Skip After N Renames",
                "Skip functions already renamed N times or more.\n\n"
                "Enter N (e.g. 2 = skip after 2 renames),\n"
                "or 0 to never skip based on count.",
                "0"
            )
            try:
                OPT_SKIP_AFTER_N = int(skip_n_input.strip())
            except ValueError:
                OPT_SKIP_AFTER_N = 0

            short_desc_input = askString(
                "Re-process Short Descriptions",
                "Don't skip tagged functions whose description is\n"
                "this many characters or shorter (excluding the\n"
                "[AI-RENAMED] tag).\n\n"
                "This lets you re-run functions that got a poor or\n"
                "empty description on a previous pass.\n\n"
                "Enter max length (e.g. 20), or 0 to disable.",
                "0"
            )
            try:
                OPT_DONT_SKIP_SHORT_DESC = int(short_desc_input.strip())
            except ValueError:
                OPT_DONT_SKIP_SHORT_DESC = 0

            force_pattern_input = askString(
                "Force Re-process Pattern",
                "Regex to force re-process tagged functions whose\n"
                "name or description matches (case-insensitive).\n\n"
                "Example: FUN_|param_1\n\n"
                "Enter #disabled to skip.",
                "#disabled"
            )
            if force_pattern_input.strip() != "#disabled":
                try:
                    OPT_FORCE_RENAME_PATTERN = re.compile(force_pattern_input.strip(), re.IGNORECASE)
                    logging.info("Force re-process pattern: {}".format(OPT_FORCE_RENAME_PATTERN.pattern))
                except re.error as e:
                    logging.warning("Invalid regex '{}': {} — filter disabled".format(force_pattern_input.strip(), e))
                    OPT_FORCE_RENAME_PATTERN = None
        OPT_BOTTOM_UP      = askYesNo(
            "Processing Order",
            "Process functions bottom-up (leaves first)?\n\n"
            "YES = Bottom-up: leaf functions are renamed first, so when a\n"
            "parent function is analyzed its callees already have meaningful\n"
            "names, giving the AI much better context.\n\n"
            "NO = Top-down: the entry function is analyzed first, then its\n"
            "callees. Faster feedback, but callee names are still generic\n"
            "when the parent is processed."
        )
        OPT_ADD_DESCRIPTION = askYesNo(
            "Function Descriptions",
            "Add AI-generated function descriptions as plate comments?\n\n"
            "The AI will write a summary of what each function does\n"
            "and it will appear as a plate comment above the function.\n\n"
            "Note: this adds a small amount of extra output tokens per request."
        )
        if OPT_ADD_DESCRIPTION:
            OPT_LONG_DESCRIPTION = askYesNo(
                "Longer Descriptions",
                "Use longer, more detailed descriptions?\n\n"
                "YES = Multi-line description covering purpose, inputs,\n"
                "outputs, side effects, and key logic.\n\n"
                "NO = One-line concise summary."
            )
            OPT_DESC_INSIGHT = askYesNo(
                "Program Insight",
                "Include an insight on why this function matters?\n\n"
                "YES = The description will also explain the function's\n"
                "role and importance within the larger program, based\n"
                "on its callers and callees.\n\n"
                "NO = Description only covers what the function does."
            )
        OPT_SEND_CONTEXT_CODE = askYesNo(
            "Send Caller/Callee Code",
            "Send decompiled code of callers and callees to the AI?\n\n"
            "YES = The AI receives the full decompiled code of each\n"
            "caller and callee, giving it much richer context for\n"
            "choosing meaningful names. Uses more input tokens.\n\n"
            "NO = Only caller/callee names are sent (cheaper but\n"
            "the AI has less context)."
        )
        OPT_RETYPE_GLOBALS = askYesNo(
            "Retype Globals",
            "Auto-retype undefined global variables?\n\n"
            "YES = Collect globals with undefined types (undefined1,\n"
            "undefined4, etc.) and after every {} found, ask the AI\n"
            "to suggest proper C types based on their names and values.\n\n"
            "NO = Leave global variable types unchanged.".format(GLOBAL_RETYPE_THRESHOLD)
        )
        OPT_ANNOTATE_ORPHANS = askYesNo(
            "Annotate Orphan Code Blocks",
            "Annotate orphan code blocks with AI-generated comments?\n\n"
            "Orphan blocks are instruction sequences not covered by\n"
            "any recognized function. The AI will analyze their\n"
            "assembly and add a plate comment with a description\n"
            "and a suggested function name.\n\n"
            "Only blocks with at least N chars of disassembly are\n"
            "included (you will be asked next).\n\n"
            "This does NOT alter program structure \u2014 only adds comments."
        )
        if OPT_ANNOTATE_ORPHANS:
            orphan_min_input = askString(
                "Orphan Block Min Size",
                "Minimum disassembly size (in characters) for an\n"
                "orphan block to be annotated. Smaller blocks are\n"
                "skipped.\n\n"
                "Default: 1000 (roughly 30+ instructions).",
                str(ORPHAN_BLOCK_MIN_SIZE)
            )
            try:
                OPT_ORPHAN_MIN_SIZE = max(0, int(orphan_min_input.strip()))
            except ValueError:
                OPT_ORPHAN_MIN_SIZE = ORPHAN_BLOCK_MIN_SIZE

        # --- Model selection ---
        logging.debug("Fetching available models from OpenAI...")
        available_models = fetch_available_models()
        if available_models and len(available_models) > 0:
            choices, model_ids = build_model_selection_prompt(available_models)
            # Print the table to the console where it renders properly
            print("")
            print("=" * 60)
            print("  AVAILABLE MODELS  (prices per 1M tokens, USD)")
            print("=" * 60)
            print("  {:<20} {:>8} {:>8} {:>8}".format("Model", "Input", "Cached", "Output"))
            print("  " + "-" * 54)
            for label, mid in zip(choices, model_ids):
                m = next(x for x in available_models if x["id"] == mid)
                if m["input"] is not None:
                    print("  {:<20} {:>7.3f}  {:>7.3f}  {:>7.3f}".format(
                        mid, m["input"], m["cached_input"], m["output"]))
                else:
                    print("  {:<20} {:>8} {:>8} {:>8}".format(mid, "N/A", "N/A", "N/A"))
            print("=" * 60)
            print("")

        model_input = askString(
            "Model Selection",
            "Enter the model name.\nSee the console for the list of available models with pricing.",
            "gpt-4o-mini"
        )
        OPT_MODEL = model_input.strip() if model_input and model_input.strip() else "gpt-4o-mini"
        logging.info("Selected model: {}".format(OPT_MODEL))

        log_program_info()

        # Prompt user to enter the root function for the call tree
        if OPT_BOTTOM_UP:
            func_prompt = (
                "Enter a ROOT function, or * for all functions.\n\n"
                "Bottom-up mode: functions are sorted by fewest outgoing\n"
                "calls (leaves first). If you enter *, every non-external\n"
                "function in the program is included."
            )
            func_name = askString("Function Name", func_prompt, "*")
        else:
            func_prompt = (
                "Enter the name of the function to start analysis with.\n\n"
                "Top-down mode: this function will be analyzed first,\n"
                "then its callees."
            )
            func_name = askString("Function Name", func_prompt)

        if OPT_BOTTOM_UP and func_name.strip() == "*":
            # Collect all eligible functions
            all_funcs = [
                f for f in currentProgram.getFunctionManager().getFunctions(True)
                if not f.isExternal() and f.getName() not in WHITELISTED_FUNCTIONS
            ]
            logging.info("Bottom-up: collected {} functions from entire program".format(len(all_funcs)))
            analyzed_functions = traverse_and_analyze_functions(all_funcs)
        else:
            entry_func = None
            for func in currentProgram.getFunctionManager().getFunctions(True):
                if func.getName() == func_name:
                    entry_func = func
                    break

            if not entry_func:
                logging.error("Function '{}' not found.".format(func_name))
                return

            logging.info("Starting traversal with function: {}".format(entry_func.getName()))
            call_tree = collect_call_tree(entry_func)
            analyzed_functions = traverse_and_analyze_functions(call_tree)

        logging.info("Starting garbage collection for unanalyzed functions...")
        garbage_collect_unanalyzed_functions(analyzed_functions)

        # Final batch retype for any remaining globals below threshold
        if OPT_RETYPE_GLOBALS and _undefined_globals:
            batch_retype_globals()

        # Annotate orphan code blocks after all renaming is done
        if OPT_ANNOTATE_ORPHANS:
            annotate_orphan_code_blocks()

        log_program_info()
        logging.info("Renames applied successfully.")

    except Exception as e:
        logging.error("Error: {}".format(e))
        return

if __name__ == "__main__":
    main()
