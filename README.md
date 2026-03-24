# Ghidra-AI-AutoRename-Plugin

**Fully automatic AI-powered symbol renaming for Ghidra. Hit run, walk away, come back to a fully renamed binary — every function, parameter, variable, global, and type given a meaningful name by OpenAI.**

Turn `FUN_004012a0(undefined4 param_1, int param_2)` into `decryptPayload(byte *encryptedBuffer, int bufferLength)` — across your entire binary, with zero manual effort.

## How It Works

1. **AIGhidra.py** runs inside Ghidra's **Python 2.7 (Jython)** scripting engine.  
   It decompiles each function, collects its callers, callees, and global variables, then shells out to an external Python 3 script.

2. **handleOpenAi.py** runs with your **system Python 3.x**.  
   It calls the OpenAI API, receives rename suggestions in JSON, and writes them to a temp file that AIGhidra reads back.

3. Renames are applied inside a Ghidra transaction — function names, parameters, locals, globals, labels, classes, namespaces, enums, structs, and typedefs.

### Why two Python versions?

Ghidra's built-in scripting engine uses **Jython (Python 2.7)**. All Ghidra API calls (`currentProgram`, `DecompInterface`, `askYesNo`, etc.) must run under that interpreter — there is no way around it.

The OpenAI Python SDK (`openai >= 1.0`) **requires Python 3.8+** and is completely incompatible with Python 2.7. The same is true for most modern Python packages (e.g. `tqdm`, `httpx`).

To bridge the gap, `AIGhidra.py` (Jython 2.7) spawns `handleOpenAi.py` as a **subprocess** using your system's Python 3 interpreter. The two scripts communicate through temporary JSON files — no shared runtime is needed.

**In short:**

| Component | Interpreter | Why |
|---|---|---|
| `AIGhidra.py` | Jython 2.7 (Ghidra) | Must use Ghidra's scripting API |
| `handleOpenAi.py` | Python 3.8+ (system) | OpenAI SDK and modern packages require Python 3 |

## Features

- **Bottom-up analysis** — leaf functions renamed first so parent context is richer.
- **Resume mode** — skip already-processed functions on re-runs.
- **AI rename counting** — tracks how many times each function was AI-renamed (`[AI-RENAMED]`, `[AI-RENAMED 2]`, …). Optionally skip functions renamed N+ times.
- **Function descriptions** — optional one-line or detailed plate comments.
- **Program insight** — explains why a function matters in context.
- **Batch global retyping** — collects `undefined*` globals and asks the AI to suggest proper C types.
- **Orphan code block annotation** — finds instruction sequences not covered by any function, sends their disassembly to the AI, and adds plate comments with a description and suggested function name. Only large blocks are processed (configurable minimum size). Already-annotated blocks are skipped on re-runs. Does not alter program structure.
- **Multiple log levels** — RAW, DEBUG, INFO, WARNING, ERROR.
- **Model selection** — choose any OpenAI chat model with pricing info displayed.

## Setup

### Prerequisites

- [Ghidra](https://ghidra-sre.org/) (tested with 10.x / 11.x)
- **Python 3.8+** installed on your system (separate from Ghidra's Jython)
- An OpenAI API key

### Installing Python 3 dependencies

> **Important:** The packages in `requirements.txt` must be installed in your **Python 3** environment, **not** in Ghidra's Jython. Ghidra's Jython 2.7 cannot run the OpenAI SDK or any of the other dependencies listed below.

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/AIGhidra.git
cd AIGhidra
```

Install the dependencies using your **Python 3** pip. Pick whichever matches your setup:

```bash
# If "python" on your PATH is Python 3:
pip install -r requirements.txt

# If you need to be explicit:
python3 -m pip install -r requirements.txt

# Or inside a virtual environment (recommended):
python3 -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux / macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

Current dependencies (`requirements.txt`):
| Package | Min version | Purpose |
|---|---|---|
| `openai` | >= 1.0.0 | OpenAI API client |
| `tqdm` | any | Progress bars in console |

If you use a virtual environment, make sure `PYTHON_EXECUTABLE` in `AIGhidra.py` points to the venv's Python binary:

| OS | Example path |
|---|---|
| Windows | `C:\Users\YOU\Code\AIGhidra\.venv\Scripts\python.exe` |
| Linux / macOS | `/home/you/Code/AIGhidra/.venv/bin/python` |

### API key

You need an OpenAI API key to use AIGhidra. Here's how to get one:

1. Go to [platform.openai.com](https://platform.openai.com/) and sign in (or create an account).
2. Navigate to **API keys** ([platform.openai.com/api-keys](https://platform.openai.com/api-keys)).
3. Click **Create new secret key**, give it a name, and copy the key.
4. Add billing info under **Settings → Billing** — API access requires a paid account (usage is pay-as-you-go, separate from ChatGPT Plus).

Once you have your key, save it to the `.secret` file:

**Windows:**
```powershell
copy .secret.example .secret
notepad .secret
```

**Linux / macOS:**
```bash
cp .secret.example .secret
nano .secret
```

Paste your API key into the file and save. This file is git-ignored and will not be committed.

> **Security:** Never share your API key or commit it to version control. If you suspect a key has been leaked, revoke it immediately from the OpenAI dashboard and create a new one.

### Ghidra integration

`AIGhidra.py` must be accessible to Ghidra's script manager. You have two options:

**Option A — Symlink (recommended)**  
Create a symbolic link from the repo into your Ghidra scripts folder:

*Windows (PowerShell — run as Administrator):*
```powershell
New-Item -ItemType SymbolicLink `
    -Path "C:\Users\YOUR_USER\ghidra_scripts\AIGhidra.py" `
    -Target "C:\Users\YOUR_USER\Code\AIGhidra\AIGhidra.py"
```

*Linux / macOS:*
```bash
ln -s /home/YOUR_USER/Code/AIGhidra/AIGhidra.py ~/ghidra_scripts/AIGhidra.py
```

**Option B — Copy after editing**  
Manually copy `AIGhidra.py` to your `ghidra_scripts` folder after each change.

### Configuration

Edit the constants at the top of `AIGhidra.py`:

| Constant | Description |
|---|---|
| `PYTHON_EXECUTABLE` | Python 3 executable name or full path (e.g. `python3` on Linux, `python` on Windows). If you use a venv, set this to the venv's `python` binary. |
| `OPENAI_CONNECTOR_SCRIPT` | Absolute path to `handleOpenAi.py` (use forward slashes on Linux, e.g. `/home/you/Code/AIGhidra/handleOpenAi.py`) |
| `CALL_TREE_DEPTH_UP` | Levels of callers to include (default: 1) |
| `CALL_TREE_DEPTH_DOWN` | Levels of callees to include (default: 1) |
| `GLOBAL_RETYPE_THRESHOLD` | Batch size for global retyping (default: 30) |
| `ANNOTATE_BLOCK_BATCH_SIZE` | Max orphan blocks per AI call (default: 10) |
| `ORPHAN_BLOCK_MIN_SIZE` | Min disassembly chars for an orphan block to be annotated (default: 1000) |

> **Tip:** If the script cannot find the Python 3 executable at startup, it will show a popup dialog in Ghidra telling you to install Python 3 or fix the `PYTHON_EXECUTABLE` path.

## Usage

1. Open a binary in Ghidra and run **Tools → AI Assisted Renamer**.
2. Walk through the interactive dialogs described below.
3. Watch the console — renamed functions appear as banners.

### Interactive dialogs

When the script starts, it presents a series of dialogs to configure the run. Here is each one in order:

#### 1. Log Level
Enter a log verbosity level: `RAW`, `DEBUG`, `INFO`, `WARNING`, or `ERROR`.  
Default: `INFO`. Use `RAW` to see everything (decompilation cache hits, subprocess commands, etc.). Use `DEBUG` to see a recap of every individual symbol rename.

#### 2. Resume
**YES** — Skip functions already marked `[AI-RENAMED]` from a previous run. Three follow-up dialogs let you fine-tune what gets skipped (see 2a–2c below).  
**NO** — Process every function from scratch, ignoring any existing tags.

##### 2a. Skip After N Renames *(only if Resume = YES)*
Enter a number N. Functions that have already been renamed N or more times (tracked via `[AI-RENAMED 2]`, `[AI-RENAMED 3]`, etc.) will be skipped.  
Enter `0` to never skip based on rename count.

##### 2b. Re-process Short Descriptions *(only if Resume = YES)*
Enter a character threshold. Tagged functions whose plate-comment description (excluding the `[AI-RENAMED]` tag) is this many characters or shorter will be re-processed anyway — useful for functions that got an empty or poor description on a previous pass.  
Enter `0` to disable.

##### 2c. Force Re-process Pattern *(only if Resume = YES)*
Enter a case-insensitive regex. Tagged functions whose **name** or **description** matches this pattern will be re-processed regardless of other skip rules.  
Example: `FUN_|param_1` — re-process functions still named `FUN_*` or whose description still mentions `param_1`.  
Enter `#disabled` to skip this filter.

#### 3. Processing Order
**YES (Bottom-up)** — Sort functions by fewest outgoing calls so leaf functions are renamed first. When a parent function is analyzed later, its callees already have meaningful names, giving the AI much better context.  
**NO (Top-down)** — Analyze the root function first, then its callees. Gives faster initial feedback but callees still have generic names when the parent is processed.

#### 4. Function Descriptions
**YES** — Ask the AI to generate a summary of what each function does, stored as a plate comment above the function.  
**NO** — Only rename symbols, no descriptions.

##### 4a. Longer Descriptions *(only if Descriptions = YES)*
**YES** — Multi-line description covering purpose, inputs, outputs, side effects, and key logic.  
**NO** — One-line concise summary.

##### 4b. Program Insight *(only if Descriptions = YES)*
**YES** — The description also explains the function's role and importance within the larger program, based on its callers and callees.  
**NO** — Description only covers what the function does in isolation.

#### 5. Send Caller/Callee Code
**YES** — Send the full decompiled code of each caller and callee to the AI, giving it much richer context. Uses more input tokens.  
**NO** — Only send caller/callee names (cheaper, less context).

#### 6. Retype Globals
**YES** — Collect global variables with `undefined*` types and, after every 30 found, ask the AI to suggest proper C types.  
**NO** — Leave global variable types unchanged.

#### 7. Annotate Orphan Code Blocks
**YES** — Find instruction sequences not covered by any recognized function, send their assembly to the AI, and add a plate comment with a description and a suggested function name. Only blocks meeting a minimum size threshold are processed. Already-annotated blocks (with `[ORPHAN CODE BLOCK]` tag) are skipped. This runs **after** all function renaming is complete and does **not** alter program structure — only comments are added.  
**NO** — Skip orphan block annotation.

##### 7a. Orphan Block Min Size *(only if Annotate Orphans = YES)*
Enter the minimum disassembly size (in characters) for an orphan block to be annotated. Smaller blocks are skipped.  
Default: `1000` (roughly 30+ instructions). Increase this if you still get too many small blocks.

#### 8. Model Selection
A pricing table is printed to the console. Enter the model name to use (e.g. `gpt-4o-mini`, `gpt-4o`, `gpt-4.1`).  
Default: `gpt-4o-mini`.

#### 9. Function Name / Root
- **Bottom-up mode:** Enter a root function name, or `*` to include every non-external function in the program.
- **Top-down mode:** Enter the name of the function to start analysis with. The script will walk its call tree.

## File Structure

```
AIGhidra/
├── AIGhidra.py          # Ghidra Jython script (runs inside Ghidra under Python 2.7)
├── handleOpenAi.py      # OpenAI connector (runs with system Python 3)
├── .secret              # Your API key (git-ignored)
├── .secret.example      # Template for .secret
├── .gitignore
├── requirements.txt     # Python 3 dependencies — install with pip3
└── README.md
```

## Tips & Advice

> **Run "Aggressive Instruction Finder" before using AIGhidra.**
> By default, Ghidra's auto-analysis may miss a significant number of functions. In one test, standard analysis found ~1,000 functions while enabling **Analysis → One Shot → Aggressive Instruction Finder** uncovered ~1,500 — including some of the most interesting ones. Always consider running it (via **Analysis → Auto Analyze… → Aggressive Instruction Finder**, or from the one-shot menu) before starting the AI renaming pass. More discovered functions means better context and more complete results.

> **Orphan code blocks are common and mostly noise.**
> Binaries often contain hundreds of small orphan instruction sequences — alignment padding, dead code, unreferenced stubs, etc. The orphan annotation feature filters by disassembly size to focus on the substantial blocks that are likely real code the disassembler missed. The default threshold of 1000 characters works well in practice; increase it if you're still getting too many annotations. Already-annotated blocks are automatically skipped on re-runs.

> **Bottom-up + descriptions gives the best results.**
> When you enable bottom-up processing along with descriptions, leaf functions are named and described first. By the time the AI reaches a parent function, all its callees already have meaningful names and descriptions in the decompilation, producing significantly better rename choices for the parent.

## License

This project is provided as-is for reverse-engineering research and education purposes.
