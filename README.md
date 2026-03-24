# AIGhidra — AI-Assisted Symbol Renaming for Ghidra

AIGhidra uses OpenAI to automatically rename functions, parameters, local variables, globals, labels, classes, namespaces, and more inside [Ghidra](https://ghidra-sre.org/) reverse-engineering projects.

## How It Works

1. **AIGhidra.py** runs inside Ghidra's Python 2.7 (Jython) scripting engine.  
   It decompiles each function, collects its callers, callees, and global variables, then sends the context to an external script.

2. **handleOpenAi.py** runs with your system Python 3.x.  
   It calls the OpenAI API, receives rename suggestions in JSON, and writes them to a temp file that AIGhidra reads back.

3. Renames are applied inside a Ghidra transaction — function names, parameters, locals, globals, labels, classes, namespaces, enums, structs, and typedefs.

## Features

- **Bottom-up analysis** — leaf functions renamed first so parent context is richer.
- **Resume mode** — skip already-processed functions on re-runs.
- **AI rename counting** — tracks how many times each function was AI-renamed (`[AI-RENAMED]`, `[AI-RENAMED 2]`, …). Optionally skip functions renamed N+ times.
- **Function descriptions** — optional one-line or detailed plate comments.
- **Program insight** — explains why a function matters in context.
- **Batch global retyping** — collects `undefined*` globals and asks the AI to suggest proper C types.
- **Multiple log levels** — RAW, DEBUG, INFO, WARNING, ERROR.
- **Model selection** — choose any OpenAI chat model with pricing info displayed.

## Setup

### Prerequisites

- [Ghidra](https://ghidra-sre.org/) (tested with 10.x / 11.x)
- Python 3.8+ on your system PATH
- An OpenAI API key

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/AIGhidra.git
cd AIGhidra

# Install Python 3 dependencies
pip install -r requirements.txt

# Create your API key file (never committed to git)
copy .secret.example .secret
# Edit .secret and paste your real API key
```

### Ghidra Integration

AIGhidra.py must be accessible to Ghidra's script manager.  You have two options:

**Option A — Symlink (recommended)**  
Create a symbolic link from the repo into your Ghidra scripts folder:
```powershell
New-Item -ItemType SymbolicLink `
    -Path "C:\Users\YOUR_USER\ghidra_scripts\AIGhidra.py" `
    -Target "C:\Users\YOUR_USER\Code\AIGhidra\AIGhidra.py"
```

**Option B — Copy after editing**  
Manually copy `AIGhidra.py` to your `ghidra_scripts` folder after each change.

### Configuration

Edit the constants at the top of `AIGhidra.py`:

| Constant | Description |
|---|---|
| `OPENAI_CONNECTOR_SCRIPT` | Absolute path to `handleOpenAi.py` |
| `PYTHON_EXECUTABLE` | Python 3 executable name or path |
| `CALL_TREE_DEPTH_UP` | Levels of callers to include (default: 1) |
| `CALL_TREE_DEPTH_DOWN` | Levels of callees to include (default: 1) |
| `GLOBAL_RETYPE_THRESHOLD` | Batch size for global retyping (default: 30) |

## Usage

1. Open a binary in Ghidra and run **Tools → AI Assisted Renamer**.
2. Answer the interactive dialogs (log level, resume, tagging, processing order, etc.).
3. Enter a root function name or `*` for all functions.
4. Watch the console — renamed functions appear as banners.

## File Structure

```
AIGhidra/
├── AIGhidra.py          # Ghidra Jython script (runs inside Ghidra)
├── handleOpenAi.py      # OpenAI connector (runs with system Python 3)
├── .secret              # Your API key (git-ignored)
├── .secret.example      # Template for .secret
├── .gitignore
├── requirements.txt
└── README.md
```

## License

This project is provided as-is for reverse-engineering research and education purposes.
