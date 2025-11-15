# DLLMirage

A fast, clean DLL export proxy generator powered by the LIEF library.

DLLMirage parses a target DLL’s export table and generates two types of output:

- A forwarding pragma header (for linker-based export forwarding)
- A C++ stub source file where each exported function calls a common loader (ProxyFunction)

## Features

- Parse 32-bit & 64-bit PE exports using LIEF
- Generate forwarding pragmas (`Export=Path_of_the_DLL.Export,@Ordinal`)
- Generate C++ stub functions that call `ProxyFunction()`
- Sanitize invalid C++ export names automatically
- Skip already-forwarded exports for clarity
- No unsafe runtime resolution (no `GetProcAddress` calls)
- Simple CLI: `--dll`, `--pragmas`, `--stubs`, `--both`
- Red-team friendly output for DLL sideloading & proxy builds

## Requirements

- Python 3.8+
- LIEF

Install LIEF:

```bash
pip install lief
```

Clone the repo:

```bash
git https://github.com/S4vTrX/DLLMirage.git
cd DLLMirage
```

## Usage

Generate a pragma header (produces: `yourdll_pragmas.h`):

```bash
python DLLMirage.py --dll C:\Windows\System32\wdscore.dll --pragmas
```

Example pragma output:

```c
#pragma comment(linker,"/export:ExportFunction=Pathofthedll.ExportFunction,@99")
#pragma comment(linker,"/export:SomeFunction=Pathofthedll.SomeFunction,@12")
```

Generate stub C++ file (produces: `yourdll_stubs.cpp`):

```bash
python dll_fwd_lief.py --dll C:\Windows\System32\devobj.dll --stubs
```

Example stub output:

```cpp
extern "C" {

__declspec(dllexport) void ExportFunction() {
    ProxyFunction();
}

__declspec(dllexport) void SomeFunction() {
    ProxyFunction();
}

}
```

## CLI

Options:
- `--dll <path>` : Path to target DLL
- `--pragmas` : Generate forwarding pragma header
- `--stubs` : Generate C++ stub source file
- `--both` : Generate both outputs

## Notes

- Forwarded exports are skipped by design.
- Output filenames are based on the input DLL name (e.g., `yourdll_pragmas.h`, `yourdll_stubs.cpp`).

