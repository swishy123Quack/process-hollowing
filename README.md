# Overview
- PoC (Proof of Concept) of Process Hollowing

# Usage
- Run prochollow.exe, it will start svchost and inject helloworld.exe into it.
- prochollow.exe will occasionally pause at some crucial steps of the process, allowing for easy debugging.
- If you want to run without pausing or specify custom paths, you can pass some arguments into the program, usage is as follows:
  - `-a, --auto` : Enable automatic processing without user prompt (default: `false`)
  - `-pa <path>` : Specify path for process (default: `"C:\\Windows\\SysWOW64\\cmd.exe"`)
  - `pb <path>` : Specify path for payload (default: `"helloworld.exe"`)
  
# Notes
- This is intended to use on x86 (32 bit) programs only, I did not managed to make it work for x86_64 programs due to the lack of resource (noob).
- For maximum compatibility, both of the programs' subsystem must match, I compiled `helloworld.cpp` with 32 bit g++ with the flag `-mwindows`.
- Lastly, this is for educational purpose only, any malicous usage is NOT intended! (If you even managed to lol).

# TODO
- Describe how it works!!!
