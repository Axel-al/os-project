# Snapshot and Malicious File Detection Project

This project aims to **monitor** one or more directories, **create or update** a snapshot file describing each directory’s contents, and **detect** any potentially malicious files so that they can be isolated in a dedicated location.

## Table of Contents

1. [General Context](#general-context)  
2. [Key Features](#key-features)  
   - [Snapshot Creation](#snapshot-creation)  
   - [Change Detection](#change-detection)  
   - [Suspicious File Analysis](#suspicious-file-analysis)  
   - [Isolation of Dangerous Files](#isolation-of-dangerous-files)  
3. [Code Structure](#code-structure)  
4. [Compilation and Execution](#compilation-and-execution)  
   - [Compilation](#compilation)  
   - [Execution](#execution)  
   - [Available Options/Arguments](#available-optionsarguments)  
5. [Usage Example](#usage-example)  
6. [Remarks and Possible Corrections](#remarks-and-possible-corrections)  
7. [Authors / License / Credits](#authors--license--credits)

---

## General Context

The project addresses a need to **monitor directories** for file or subdirectory additions, deletions, and modifications. In addition, certain files may be **potentially malicious** — especially those with no permissions (permissions set to `0000`).  
To manage this risk, a **shell script** is invoked to analyze the contents of such files and decide whether to quarantine them if necessary.

## Key Features

### Snapshot Creation

- The main C program recursively scans each directory specified as a command-line argument.  
- It creates or updates a `snapshot.txt` file in each monitored directory.  
- This file contains **metadata** about each item (permissions, owner, last modification date, size).

### Change Detection

On each new run:

- **New files or directories** are detected and reported as “created.”  
- **Missing files or directories** are detected and reported as “deleted.”  
- Any changes to **permissions**, **owner**, or **size/last modification date** are also flagged.

### Suspicious File Analysis

- If a file has all its permissions removed (`(stats.st_mode & 0777) == 0`), the program spawns a **child process** that executes `verify_for_malicious.sh`.  
- The script checks for the presence of danger keywords (`corrupted`, `dangerous`, `risk`, `attack`, `malware`, `malicious`) or non-ASCII characters, etc.  
- If a file is deemed malicious by the script, it is moved to a **quarantine directory** (specified via the `-s` option).

### Isolation of Dangerous Files

- Files identified as malicious or corrupted are **moved** to an isolation directory (e.g., `isolated_space_dir`).  
- This prevents further risk from these files while allowing for future investigation.

## Code Structure

The project comprises two main components:

1. **C Program**: `OS Project.c`  
   - `main()` parses arguments, creates **one child process per top-level directory**, and calls `compareMetadata()` for each directory.  
   - `compareMetadata()` reads/updates the local `snapshot.txt`, detects modifications, and if necessary, invokes the malicious file analysis script.

2. **Shell Script**: `verify_for_malicious.sh`  
   - Receives the file path to be analyzed as a parameter.  
   - Searches for dangerous keywords or non-ASCII characters.  
   - Uses various criteria (number of lines, size, etc.) to determine if the file is “SAFE” or “dangerous.”  
   - Returns an exit code so the main C program can decide whether to move the file to an isolation directory.

Supplementary documents (Project.pdf, week-8.pdf, week-9.pdf) describe:

- The project’s overarching goals.  
- The requirement to create parallel child processes.  
- Conditions for detecting malicious files.

## Compilation and Execution

### Compilation

Make sure you have a C compiler (e.g., gcc, clang):

```bash
gcc -o snapshot_project "OS Project.c"
```

This produces an executable named `snapshot_project` (or another name of your choice).

### Execution

```bash
./snapshot_project [OPTIONS] [DIRECTORY ...]
```

### Available Options/Arguments

- **`-o output_file`**: Specifies a **global output file** in which the metadata for all scanned files will be recorded.  
- **`-s isolated_space_dir`**: Specifies the **quarantine directory** where potentially malicious files are moved.  
- Then, **a list of directories** follows, each of which will be analyzed by a **separate child process**.

**Note**: The code allows `-s` and `-o` in different orders. The order of these flags determines how subsequent arguments are interpreted (see the `main()` function for details).

## Usage Example

1. **No isolation, just a global output file**:

   ```bash
   ./snapshot_project -o global_output.txt /path/to/dir1 /path/to/dir2
   ```
   - Creates snapshots for `dir1` and `dir2`.
   - Also writes metadata of all scanned files to `global_output.txt`.

2. **With isolation and a global output file**:

   ```bash
   ./snapshot_project -o my_output.txt -s quarantine_dir dir1 dir2 dir3
   ```
   - Files deemed malicious are moved to `./quarantine_dir/`.  
   - A global record is kept in `my_output.txt`.

3. **With only isolation** (no global output):

   ```bash
   ./snapshot_project -s quarantine_dir dir1
   ```
   - Stores a local `snapshot.txt` under `dir1`.  
   - Suspicious files are moved to `quarantine_dir`.

## Remarks and Possible Corrections

1. **`verify_for_malicious.sh` Script**  
   - As currently written, it particularly checks if the file has **fewer than 3 lines** and **more than 1000 words / 2000 characters** before scanning for dangerous keywords or non-ASCII characters.  
   - If a file has **3 or more lines**, it effectively does no additional checks in the code we see.  
   - Depending on the project requirements, you might wish to analyze **all** files or adapt this logic.  
   - A correction or improvement would be to ensure a broader check is performed for any file, regardless of size or line count.

2. **Permissions Check**  
   - The code flags suspicious files when `(stats.st_mode & 0777) == 0`, which means the file has absolutely **no** permissions (--- --- ---).  
   - Depending on specifications, you might also want to handle other unusual permission combinations.

3. **Directory Handling**  
   - A **child process** is created for each **top-level** directory, which then recursively scans subdirectories.  
   - Subdirectories are not handled by separate processes; they are scanned by the same process. This is an intentional choice in the code.

4. **Parallel Processes and Output**  
   - Each child process updates a `snapshot.txt` in its own directory and, if specified, writes to the global output file.  
   - The parent waits for each child and displays:  
     ```
     Child Process X terminated with PID Y and exit code Z.
     ```

Feel free to adjust these behaviors or messages to meet the exact requirements of your course or project.

## Authors

- Alabéatrix Axel
