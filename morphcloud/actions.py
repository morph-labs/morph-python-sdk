ide_actions = {
    "success": True,
    "actions": [
        {
            "name": "semanticSearch",
            "description": "Use this tool to search for specific code patterns or text within the workspace. It's useful for finding references, definitions, or occurrences of particular code elements across your project.",
            "parameters": [
                {
                    "name": "query",
                    "type": "string",
                    "description": "The search query",
                    "optional": False,
                },
                {
                    "name": "maxResults",
                    "type": "integer",
                    "description": "Optional. Maximum number of results to return (default: 10)",
                    "optional": True,
                },
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                    "results": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "path": {"type": "string"},
                                "contents": {"type": "string"},
                                "lineRange": {
                                    "type": "array",
                                    "items": {"type": "number"},
                                },
                            },
                        },
                        "optional": True,
                    },
                },
            },
            "examples": [
                'semanticSearch("SomeClass.__init__")',
                'semanticSearch("import numpy", 5)',
            ],
        },
        {
            "name": "openFolder",
            "description": "Use this tool when you need to start working on a new project or switch to a different workspace. It opens a folder in the IDE and lists its contents, providing an overview of the project structure. Consider using this at the beginning of your development session or when you need to access files in a different project folder.",
            "parameters": [
                {
                    "name": "path",
                    "type": "string",
                    "description": "Absolute path to the folder",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            },
            "examples": ['openFolder("/path/to/project")'],
        },
        {
            "name": "openFile",
            "description": "Use this tool when you need to view or edit a specific file. It's particularly useful when you know the exact file you want to work on, or when you're navigating through your project and need to open files referenced in other parts of your code. Consider using this tool when you're ready to make changes to a file or need to review its contents.",
            "parameters": [
                {
                    "name": "file",
                    "type": "string",
                    "description": "Absolute path to the file",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "contentB64": {
                        "type": "string",
                        "description": "Base64 encoded file content",
                    },
                    "contentStr": {
                        "type": "string",
                        "description": "Plain text file content",
                    },
                },
            },
            "examples": [
                'openFile("/path/to/file.txt")',
                'openFile("/path/to/script.py")',
            ],
        },
        {
            "name": "closeFile",
            "description": "Use this tool when you've finished working on a file and want to declutter your workspace. It's helpful for managing system resources and maintaining focus by closing files you no longer need open. Consider using this tool at the end of editing sessions or when switching between different parts of your project.",
            "parameters": [
                {
                    "name": "file",
                    "type": "string",
                    "description": "Absolute path to the file",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            },
            "examples": [
                'closeFile("/path/to/file.txt")',
                'closeFile("/path/to/completed_task.js")',
            ],
        },
        {
            "name": "createFile",
            "description": "Use this tool when you need to add a new file to your project. It's essential for starting new modules, creating configuration files, or adding any new content to your project structure. Consider using this tool when expanding your project or implementing new features that require additional files.",
            "parameters": [
                {
                    "name": "file",
                    "type": "string",
                    "description": "Absolute path to the new file",
                    "optional": False,
                },
                {
                    "name": "content",
                    "type": "string",
                    "description": "Content to write to the file",
                    "optional": False,
                },
            ],
            "returns": {
                "type": "object",
                "properties": {"success": {"type": "boolean"}},
            },
            "examples": [
                'createFile("/path/to/newfile.txt", "File content")',
                'createFile("/path/to/config.json", "{\\"key\\": \\"value\\"}")',
            ],
        },
        {
            "name": "readFile",
            "description": "Use this tool when you need to inspect the contents of a file without opening it in the editor. It's useful for quick checks, verifying file contents, or when you need to process file contents programmatically. Consider using this tool when you're debugging, need to confirm recent changes, or want to retrieve information from configuration files.",
            "parameters": [
                {
                    "name": "file",
                    "type": "string",
                    "description": "Absolute path to the file",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "content": {"type": "string"},
                },
            },
            "examples": [
                'readFile("/path/to/file.txt")',
                'readFile("/path/to/config.json")',
            ],
        },
        {
            "name": "editFile",
            "description": "Use this tool when you need to make specific changes to a file, especially when modifying a particular section. It's ideal for automated edits, refactoring, or when you want to ensure changes are made to exact line ranges. Consider using this tool when you have precise edits in mind and know the exact location in the file where changes should be made.",
            "parameters": [
                {
                    "name": "file",
                    "type": "string",
                    "description": "Absolute path to the file",
                    "optional": False,
                },
                {
                    "name": "content",
                    "type": "string",
                    "description": "New content to replace the specified lines",
                    "optional": False,
                },
                {
                    "name": "startLine",
                    "type": "integer",
                    "description": "Start line number (0-based index)",
                    "optional": False,
                },
                {
                    "name": "endLine",
                    "type": "integer",
                    "description": "End line number (0-based index)",
                    "optional": False,
                },
            ],
            "returns": {
                "type": "object",
                "properties": {"success": {"type": "boolean"}},
            },
            "examples": [
                'editFile("/path/to/file.txt", "New content", 0, 5)',
                'editFile("/path/to/script.py", "def new_function():\\n    pass", 10, 15)',
            ],
        },
        {
            "name": "listOpenFiles",
            "description": "Use this tool when you need an overview of all currently open files in your IDE. It's helpful for managing your workspace, ensuring you haven't left any unnecessary files open, or when you need to refer to the set of files you're actively working on. Consider using this tool when switching between tasks or at the end of a coding session to review your work.",
            "parameters": [],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "files": {"type": "array", "items": {"type": "string"}},
                },
            },
            "examples": ["listOpenFiles()"],
        },
        {
            "name": "listFileTree",
            "description": "Use this tool when you need a comprehensive view of your project structure. It's particularly useful when you're new to a project, planning refactoring, or need to understand the organization of files and folders. Consider using this tool at the start of a development session or when you're trying to locate specific files within a complex project structure.",
            "parameters": [],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "tree": {
                        "type": "object",
                        "description": "Nested object representing the file tree",
                    },
                },
            },
            "examples": ["listFileTree()"],
        },
        {
            "name": "retrieveProblems",
            "description": "Use this tool when you want to get an overview of current issues in your workspace. It's crucial for identifying and addressing errors, warnings, or other diagnostic problems in your code. Consider using this tool after making significant changes, before committing code, or when you're troubleshooting unexpected behavior in your application.",
            "parameters": [],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "problems": {"type": "array", "items": {"type": "object"}},
                },
            },
            "examples": ["retrieveProblems()"],
        },
        {
            "name": "launchDebuggerOnCurrentFile",
            "description": "Use this tool when you need to start a debugging session for the currently active file. It's essential when you want to step through code execution, set breakpoints, or inspect variables in real-time. Consider using this tool when you encounter unexpected behavior, want to verify the flow of your program, or need to understand complex logic in your code.",
            "parameters": [],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            },
            "examples": ["launchDebuggerOnCurrentFile()"],
        },
        {
            "name": "addBreakpoints",
            "description": "Use this tool when you need to set specific points in your code where execution should pause during debugging. It's crucial for examining the state of your program at critical junctures. Consider using this tool before starting a debug session, when you've identified areas of interest in your code, or when you're trying to isolate the source of a bug.",
            "parameters": [
                {
                    "name": "lineNumbers",
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Array of line numbers to add breakpoints",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {"success": {"type": "boolean"}},
            },
            "examples": [
                "addBreakpoints([5, 10, 15])",
                "addBreakpoints([20, 30, 40, 50])",
            ],
        },
        {
            "name": "continueToNextBreakpoint",
            "description": "Use this tool during an active debugging session to resume code execution until the next breakpoint is reached. It's useful for moving through your code efficiently while still pausing at important points. Consider using this tool when you want to skip over sections of code you're confident in and focus on specific areas of interest or suspected issues.",
            "parameters": [],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                    "runState": {"type": "string"},
                },
            },
            "examples": ["continueToNextBreakpoint()"],
        },
        {
            "name": "runDebugConsoleCommand",
            "description": "The runDebugConsole tool executes a command in the debug console while a debugging session is active and paused at a breakpoint. Use this tool when your program behaves unexpectedly and you need to inspect its state during execution. Before using, ensure you've set breakpoints at critical points and the debugger is paused. As you use it, ask yourself: What variables or expressions are crucial to understanding the current state? Could executing this command have unintended side effects? How does the observed state differ from your expectations? This tool allows real-time inspection of variables, evaluation of expressions, and interaction with the program state, but use it cautiously as some commands may alter the program's state. Always consider the scope and context of your debugging session, and use this tool in conjunction with step-by-step debugging for a comprehensive understanding of your code's behavior.",
            "parameters": [
                {
                    "name": "command",
                    "type": "string",
                    "description": "Command to run in the debug console",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "result": {"type": "string"},
                    "debugInfo": {"type": "object", "optional": True},
                },
            },
            "examples": [
                'runDebugConsoleCommand("myVariable")',
                'runDebugConsoleCommand("len(myList) + 5")',
                'runDebugConsoleCommand("dir(myObject)")',
                'runDebugConsoleCommand("x \u003E 10 and y \u003C 5")',
            ],
        },
        {
            "name": "getWorkspaceDirectory",
            "description": "Use this tool when you need to confirm or retrieve the absolute path of the current workspace directory. It's helpful for ensuring you're working in the correct location, especially in scripts or automated processes. Consider using this tool at the beginning of sessions, in build scripts, or when you need to construct absolute file paths based on the workspace root.",
            "parameters": [],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "directory": {"type": "string", "optional": True},
                },
            },
            "examples": ["getWorkspaceDirectory()"],
        },
        {
            "name": "clearBreakpoints",
            "description": "Use this tool when you want to remove all breakpoints from a specific file. It's useful for cleaning up your debugging environment, especially after you've finished investigating a particular issue or when you want to set up a new debugging scenario. Consider using this tool at the end of a debugging session or when you want to start fresh with a new set of breakpoints.",
            "parameters": [
                {
                    "name": "file",
                    "type": "string",
                    "description": "Absolute path to the file",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            },
            "examples": [
                'clearBreakpoints("/path/to/file.py")',
                'clearBreakpoints("/path/to/script.js")',
            ],
        },
        {
            "name": "alert",
            "description": "Use this tool when you need to display an important message to the user within the IDE. It's useful for providing notifications about significant events, warnings, or completion of long-running tasks. Consider using this tool when you want to ensure the user doesn't miss critical information or when you need to prompt for user attention.",
            "parameters": [
                {
                    "name": "message",
                    "type": "string",
                    "description": "Message to display in the alert",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {"success": {"type": "boolean"}},
            },
            "examples": [
                'alert("Important notification")',
                'alert("Task completed successfully")',
            ],
        },
        {
            "name": "shellCommand",
            "description": "Use this tool when you need to execute a command in the IDE's integrated terminal. It's particularly useful for running shell commands, build scripts, or any CLI operations within your project context. Consider using this tool when you need to perform operations that are typically done via command line, but want to integrate them into your IDE workflow.",
            "parameters": [
                {
                    "name": "command",
                    "type": "string",
                    "description": "Command to run in the terminal",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {
                        "type": "boolean",
                        "description": "Indicates whether the command was executed successfully",
                    },
                    "result": {
                        "type": "string",
                        "description": "The combined stdout and stderr output of the executed command",
                    },
                },
            },
            "examples": [
                'shellCommand("npm install")',
                "shellCommand(\"echo 'Hello, world!'\")",
            ],
        },
        {
            "name": "getOpenFilesView",
            "description": "Use this tool when you need to retrieve the content of all currently open files in the editor. It's useful for creating snapshots of your working set, comparing file states, or implementing features that need to operate on all open files. Consider using this when implementing multi-file operations or when you need to save the current state of your workspace.",
            "parameters": [],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "openFiles": {
                        "type": "object",
                        "description": "An object where keys are file paths and values are the visible content of the files",
                        "additionalProperties": {
                            "type": "string",
                            "description": "Visible content of the file",
                        },
                    },
                },
            },
            "examples": ["getOpenFilesView()"],
        },
        {
            "name": "openDiff",
            "description": "Use this tool when you need to compare the current state of a file with a previous version in your git history. It's invaluable for code review, understanding recent changes, or tracking down when a particular change was introduced. Consider using this tool when investigating bugs, reviewing your own changes before a commit, or exploring the evolution of a file over time.",
            "parameters": [
                {
                    "name": "file",
                    "type": "string",
                    "description": "The path of the file to diff",
                    "optional": False,
                },
                {
                    "name": "versionIndex",
                    "type": "integer",
                    "description": "The number of versions to go back in git history (default: 1)",
                    "optional": False,
                },
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                    "diff": {"type": "string", "optional": True},
                },
            },
            "examples": [
                'openDiff("/path/to/file.txt", 1)',
                'openDiff("/path/to/script.js", 3)',
            ],
        },
        {
            "name": "diffTwoFiles",
            "description": "Use this tool when you need to compare the contents of two different files. It's useful for identifying differences between similar files, comparing implementation across different versions or branches, or reviewing changes made in a new file against an existing one. Consider using this tool during code reviews, when refactoring similar components, or when you need to understand the differences between two implementations.",
            "parameters": [
                {
                    "name": "file1",
                    "type": "string",
                    "description": "The path of the first file to compare",
                    "optional": False,
                },
                {
                    "name": "file2",
                    "type": "string",
                    "description": "The path of the second file to compare",
                    "optional": False,
                },
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                    "diff": {"type": "string", "optional": True},
                },
            },
            "examples": [
                'diffTwoFiles("/path/to/file1.txt", "/path/to/file2.txt")',
                'diffTwoFiles("/path/to/oldversion.js", "/path/to/newversion.js")',
            ],
        },
        {
            "name": "scrollFile",
            "description": "Use this tool when you need to programmatically adjust the view of an open file in the editor. It's useful for focusing on specific parts of a file, especially in large documents. Consider using this tool when implementing features that need to guide the user's attention to particular sections of code or when you want to ensure certain parts of a file are visible during automated operations.",
            "parameters": [
                {
                    "name": "file",
                    "type": "string",
                    "description": "Absolute path to the file",
                    "optional": False,
                },
                {
                    "name": "direction",
                    "type": "string",
                    "enum": ["up", "down"],
                    "description": "Scroll direction ('up' or 'down')",
                    "optional": False,
                },
                {
                    "name": "lines",
                    "type": "integer",
                    "description": "Number of lines to scroll",
                    "optional": False,
                },
            ],
            "returns": {
                "type": "object",
                "properties": {"success": {"type": "boolean"}},
            },
            "examples": [
                'scrollFile("/path/to/file.txt", "down", 10)',
                'scrollFile("/path/to/longscript.py", "up", 20)',
            ],
        },
        {
            "name": "gotoLine",
            "description": "Use this tool when you need to move the cursor to a specific line in an open file. It's particularly useful for navigating to known locations in your code, such as error lines reported by linters or specific function definitions. Consider using this tool when implementing features that involve precise navigation within files or when you need to focus the user's attention on a particular line of code.",
            "parameters": [
                {
                    "name": "file",
                    "type": "string",
                    "description": "Absolute path to the file",
                    "optional": False,
                },
                {
                    "name": "line",
                    "type": "integer",
                    "description": "Line number to navigate to (1-based index)",
                    "optional": False,
                },
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            },
            "examples": [
                'gotoLine("/path/to/file.txt", 100)',
                'gotoLine("/path/to/script.py", 42)',
            ],
        },
        {
            "name": "undoLastEdit",
            "description": "Use this tool when you need to revert the most recent edit operation in the active file. It's useful for quickly correcting mistakes or experimenting with changes that you might want to undo. Consider using this tool immediately after making an unintended change or when you want to step back through recent edits to review changes.",
            "parameters": [],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            },
            "examples": ["undoLastEdit()"],
        },
        {
            "name": "applyAiderEdit",
            "description": "Use this tool when you want to apply structured edits to a file. This tool is designed to handle edits in a specific diff format. Consider using this tool when needing to modify the contents of a file, automated edits, refactoring, or when applying standardized changes across your codebase. Be sure to include at least 1 other contigous line of context around the edit to ensure the diff is applied correctly. Each edit block should follow this format:\n1. The file path\n2. The opening fence: ```\u003Clanguage\u003E\n3. The start of search block: \u003C\u003C\u003C\u003C\u003C\u003C\u003C SEARCH\n4. The original code to be replaced\n5. The dividing line: =======\n6. The new code to replace the original\n7. The end of replace block: \u003E\u003E\u003E\u003E\u003E\u003E\u003E REPLACE\n8. The closing fence: ```",
            "parameters": [
                {
                    "name": "file",
                    "type": "string",
                    "description": "Absolute path to the file",
                    "optional": False,
                },
                {
                    "name": "aiderDiff",
                    "type": "string",
                    "description": "Aider diff content to apply",
                    "optional": False,
                },
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            },
            "examples": [
                "applyAiderEdit(\"/path/to/file.py\", \"\u003C\u003C\u003C\u003C\u003C\u003C\u003C SEARCH\\ndef calculator(args):\\n    print('Simple Calculator')\\n    print('Operations: +, -, *, /')\\n=======\\ndef calculator(args):\\n    print('Advanced Calculator')\\n    print('Operations: +, -, *, /')\\n\u003E\u003E\u003E\u003E\u003E\u003E\u003E REPLACE\")"
            ],
        },
        {
            "name": "addPythonDebugConfig",
            "description": "Use this tool when you need to set up or ensure a Python debug configuration exists in your project. It's particularly useful when starting work on a new Python project or when you want to standardize debugging setups across a team. Consider using this tool as part of your project initialization process or when you're about to start a debugging session and want to ensure the correct configuration is in place.",
            "parameters": [],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            },
            "examples": ["addPythonDebugConfig()"],
        },
        {
            "name": "getBreakpointRunState",
            "description": "Use this tool during a debugging session when you need to retrieve the current execution state at a breakpoint. It's invaluable for understanding the program's state, including variable values and the call stack, at a specific point in execution. Consider using this tool when you've hit a breakpoint and need to gather detailed information about the program's current state for analysis or to guide your next debugging steps.",
            "parameters": [],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "runState": {"type": "string"},
                },
            },
            "examples": ["getBreakpointRunState()"],
        },
        {
            "name": "killTerminal",
            "description": "Use this tool when you need to stop a long-running terminal process (typically a long-running command or a development server) that was started using the terminalCommand. It's useful for terminating background tasks, stopping development servers, or cancelling ongoing operations. Consider using this tool when a process is no longer needed, is consuming too many resources, or when you need to restart a process with different parameters.",
            "parameters": [
                {
                    "name": "terminalName",
                    "type": "string",
                    "description": "The name of the terminal process to terminate",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            },
            "examples": ['killTerminal("dev-server")', 'killTerminal("build-watch")'],
        },
        {
            "name": "deleteFile",
            "description": "Use this tool when you need to delete a file from your project. It's essential for removing obsolete files, cleaning up your project structure, or when you want to discard temporary files. Consider using this tool when you're sure you no longer need the file or when you want to declutter your workspace.",
            "parameters": [
                {
                    "name": "file",
                    "type": "string",
                    "description": "Absolute path to the file",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            },
            "examples": [
                'deleteFile("/path/to/file.txt")',
                'deleteFile("/path/to/obsolete_script.py")',
            ],
        },
        {
            "name": "gitClone",
            "description": "Clones a GitHub repository to the specified directory or workspace root.",
            "parameters": [
                {
                    "name": "repoUrl",
                    "type": "string",
                    "description": "URL of the GitHub repository to clone",
                    "optional": False,
                },
                {
                    "name": "targetDir",
                    "type": "string",
                    "description": "Optional. Target directory for cloning. If not provided, clones to workspace root.",
                    "optional": False,
                },
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            },
            "examples": [
                'gitClone("https://github.com/username/repo.git", "/path/to/clone/dir")'
            ],
        },
        {
            "name": "generateGitPatch",
            "description": "Generates a patch file from the current state of the git repository in the workspace.",
            "parameters": [],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                    "patch": {
                        "type": "string",
                        "description": "The generated patch content",
                        "optional": True,
                    },
                },
            },
            "examples": ["generateGitPatch()"],
        },
        {
            "name": "vercelCreateApp",
            "description": "Create a new Vercel app.",
            "parameters": [
                {
                    "name": "name",
                    "type": "string",
                    "description": "Name of the new Vercel app to create",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            },
            "examples": ['vercelCreateApp("myApp")', 'vercelCreateApp("newProject")'],
        },
        {
            "name": "vercelRunApp",
            "description": "Run a Vercel app.",
            "parameters": [
                {
                    "name": "name",
                    "type": "string",
                    "description": "Name of the Vercel app to run",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            },
            "examples": ['vercelRunApp("myApp")', 'vercelRunApp("testProject")'],
        },
        {
            "name": "vercelGitConnect",
            "description": "Connect a Vercel app to a git repository.",
            "parameters": [
                {
                    "name": "name",
                    "type": "string",
                    "description": "Name of the Vercel app to connect to a git repository",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            },
            "examples": ['vercelGitConnect("myApp")', 'vercelGitConnect("webProject")'],
        },
        {
            "name": "vercelDeployApp",
            "description": "Deploy a Vercel app.",
            "parameters": [
                {
                    "name": "name",
                    "type": "string",
                    "description": "Name of the Vercel app to deploy",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            },
            "examples": [
                'vercelDeployApp("myApp")',
                'vercelDeployApp("productionReadyProject")',
            ],
        },
        {
            "name": "dbCreate",
            "description": "Create a new database with the specified name.",
            "parameters": [
                {
                    "name": "name",
                    "type": "string",
                    "description": "Name of the new database to create",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {
                        "type": "boolean",
                        "description": "Indicates whether the command was executed successfully",
                    },
                    "result": {
                        "type": "string",
                        "description": "The combined stdout and stderr output of the executed command",
                    },
                },
            },
            "examples": ['dbCreate("myDatabase")', 'dbCreate("testDB")'],
        },
        {
            "name": "dbList",
            "description": "List all existing databases",
            "parameters": [],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {
                        "type": "boolean",
                        "description": "Indicates whether the command was executed successfully",
                    },
                    "result": {
                        "type": "string",
                        "description": "The combined stdout and stderr output of the executed command",
                    },
                },
            },
            "examples": ["dbList()"],
        },
        {
            "name": "terminalCommand",
            "description": "Use this tool to execute a command in the terminal. If a terminalName is provided, it creates a new terminal for that command. If not, it uses or creates a default 'Morph Code Link' terminal. You can use this tool to run any command in the terminal, such as a server start command, a long-running process, or a one-time command. Use the `observeTerminals` tool to get the list of all terminals and the last command executed and their outputs.",
            "parameters": [
                {
                    "name": "command",
                    "type": "string",
                    "description": "The command to run in the terminal",
                    "optional": False,
                },
                {
                    "name": "terminalName",
                    "type": "string",
                    "description": "Optional name for a new terminal process. If not provided, the command will be executed in the 'Morph Code Link' terminal.",
                    "optional": True,
                },
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "output": {"type": "string"},
                },
            },
            "examples": [
                'terminalCommand({ command: "npm start", terminalName: "dev-server" })',
                'terminalCommand({ command: "ls -la" })',
            ],
        },
        {
            "name": "dbQuery",
            "description": "Query a database in the cloud",
            "parameters": [
                {
                    "name": "name",
                    "type": "string",
                    "description": "Name of the database to query",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {
                        "type": "boolean",
                        "description": "Indicates whether the command was executed successfully",
                    },
                    "result": {
                        "type": "string",
                        "description": "The combined stdout and stderr output of the executed command",
                    },
                },
            },
            "examples": [
                'dbQuery("myDatabase", "SELECT * FROM myTable")',
                'dbQuery("userDB", "SELECT username FROM users WHERE age \u003E 18")',
            ],
        },
        {
            "name": "dbDelete",
            "description": "Delete a database in the cloud",
            "parameters": [
                {
                    "name": "name",
                    "type": "string",
                    "description": "Name of the database to delete",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {
                        "type": "boolean",
                        "description": "Indicates whether the command was executed successfully",
                    },
                    "result": {
                        "type": "string",
                        "description": "The combined stdout and stderr output of the executed command",
                    },
                },
            },
            "examples": ['dbDelete("myDatabase")', 'dbDelete("testDB")'],
        },
        {
            "name": "dbConnectionString",
            "description": "Get the connection string for a database in the cloud",
            "parameters": [
                {
                    "name": "name",
                    "type": "string",
                    "description": "Name of the database to get the connection string for",
                    "optional": False,
                },
                {
                    "name": "instance_id",
                    "type": "string",
                    "description": "ID of the Neon instance to get the connection string for",
                    "optional": False,
                },
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {
                        "type": "boolean",
                        "description": "Indicates whether the command was executed successfully",
                    },
                    "result": {
                        "type": "string",
                        "description": "The connection string for the database",
                    },
                },
            },
            "example": 'dbConnectionString("myDatabase", "123")',
        },
        {
            "name": "gitCreate",
            "description": "Create a new remote git repository.",
            "parameters": [
                {
                    "name": "name",
                    "type": "string",
                    "description": "Name of the new remote git repository to create",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            },
            "example": 'gitCreate("myRepo")',
        },
        {
            "name": "gitPush",
            "description": "Commit and push changes to the remote git repository.",
            "parameters": [
                {
                    "name": "name",
                    "type": "string",
                    "description": "Name of the remote git repository to push to",
                    "optional": False,
                },
                {
                    "name": "commit_message",
                    "type": "string",
                    "description": "Message of the commit to push",
                    "optional": False,
                },
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            },
            "example": 'gitPush("myRepo", "My commit message")',
        },
        {
            "name": "gitDelete",
            "description": "Delete the remote git repository.",
            "parameters": [
                {
                    "name": "name",
                    "type": "string",
                    "description": "Name of the remote git repository to delete",
                }
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            },
            "example": 'gitDelete("myRepo")',
        },
        {
            "name": "observeTerminals",
            "description": "Use this tool to monitor and retrieve information about terminals and their processes running in the background. It provides a snapshot of all active terminals running your asynchronous commands, capturing their recent output and last executed command. This function is particularly useful for tracking long-running processes, debugging background tasks, or getting status updates on multiple concurrent operations without interrupting their execution.",
            "parameters": [],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {
                        "type": "boolean",
                        "description": "Indicates whether the operation was successful",
                    },
                    "result": {
                        "type": "object",
                        "description": "A dictionary where keys are terminal names and values are objects containing lastCommand and output",
                        "additionalProperties": {
                            "type": "object",
                            "properties": {
                                "lastCommand": {
                                    "type": "string",
                                    "description": "The last command executed in the terminal",
                                },
                                "output": {
                                    "type": "string",
                                    "description": "The recent output of the terminal (last 750 characters)",
                                },
                            },
                        },
                    },
                    "error": {
                        "type": "string",
                        "optional": True,
                        "description": "Error message if the operation failed",
                    },
                },
            },
            "example": "observeTerminals()",
        },
        {
            "name": "getCodeLinks",
            "description": "Use this tool to find references, usages, and implementations of a specific identifier in a file.",
            "parameters": [
                {
                    "name": "file",
                    "type": "string",
                    "description": "The file to search for the identifier",
                    "optional": False,
                },
                {
                    "name": "lineStart",
                    "type": "integer",
                    "description": "The start line number of the range to search",
                    "optional": False,
                },
                {
                    "name": "lineEnd",
                    "type": "integer",
                    "description": "The end line number of the range to search",
                    "optional": False,
                },
                {
                    "name": "identifier",
                    "type": "string",
                    "description": "The identifier to search for",
                    "optional": False,
                },
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "result": {"type": "string"},
                },
            },
            "examples": [
                'getCodeLinks({ file: "main.py", lineStart: 10, lineEnd: 20, identifier: "my_function" })'
            ],
        },
        {
            "name": "lint",
            "description": "Use this tool to lint specific files in your project. It opens the files and returns any problems (errors, warnings, syntax errors, etc.) found by the IDE's diagnostic systems.",
            "parameters": [
                {
                    "name": "files",
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Array of file paths (absolute or relative) to lint",
                    "optional": False,
                }
            ],
            "returns": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "problems": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "file": {"type": "string"},
                                "line": {"type": "number"},
                                "column": {"type": "number"},
                                "message": {"type": "string"},
                                "severity": {"type": "string"},
                            },
                        },
                    },
                },
            },
            "examples": [
                'lint(["src/main.py", "/absolute/path/to/file.js"])',
                'lint(["package.json", "tsconfig.json"])',
            ],
        },
    ],
}
