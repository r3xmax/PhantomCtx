#include <Windows.h>
#include <stdio.h>

#include "utils\utils.h"
#include "recon\recon.h"
#include "spawn\spawn.h"
#include "runtime\runtime.h"

// Returns the value of a flag, or NULL if not found
char* getArg(int argc, char** argv, const char* flag) {
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], flag) == 0) {
            return argv[i + 1];
        }
    }
    return NULL;
}

// Returns TRUE if a flag exists
BOOL hasArg(int argc, char** argv, const char* flag) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], flag) == 0) return TRUE;
    }
    return FALSE;
}

// Validates that no unknown flags are present for a given mode
// validFlags: NULL-terminated array of valid flag strings
BOOL validateArgs(int argc, char** argv, const char** validFlags) {
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            BOOL known = FALSE;
            for (int j = 0; validFlags[j] != NULL; j++) {
                if (strcmp(argv[i], validFlags[j]) == 0) {
                    known = TRUE;
                    break;
                }
            }
            if (!known) {
                fprintf(stderr, "[ERROR] Unknown argument '%s'.\n\n", argv[i]);
                return FALSE;
            }
            if (i + 1 < argc) i++; // skip flag value if present
        } else if (i > 1 &&
                   strcmp(argv[i - 1], "-m") != 0 &&
                   strcmp(argv[i - 1], "-s") != 0 &&
                   strcmp(argv[i - 1], "-p") != 0) {
            fprintf(stderr, "[ERROR] Unexpected argument '%s'.\n\n", argv[i]);
            return FALSE;
        }
    }
    return TRUE;
}

int main(int argc, char** argv) {

    if (argc < 2) {
        helpPanel();
        return 0;
    }

    // Global --help/-h without -m
    if (!hasArg(argc, argv, "-m")) {
        if (hasArg(argc, argv, "--help") || hasArg(argc, argv, "-h")) {
            helpPanel();
            return 0;
        }
        fprintf(stderr, "[ERROR] No mode specified. Use -m [MODE].\n\n");
        helpPanel();
        return 1;
    }

    // Parse -m [MODE]
    char* mode = getArg(argc, argv, "-m");
    if (mode == NULL) {
        fprintf(stderr, "[ERROR] -m requires a mode argument.\n\n");
        helpPanel();
        return 1;
    }

    BOOL wantsHelp = hasArg(argc, argv, "--help") || hasArg(argc, argv, "-h");

    // -------------------------------------------------------------------------
    // MODE: recon
    // -------------------------------------------------------------------------
    if (strcmp(mode, "recon") == 0) {

        if (wantsHelp || argc < 4) { helpPanelRecon(); return 0; }

        const char* validFlags[] = { "-m", "-s", "-p", "--help", "-h", NULL };
        if (!validateArgs(argc, argv, validFlags)) {
            helpPanelRecon();
            return 1;
        }

        char* submode = getArg(argc, argv, "-s");
        if (submode == NULL) {
            fprintf(stderr, "[ERROR] Missing required argument -s [SUBMODE].\n");
            fprintf(stderr, "        Use '-m recon -s spawn' or '-m recon -s runtime'.\n\n");
            helpPanelRecon();
            return 1;
        }
        if (strcmp(submode, "spawn") != 0 && strcmp(submode, "runtime") != 0) {
            fprintf(stderr, "[ERROR] Unknown submode '%s'.\n", submode);
            fprintf(stderr, "        Valid submodes: spawn, runtime.\n\n");
            helpPanelRecon();
            return 1;
        }

        char* target = getArg(argc, argv, "-p");
        if (target == NULL) {
            fprintf(stderr, "[ERROR] Missing required argument -p [PID|PATH].\n\n");
            helpPanelRecon();
            return 1;
        }

        modeRecon(submode, target);

    // -------------------------------------------------------------------------
    // MODE: spawn
    // -------------------------------------------------------------------------
    } else if (strcmp(mode, "spawn") == 0) {

        if (wantsHelp || argc < 4) { helpPanelSpawn(); return 0; }

        const char* validFlags[] = { "-m", "-s", "-p", "-d", "--dll-path", "--steal-from", "--help", "-h", NULL };
        if (!validateArgs(argc, argv, validFlags)) {
            helpPanelSpawn();
            return 1;
        }

        char* submode   = getArg(argc, argv, "-s");
        char* target    = getArg(argc, argv, "-p");
        char* dllName   = getArg(argc, argv, "-d");
        char* dllPath   = getArg(argc, argv, "--dll-path");
        char* stealFrom = getArg(argc, argv, "--steal-from");

        if (submode == NULL) {
            fprintf(stderr, "[ERROR] Missing required argument -s [SUBMODE].\n");
            fprintf(stderr, "        Valid submodes: steal-context, add-entry, patch-entry.\n\n");
            helpPanelSpawn();
            return 1;
        }
        if (strcmp(submode, "steal-context")  != 0 &&
            strcmp(submode, "add-entry")      != 0 &&
            strcmp(submode, "patch-entry")    != 0) {
            fprintf(stderr, "[ERROR] Unknown submode '%s'.\n", submode);
            fprintf(stderr, "        Valid submodes: steal-context, add-entry, patch-entry.\n\n");
            helpPanelSpawn();
            return 1;
        }
        if (target == NULL) {
            fprintf(stderr, "[ERROR] Missing required argument -p <PATH>.\n\n");
            helpPanelSpawn();
            return 1;
        }
        if (dllName == NULL) {
            fprintf(stderr, "[ERROR] Missing required argument -d <DLL>.\n\n");
            helpPanelSpawn();
            return 1;
        }
        if (dllPath == NULL) {
            fprintf(stderr, "[ERROR] Missing required argument --dll-path <PATH>.\n\n");
            helpPanelSpawn();
            return 1;
        }
        if (strcmp(submode, "steal-context") == 0 && stealFrom == NULL) {
            fprintf(stderr, "[ERROR] Submode 'steal-context' requires --steal-from <PROCESS_NAME>.\n\n");
            helpPanelSpawn();
            return 1;
        }

        modeSpawn(submode, target, dllName, dllPath, stealFrom);

    // -------------------------------------------------------------------------
    // MODE: runtime
    // -------------------------------------------------------------------------
    } else if (strcmp(mode, "runtime") == 0) {

        if (wantsHelp || argc < 4) { helpPanelRuntime(); return 0; }

        const char* validFlags[] = { "-m", "-s", "-p", "-d", "--dll-path", "--steal-from", "--help", "-h", NULL };
        if (!validateArgs(argc, argv, validFlags)) {
            helpPanelRuntime();
            return 1;
        }

        char* submode   = getArg(argc, argv, "-s");
        char* target    = getArg(argc, argv, "-p");
        char* dllName   = getArg(argc, argv, "-d");
        char* dllPath   = getArg(argc, argv, "--dll-path");
        char* stealFrom = getArg(argc, argv, "--steal-from");

        if (submode == NULL) {
            fprintf(stderr, "[ERROR] Missing required argument -s [SUBMODE].\n");
            fprintf(stderr, "        Valid submodes: steal-context, add-entry, patch-entry.\n\n");
            helpPanelRuntime();
            return 1;
        }
        if (strcmp(submode, "steal-context")  != 0 &&
            strcmp(submode, "add-entry")      != 0 &&
            strcmp(submode, "patch-entry")    != 0) {
            fprintf(stderr, "[ERROR] Unknown submode '%s'.\n", submode);
            fprintf(stderr, "        Valid submodes: steal-context, add-entry, patch-entry.\n\n");
            helpPanelRuntime();
            return 1;
        }
        if (target == NULL) {
            fprintf(stderr, "[ERROR] Missing required argument -p <NAME>.\n\n");
            helpPanelRuntime();
            return 1;
        }
        if (dllName == NULL) {
            fprintf(stderr, "[ERROR] Missing required argument -d <DLL>.\n\n");
            helpPanelRuntime();
            return 1;
        }
        if (dllPath == NULL) {
            fprintf(stderr, "[ERROR] Missing required argument --dll-path <PATH>.\n\n");
            helpPanelRuntime();
            return 1;
        }
        if (strcmp(submode, "steal-context") == 0 && stealFrom == NULL) {
            fprintf(stderr, "[ERROR] Submode 'steal-context' requires --steal-from <PROCESS_NAME>.\n\n");
            helpPanelRuntime();
            return 1;
        }

        modeRuntime(submode, target, dllName, dllPath, stealFrom);

    // -------------------------------------------------------------------------
    // Unknown mode
    // -------------------------------------------------------------------------
    } else {
        fprintf(stderr, "[ERROR] Unknown mode '%s'.\n\n", mode);
        helpPanel();
        return 1;
    }

    return 0;
}