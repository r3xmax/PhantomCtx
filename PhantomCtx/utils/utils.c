#include <Windows.h>
#include <stdio.h>
#include "utils.h"

VOID helpPanel() {
    printf("\n\t\t+----------------------------------+\n");
    printf("\t\t|         PhantomCtx v1.0          |\n");
    printf("\t\t+----------------------------------+\n\n");

    printf("  Usage:\n");
    printf("\tPhantomCtx.exe -m [MODE] [OPTIONS]\n\n");

    printf("  Modes:\n");
    printf("\t-m recon\tDisplays information about the Activation Context DLL redirections\n");
    printf("\t\t\tof a running process or one to be spawned.\n\n");
    printf("\t-m spawn\tPerform Activation Context Hijacking using an on-disk executable\n");
    printf("\t\t\t(preferably a signed binary for OPSEC purposes).\n\n");
    printf("\t-m runtime\tPerform Activation Context Hijacking on an already running process.\n\n");
}

VOID helpPanelRecon() {
    printf("\n\t\t+----------------------------------+\n");
    printf("\t\t|         PhantomCtx v1.0          |\n");
    printf("\t\t+----------------------------------+\n\n");

    printf("  Usage:\n");
    printf("\tPhantomCtx.exe -m recon -s [SUBMODE] -p [PROCESS_NAME|PATH]\n\n");

    printf("  Submodes:\n");
    printf("\t-s spawn\tSpawn a process in suspended mode to retrieve its\n");
    printf("\t\t\tActivation Context DLL redirection information.\n\n");
    printf("\t-s runtime\tAttach to a currently running process to retrieve its\n");
    printf("\t\t\tActivation Context DLL redirection information.\n\n");

    printf("  Examples:\n");
    printf("\tPhantomCtx.exe -m recon -s spawn   -p C:\\path\\to\\target.exe\n");
    printf("\tPhantomCtx.exe -m recon -s runtime -p target.exe\n\n");
}

VOID helpPanelSpawn() {
    printf("\n\t\t+----------------------------------+\n");
    printf("\t\t|         PhantomCtx v1.0          |\n");
    printf("\t\t+----------------------------------+\n\n");

    printf("  Usage:\n");
    printf("\tPhantomCtx.exe -m spawn -s [SUBMODE] -p [PATH] [OPTIONS]\n\n");

    printf("  Submodes:\n");
    printf("\t-s steal-context\tSpawn a process and hijack its Activation Context\n");
    printf("\t\t\t\tby stealing the context from another running process.\n\n");

    printf("\t-s add-entry\t\tSpawn a process and hijack its Activation Context\n");
    printf("\t\t\t\tby adding a new DLL redirection entry.\n\n");

    printf("\t-s patch-entry\t\tSpawn a process and hijack its Activation Context\n");
    printf("\t\t\t\tby patching the path of an existing DLL redirection entry.\n\n");

    printf("  Options:\n");
    printf("\t-p <PATH>\t\tPath to the target executable to spawn.\n");
    printf("\t-d <DLL>\t\tName of the DLL to hijack (e.g. comctl32.dll).\n");
    printf("\t--dll-path <PATH>\tPath to the custom DLL to load.\n\n");

    printf("  steal-context Options:\n");
    printf("\t--steal-from <NAME>\tProcess name to steal the Activation Context from.\n\n");

    printf("  Examples:\n");
    printf("\tPhantomCtx.exe -m spawn -s steal-context  -p C:\\program.exe --steal-from explorer.exe -d crypt32.dll --dll-path C:\\path\\to\\custom.dll\n");
    printf("\tPhantomCtx.exe -m spawn -s add-entry      -p C:\\program.exe -d crypt32.dll --dll-path C:\\path\\to\\custom.dll\n");
    printf("\tPhantomCtx.exe -m spawn -s patch-entry    -p C:\\program.exe -d comctl32.dll --dll-path C:\\path\\to\\custom.dll\n\n");
}

VOID helpPanelRuntime(){
    printf("\n\t\t+----------------------------------+\n");
    printf("\t\t|         PhantomCtx v1.0          |\n");
    printf("\t\t+----------------------------------+\n\n");

    printf("  Usage:\n");
    printf("\tPhantomCtx.exe -m runtime -s [SUBMODE] -p [PROCESS_NAME] [OPTIONS]\n\n");

    printf("  Submodes:\n");
    printf("\t-s steal-context\tHijack the Activation Context of a running process\n");
    printf("\t\t\t\tby stealing the context from another running process.\n\n");

    printf("\t-s add-entry\t\tHijack the Activation Context of a running process\n");
    printf("\t\t\t\tby adding a new DLL redirection entry.\n\n");

    printf("\t-s patch-entry\t\tHijack the Activation Context of a running process\n");
    printf("\t\t\t\tby patching the path of an existing DLL redirection entry.\n\n");

    printf("  Options:\n");
    printf("\t-p <PROCESS_NAME>\tName of the already running target process (e.g. notepad.exe).\n");
    printf("\t-d <DLL>\t\tName of the DLL to hijack (e.g. comctl32.dll).\n");
    printf("\t--dll-path <PATH>\tPath to the custom DLL to load.\n\n");

    printf("  steal-context Options:\n");
    printf("\t--steal-from <NAME>\tProcess name to steal the Activation Context from.\n\n");

    printf("  Examples:\n");
    printf("\tPhantomCtx.exe -m runtime -s steal-context  -p program.exe --steal-from explorer.exe -d crypt32.dll --dll-path C:\\path\\to\\custom.dll\n");
    printf("\tPhantomCtx.exe -m runtime -s add-entry      -p program.exe -d crypt32.dll --dll-path C:\\path\\to\\custom.dll\n");
    printf("\tPhantomCtx.exe -m runtime -s patch-entry    -p program.exe -d comctl32.dll --dll-path C:\\path\\to\\custom.dll\n\n");
}