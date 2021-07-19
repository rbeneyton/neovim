#ifndef NVIM_OS_PROCESS_H
#define NVIM_OS_PROCESS_H

#include <stddef.h>

#include "nvim/api/private/defs.h"

#ifdef INCLUDE_GENERATED_DECLARATIONS
# include "os/process.h.generated.h"
#endif

#if defined(__linux__)
// TODO auto generated?
bool os_proc_tmux_info(int pid, char msg[static 512]);
#endif

#endif  // NVIM_OS_PROCESS_H
