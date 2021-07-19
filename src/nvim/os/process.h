#ifndef NVIM_OS_PROCESS_H
#define NVIM_OS_PROCESS_H

#include <stddef.h>
#include "nvim/api/private/defs.h"

#ifdef INCLUDE_GENERATED_DECLARATIONS
# include "os/process.h.generated.h"
#endif

// TODO auto generated?
bool os_proc_tmux_info(int pid, char msg[static 512]);

#endif  // NVIM_OS_PROCESS_H
