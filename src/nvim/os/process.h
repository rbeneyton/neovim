#pragma once

#include <stddef.h>  // IWYU pragma: keep

#ifdef MSWIN
# include "nvim/api/private/defs.h"  // IWYU pragma: keep
#endif

#ifdef INCLUDE_GENERATED_DECLARATIONS
# include "os/process.h.generated.h"
#endif

#if defined(__linux__)
// TODO auto generated?
bool os_proc_tmux_info(int pid, char msg[static 512]);
#endif
