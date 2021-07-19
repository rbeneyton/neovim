#pragma once

#include <stddef.h>  // IWYU pragma: keep

#include "nvim/api/private/defs.h"  // IWYU pragma: keep

#include "os/proc.h.generated.h"

#if defined(__linux__)
// TODO auto generated?
bool os_proc_tmux_info(int pid, char msg[static 512]);
#endif
