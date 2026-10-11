//go:build windows && amd64

#include "textflag.h"

// Wintun returns a foreign allocation address through the syscall ABI. This
// representation bridge does not dereference it or call native code. Borrowing
// bounds/lifetimes are enforced by nativePacket and the Wintun API callers.
TEXT ·nativePointer(SB), NOSPLIT, $0-16
    MOVQ address+0(FP), AX
    MOVQ AX, ret+8(FP)
    RET
