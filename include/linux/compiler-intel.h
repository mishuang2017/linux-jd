#ifndef __LINUX_COMPILER_H
#error "Please don't include <linux/compiler-intel.h> directly, include <linux/compiler.h> instead."
#endif

#ifdef __ECC

/* Some compiler specific definitions are overwritten here
 * for Intel ECC compiler
 */

#include <asm/intrinsics.h>

/* Intel ECC compiler doesn't support gcc specific asm stmts.
 * It uses intrinsics to do the equivalent things.
 */
#undef barrier_data
#undef RELOC_HIDE
#undef OPTIMIZER_HIDE_VAR

#define barrier_data(ptr) barrier()

#define RELOC_HIDE(ptr, off)					\
  ({ unsigned long __ptr;					\
     __ptr = (unsigned long) (ptr);				\
    (typeof(ptr)) (__ptr + (off)); })

/* This should act as an optimization barrier on var.
 * Given that this compiler does not have inline assembly, a compiler barrier
 * is the best we can do.
 */
#define OPTIMIZER_HIDE_VAR(var) barrier()

/* Intel ECC compiler doesn't support __builtin_types_compatible_p() */
#define __must_be_array(a) 0

#endif

#define uninitialized_var(x) x

#ifndef __HAVE_BUILTIN_BSWAP16__
/* icc has this, but it's called _bswap16 */
#define __HAVE_BUILTIN_BSWAP16__
#define __builtin_bswap16 _bswap16
#endif

/*
 * icc defines __GNUC__, but does not implement the builtin overflow checkers.
 */
#undef COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW
