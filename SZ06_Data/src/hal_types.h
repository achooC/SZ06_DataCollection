/*********************************************************************
 * Filename:       hal_types.h
 * Description:    Defined global macro.
 ********************************************************************/

#ifndef _HAL_TYPES_H_
#define _HAL_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif
/*********************************************************************
 * INCLUDES
 */
#include <stdbool.h>
/* -------------------------------------------------------------------
 *							Constants
 * -------------------------------------------------------------------
 */

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef NULL
#define NULL 0
#endif

/* -------------------------------------------------------------------
 *							Macros
 * -------------------------------------------------------------------
 */
#ifdef SH_DEBUG
extern void print_time_stamp(void);
#define DBG_PRINT(param...)	print_time_stamp(); printf(param)
#define DBG_HEXDUMP(param...) print_time_stamp(); hex_dump(param)
#else
#define DBG_PRINT(param...)
#define DBG_HEXDUMP(param...)
#endif
/* -------------------------------------------------------------------
 *							Global Variables
 * -------------------------------------------------------------------
 */
typedef signed   char   int8;
typedef unsigned char   uint8;

typedef signed   short  int16;
typedef unsigned short  uint16;

typedef signed   int   int32;
typedef unsigned int   uint32;

typedef signed long		int64;
typedef unsigned long	uint64;

#ifdef __cplusplus
}
#endif

#endif /* _HAL_TYPES_H_ */
