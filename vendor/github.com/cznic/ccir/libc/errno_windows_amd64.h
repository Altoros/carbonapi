// Code generated by running "go generate". DO NOT EDIT.

	// +build ignore
	
	// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

typedef unsigned long long size_t ;
typedef long long ssize_t ;
typedef size_t rsize_t ;
typedef long long intptr_t ;
typedef unsigned long long uintptr_t ;
typedef long long ptrdiff_t ;
typedef unsigned short wchar_t ;
typedef unsigned short wint_t ;
typedef unsigned short wctype_t ;
typedef int errno_t ;
typedef long __time32_t ;
typedef long long __time64_t ;
typedef __time64_t time_t ;
struct threadlocaleinfostruct ;
struct threadmbcinfostruct ;
typedef struct threadlocaleinfostruct *pthreadlocinfo ;
typedef struct threadmbcinfostruct *pthreadmbcinfo ;
struct __lc_time_data ;
typedef struct localeinfo_struct {pthreadlocinfo locinfo ;pthreadmbcinfo mbcinfo ;}_locale_tstruct ;
typedef struct localeinfo_struct {pthreadlocinfo locinfo ;pthreadmbcinfo mbcinfo ;}*_locale_t ;

typedef struct tagLC_ID {unsigned short wLanguage ;unsigned short wCountry ;unsigned short wCodePage ;}LC_ID ;
typedef struct tagLC_ID {unsigned short wLanguage ;unsigned short wCountry ;unsigned short wCodePage ;}*LPLC_ID ;

typedef struct threadlocaleinfostruct {int refcount ;unsigned int lc_codepage ;unsigned int lc_collate_cp ;unsigned long lc_handle [6 ];LC_ID lc_id [6 ];struct {char *locale ;wchar_t *wlocale ;int *refcount ;int *wrefcount ;}lc_category [6 ];int lc_clike ;int mb_cur_max ;int *lconv_intl_refcount ;int *lconv_num_refcount ;int *lconv_mon_refcount ;struct lconv *lconv ;int *ctype1_refcount ;unsigned short *ctype1 ;const unsigned short *pctype ;const unsigned char *pclmap ;const unsigned char *pcumap ;struct __lc_time_data *lc_time_curr ;}threadlocinfo ;
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

extern int *_errno (void );
errno_t _set_errno (int _Value );
errno_t _get_errno (int *_Value );
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define ENAMETOOLONG (38)
#define ENOEXEC (8)
#define ECONNRESET (108)
#define _SECURECRT_ERRCODE_VALUES_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _WCTYPE_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define ENETUNREACH (118)
#define ENOTSUP (129)
#define EMLINK (31)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_2(__ret, __func, __dsttype, __dst, __type1, __arg1, __type2, __arg2) 
#define _THREADLOCALEINFO 
#define _CRT_PACKING (8)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define ENFILE (23)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_2(__ret_type, __ret_policy, __decl_spec, __name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1, __arg2_type, __arg2) __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_2_EX ( __ret_type , __ret_policy , __decl_spec , __func_name , __func_name ## _s , __dst_attr , __dst_type , __dst , __arg1_type , __arg1 , __arg2_type , __arg2 )
#define __uintptr_t_defined 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define EAGAIN (11)
#define ENOPROTOOPT (123)
#define ERANGE (34)
#define EPERM (1)
#define EPROTONOSUPPORT (135)
#define ENOTEMPTY (41)
#define ESRCH (3)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _RSIZE_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define ENOTTY (25)
#define EWOULDBLOCK (140)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _CRTNOALIAS 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define EADDRINUSE (100)
#define _CRT_ERRNO_DEFINED 
#define STRUNCATE (80)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_1(__ret_type, __ret_policy, __decl_spec, __name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1) __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_2_EX ( __ret_type , __ret_policy , __decl_spec , __func_name , __func_name ## _s , __dst_attr , __dst_type , __dst , __arg1_type , __arg1 , __arg2_type , __arg2 )
#define _WINT_T 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define ENOSYS (40)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _UINTPTR_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define EACCES (13)
#define EISCONN (113)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __intptr_t_defined 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define ETIMEDOUT (138)
#define ECHILD (10)
#define EDEADLOCK EDEADLK
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _INC_CRTDEFS 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define EALREADY (103)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_1_EX(__ret_type, __ret_policy, __decl_spec, __name, __sec_name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1) 
#define _CRTRESTRICT 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define EEXIST (17)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __crt_typefix(ctype) 
#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_4(__ret, __func, __dsttype, __dst, __type1, __arg1, __type2, __arg2, __type3, __arg3, __type4, __arg4) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define EFBIG (27)
#define EROFS (30)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_SPLITPATH(__ret, __func, __dsttype, __src) 
#define _ERRCODE_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define ECANCELED (105)
#define EOWNERDEAD (133)
#define ENODEV (19)
#define ENOTSOCK (128)
#define EDEADLK (36)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _TIME_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define _INC_ERRNO 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _SIZE_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define ECONNREFUSED (107)
#define ELOOP (114)
#define ENOMEM (12)
#define EBUSY (16)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _PTRDIFF_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define EAFNOSUPPORT (102)
#define EDOM (33)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _TAGLC_ID_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define EHOSTUNREACH (110)
#define ENOLCK (39)
#define ENOTCONN (126)
#define EFAULT (14)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_2_EX(__ret_type, __ret_policy, __decl_spec, __name, __sec_name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1, __arg2_type, __arg2) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define ENOTDIR (20)
#define EBADF (9)
#define EINTR (4)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_2_0(__ret, __func, __type1, __arg1, __type2, __arg2, __dsttype, __dst) 
#define _TIME64_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define EPIPE (32)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_4(__ret_type, __ret_policy, __decl_spec, __name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1, __arg2_type, __arg2, __arg3_type, __arg3, __arg4_type, __arg4) __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_4_EX ( __ret_type , __ret_policy , __decl_spec , __func_name , __func_name ## _s , __dst_attr , __dst_type , __dst , __arg1_type , __arg1 , __arg2_type , __arg2 , __arg3_type , __arg3 , __arg4_type , __arg4 )
#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_3(__ret_type, __ret_policy, __decl_spec, __name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1, __arg2_type, __arg2, __arg3_type, __arg3) __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_3_EX ( __ret_type , __ret_policy , __decl_spec , __func_name , __func_name ## _s , __dst_attr , __dst_type , __dst , __arg1_type , __arg1 , __arg2_type , __arg2 , __arg3_type , __arg3 )
#define _PTRDIFF_T_ 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define EOPNOTSUPP (130)
#define ENOFILE ENOENT
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_1(__ret, __func, __dsttype, __dst, __type1, __arg1) 
#define _INTPTR_T_DEFINED 
#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_2_ARGLIST(__ret, __func, __vfunc, __dsttype, __dst, __type1, __arg1, __type2, __arg2) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define EADDRNOTAVAIL (101)
#define ENETDOWN (116)
#define EMSGSIZE (115)
#define EINVAL (22)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _SSIZE_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define ENOENT (2)
#define EDESTADDRREQ (109)
#define EIO (5)
#define ENETRESET (117)
#define ESPIPE (29)
#define E2BIG (7)
#define EPROTO (134)
#define EILSEQ (42)
#define EXDEV (18)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_3_EX(__ret_type, __ret_policy, __decl_spec, __name, __sec_name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1, __arg2_type, __arg2, __arg3_type, __arg3) 
#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_1_3(__ret, __func, __type0, __arg0, __dsttype, __dst, __type1, __arg1, __type2, __arg2, __type3, __arg3) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define errno ( * _errno ( ) )
#define EISDIR (21)
#define EOVERFLOW (132)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_1_2(__ret, __func, __type0, __arg0, __dsttype, __dst, __type1, __arg1, __type2, __arg2) 
#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_0(__ret, __func, __dsttype, __dst) 
#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_0_EX(__ret_type, __ret_policy, __decl_spec, __name, __sec_name, __dst_attr, __dst_type, __dst) 
#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_4_EX(__ret_type, __ret_policy, __decl_spec, __name, __sec_name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1, __arg2_type, __arg2, __arg3_type, __arg3, __arg4_type, __arg4) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define ENOSPC (28)
#define ENXIO (6)
#define ENOBUFS (119)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_3(__ret, __func, __dsttype, __dst, __type1, __arg1, __type2, __arg2, __type3, __arg3) 
#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_1_ARGLIST(__ret, __func, __vfunc, __dsttype, __dst, __type1, __arg1) 
#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_1_1(__ret, __func, __type0, __arg0, __dsttype, __dst, __type1, __arg1) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define ECONNABORTED (106)
#define EINPROGRESS (112)
#define EPROTOTYPE (136)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _TIME32_T_DEFINED 
#define _WCHAR_T_DEFINED 
#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_0(__ret_type, __ret_policy, __decl_spec, __name, __dst_attr, __dst_type, __dst) __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_0_EX ( __ret_type , __ret_policy , __decl_spec , __func_name , __func_name ## _s , __dst_attr , __dst_type , __dst )
#define _CRT_SECURE_CPP_NOTHROW throw ( )
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\errno.h 

#define EMFILE (24)
