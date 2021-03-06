// Code generated by running "go generate". DO NOT EDIT.

	// +build ignore
	
	// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

typedef unsigned int size_t ;
typedef int ssize_t ;
typedef size_t rsize_t ;
typedef int intptr_t ;
typedef unsigned int uintptr_t ;
typedef int ptrdiff_t ;
typedef unsigned short wchar_t ;
typedef unsigned short wint_t ;
typedef unsigned short wctype_t ;
typedef int errno_t ;
typedef long __time32_t ;
typedef long long __time64_t ;
typedef __time32_t time_t ;
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
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\_mingw_off_t.h 

typedef long _off_t ;
typedef long off32_t ;
typedef long long _off64_t ;
typedef long long off64_t ;
typedef off64_t off_t ;
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\types.h 

typedef unsigned short _ino_t ;
typedef unsigned short ino_t ;
typedef unsigned int _dev_t ;
typedef unsigned int dev_t ;
typedef int _pid_t ;
typedef _pid_t pid_t ;
typedef unsigned short _mode_t ;
typedef _mode_t mode_t ;
typedef unsigned int useconds_t ;
struct timespec {time_t tv_sec ;long tv_nsec ;};
struct itimerspec {struct timespec it_interval ;struct timespec it_value ;};
typedef unsigned long _sigset_t ;
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\_mingw_stat64.h 

struct _stat {_dev_t st_dev ;_ino_t st_ino ;unsigned short st_mode ;short st_nlink ;short st_uid ;short st_gid ;_dev_t st_rdev ;_off_t st_size ;__time32_t st_atime ;__time32_t st_mtime ;__time32_t st_ctime ;};
struct stat {_dev_t st_dev ;_ino_t st_ino ;unsigned short st_mode ;short st_nlink ;short st_uid ;short st_gid ;_dev_t st_rdev ;_off_t st_size ;time_t st_atime ;time_t st_mtime ;time_t st_ctime ;};
struct _stati64 {_dev_t st_dev ;_ino_t st_ino ;unsigned short st_mode ;short st_nlink ;short st_uid ;short st_gid ;_dev_t st_rdev ;long long st_size ;__time32_t st_atime ;__time32_t st_mtime ;__time32_t st_ctime ;};
struct _stat64i32 {_dev_t st_dev ;_ino_t st_ino ;unsigned short st_mode ;short st_nlink ;short st_uid ;short st_gid ;_dev_t st_rdev ;_off_t st_size ;__time64_t st_atime ;__time64_t st_mtime ;__time64_t st_ctime ;};
struct _stat64 {_dev_t st_dev ;_ino_t st_ino ;unsigned short st_mode ;short st_nlink ;short st_uid ;short st_gid ;_dev_t st_rdev ;long long st_size ;__time64_t st_atime ;__time64_t st_mtime ;__time64_t st_ctime ;};
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

int _fstat (int _FileDes ,struct _stat *_Stat );
int _stat (const char *_Name ,struct _stat *_Stat );
int _fstat64 (int _FileDes ,struct _stat64 *_Stat );
int _fstati64 (int _FileDes ,struct _stati64 *_Stat );
int _fstat64i32 (int _FileDes ,struct _stat64i32 *_Stat );
int _stat64 (const char *_Name ,struct _stat64 *_Stat );
int _stati64 (const char *_Name ,struct _stati64 *_Stat );
int _stat64i32 (const char *_Name ,struct _stat64i32 *_Stat );
int _wstat (const wchar_t *_Name ,struct _stat *_Stat );
int _wstati64 (const wchar_t *_Name ,struct _stati64 *_Stat );
int _wstat64i32 (const wchar_t *_Name ,struct _stat64i32 *_Stat );
int _wstat64 (const wchar_t *_Name ,struct _stat64 *_Stat );
int stat (const char *_Filename ,struct stat *_Stat );
int fstat (int _Desc ,struct stat *_Stat );
int wstat (const wchar_t *_Filename ,struct stat *_Stat );
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define _S_IFCHR (8192)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _PTRDIFF_T_ 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\types.h 

#define _MODE_T_ 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_3(__ret_type, __ret_policy, __decl_spec, __name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1, __arg2_type, __arg2, __arg3_type, __arg3) __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_3_EX ( __ret_type , __ret_policy , __decl_spec , __func_name , __func_name ## _s , __dst_attr , __dst_type , __dst , __arg1_type , __arg1 , __arg2_type , __arg2 , __arg3_type , __arg3 )
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\_mingw_off_t.h 

#define _OFF64_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_3_EX(__ret_type, __ret_policy, __decl_spec, __name, __sec_name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1, __arg2_type, __arg2, __arg3_type, __arg3) 
#define _RSIZE_T_DEFINED 
#define _INC_CRTDEFS 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define _S_IFIFO (4096)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_4_EX(__ret_type, __ret_policy, __decl_spec, __name, __sec_name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1, __arg2_type, __arg2, __arg3_type, __arg3, __arg4_type, __arg4) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define _S_IRWXU (448)
#define S_ISDIR(m) ( ( ( m ) & S_IFMT ) == S_IFDIR )
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __uintptr_t_defined 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\types.h 

#define _INC_TYPES 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_2_0(__ret, __func, __type1, __arg1, __type2, __arg2, __dsttype, __dst) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\_mingw_stat64.h 

#define stat64 _stat64
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define S_IRWXO (7)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _CRT_SECURE_CPP_NOTHROW throw ( )
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\_mingw_stat64.h 

#define _stat32 _stat
#define _wstat32i64 _wstati64
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define S_IFDIR _S_IFDIR
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_2(__ret, __func, __dsttype, __dst, __type1, __arg1, __type2, __arg2) 
#define _WCTYPE_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\_mingw_off_t.h 

#define _FILE_OFFSET_BITS_SET_OFFT 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _CRTNOALIAS 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define S_IWOTH (2)
#define fstat _fstat32i64
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\_mingw_off_t.h 

#define _OFF_T_ 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define S_IWRITE _S_IWRITE
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\_mingw_stat64.h 

#define _fstat32 _fstat
#define __stat64 _stat64
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define S_IFCHR _S_IFCHR
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_0_EX(__ret_type, __ret_policy, __decl_spec, __name, __sec_name, __dst_attr, __dst_type, __dst) 
#define _CRTRESTRICT 
#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_1(__ret, __func, __dsttype, __dst, __type1, __arg1) 
#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_0(__ret_type, __ret_policy, __decl_spec, __name, __dst_attr, __dst_type, __dst) __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_0_EX ( __ret_type , __ret_policy , __decl_spec , __func_name , __func_name ## _s , __dst_attr , __dst_type , __dst )
#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_1_ARGLIST(__ret, __func, __vfunc, __dsttype, __dst, __type1, __arg1) 
#define __crt_typefix(ctype) 
#define _TIME64_T_DEFINED 
#define _UINTPTR_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\types.h 

#define _PID_T_ 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_2_ARGLIST(__ret, __func, __vfunc, __dsttype, __dst, __type1, __arg1, __type2, __arg2) 
#define _WINT_T 
#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_1_3(__ret, __func, __type0, __arg0, __dsttype, __dst, __type1, __arg1, __type2, __arg2, __type3, __arg3) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define S_ISCHR(m) ( ( ( m ) & S_IFMT ) == S_IFCHR )
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _SSIZE_T_DEFINED 
#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_SPLITPATH(__ret, __func, __dsttype, __src) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define S_IXGRP (8)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _TIME_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define _S_IRUSR _S_IREAD
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\_mingw_stat64.h 

#define fstat64 _fstat64
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define S_IXOTH (1)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _SIZE_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define S_IWUSR _S_IWUSR
#define S_IRWXG (56)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\types.h 

#define _SIGSET_T_ 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_4(__ret_type, __ret_policy, __decl_spec, __name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1, __arg2_type, __arg2, __arg3_type, __arg3, __arg4_type, __arg4) __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_4_EX ( __ret_type , __ret_policy , __decl_spec , __func_name , __func_name ## _s , __dst_attr , __dst_type , __dst , __arg1_type , __arg1 , __arg2_type , __arg2 , __arg3_type , __arg3 , __arg4_type , __arg4 )
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define _S_IFREG (32768)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _THREADLOCALEINFO 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\_mingw_stat64.h 

#define _STAT_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define S_ISBLK(m) ( ( ( m ) & S_IFMT ) == S_IFBLK )
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _WCHAR_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define S_IRGRP (32)
#define _WSTAT_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _TIME32_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define S_IRUSR _S_IRUSR
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\types.h 

#define _INO_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define S_IRWXU _S_IRWXU
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\types.h 

#define _DEV_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define _S_IFDIR (16384)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _CRT_PACKING (8)
#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_0(__ret, __func, __dsttype, __dst) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define S_IFIFO _S_IFIFO
#define _INC_STAT 
#define S_IROTH (4)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\_mingw_off_t.h 

#define _OFF_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_2(__ret_type, __ret_policy, __decl_spec, __name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1, __arg2_type, __arg2) __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_2_EX ( __ret_type , __ret_policy , __decl_spec , __func_name , __func_name ## _s , __dst_attr , __dst_type , __dst , __arg1_type , __arg1 , __arg2_type , __arg2 )
#define _INTPTR_T_DEFINED 
#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_1_EX(__ret_type, __ret_policy, __decl_spec, __name, __sec_name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1) 
#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_1_2(__ret, __func, __type0, __arg0, __dsttype, __dst, __type1, __arg1, __type2, __arg2) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define _S_IXUSR _S_IEXEC
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\_mingw_stat64.h 

#define _stat32i64 _stati64
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define S_IFBLK _S_IFBLK
#define _S_IWRITE (128)
#define S_ISREG(m) ( ( ( m ) & S_IFMT ) == S_IFREG )
#define _S_IWUSR _S_IWRITE
#define S_IWGRP (16)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_3(__ret, __func, __dsttype, __dst, __type1, __arg1, __type2, __arg2, __type3, __arg3) 
#define _TAGLC_ID_DEFINED 
#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_1(__ret_type, __ret_policy, __decl_spec, __name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1) __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_2_EX ( __ret_type , __ret_policy , __decl_spec , __func_name , __func_name ## _s , __dst_attr , __dst_type , __dst , __arg1_type , __arg1 , __arg2_type , __arg2 )
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define S_IFREG _S_IFREG
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __intptr_t_defined 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define S_IXUSR _S_IXUSR
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_4(__ret, __func, __dsttype, __dst, __type1, __arg1, __type2, __arg2, __type3, __arg3, __type4, __arg4) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define _S_IFMT (61440)
#define S_ISFIFO(m) ( ( ( m ) & S_IFMT ) == S_IFIFO )
#define stat _stat32i64
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_2_EX(__ret_type, __ret_policy, __decl_spec, __name, __sec_name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1, __arg2_type, __arg2) 
#define _ERRCODE_DEFINED 
#define _PTRDIFF_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define _S_IFBLK (12288)
#define _S_IREAD (256)
#define S_IREAD _S_IREAD
#define S_IEXEC _S_IEXEC
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\types.h 

#define _TIMESPEC_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define _S_IEXEC (64)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_1_1(__ret, __func, __type0, __arg0, __dsttype, __dst, __type1, __arg1) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\_mingw_stat64.h 

#define _wstat32 _wstat
#define _fstat32i64 _fstati64
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\sys\stat.h 

#define S_IFMT _S_IFMT
