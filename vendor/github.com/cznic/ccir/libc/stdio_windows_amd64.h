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
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\_mingw_off_t.h 

typedef long _off_t ;
typedef long off32_t ;
typedef long long _off64_t ;
typedef long long off64_t ;
typedef off64_t off_t ;
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

FILE *__iob_func (void );
typedef long long fpos_t ;
extern int __mingw_sscanf (const char *_Src ,const char *_Format ,...);
extern int __mingw_vsscanf (const char *_Str ,const char *Format ,va_list argp );
extern int __mingw_scanf (const char *_Format ,...);
extern int __mingw_vscanf (const char *Format ,va_list argp );
extern int __mingw_fscanf (FILE *_File ,const char *_Format ,...);
extern int __mingw_vfscanf (FILE *fp ,const char *Format ,va_list argp );
extern int __mingw_vsnprintf (char *_DstBuf ,size_t _MaxCount ,const char *_Format ,va_list _ArgList );
extern int __mingw_snprintf (char *s ,size_t n ,const char *format ,...);
extern int __mingw_printf (const char *,...);
extern int __mingw_vprintf (const char *,va_list );
extern int __mingw_fprintf (FILE *,const char *,...);
extern int __mingw_vfprintf (FILE *,const char *,va_list );
extern int __mingw_sprintf (char *,const char *,...);
extern int __mingw_vsprintf (char *,const char *,va_list );
extern int __mingw_asprintf (char **,const char *,...);
extern int __mingw_vasprintf (char **,const char *,va_list );
int fprintf (FILE *_File ,const char *_Format ,...);
int printf (const char *_Format ,...);
int sprintf (char *_Dest ,const char *_Format ,...);
int vfprintf (FILE *_File ,const char *_Format ,va_list _ArgList );
int vprintf (const char *_Format ,va_list _ArgList );
int vsprintf (char *_Dest ,const char *_Format ,va_list _Args );
int fscanf (FILE *_File ,const char *_Format ,...);
int scanf (const char *_Format ,...);
int sscanf (const char *_Src ,const char *_Format ,...);
int __ms_vscanf (const char *Format ,va_list argp );
int __ms_vfscanf (FILE *fp ,const char *Format ,va_list argp );
int __ms_vsscanf (const char *_Str ,const char *Format ,va_list argp );
int _filbuf (FILE *_File );
int _flsbuf (int _Ch ,FILE *_File );
FILE *_fsopen (const char *_Filename ,const char *_Mode ,int _ShFlag );
void clearerr (FILE *_File );
int fclose (FILE *_File );
int _fcloseall (void );
FILE *_fdopen (int _FileHandle ,const char *_Mode );
int feof (FILE *_File );
int ferror (FILE *_File );
int fflush (FILE *_File );
int fgetc (FILE *_File );
int _fgetchar (void );
int fgetpos (FILE *_File ,fpos_t *_Pos );
int fgetpos64 (FILE *_File ,fpos_t *_Pos );
char *fgets (char *_Buf ,int _MaxCount ,FILE *_File );
int _fileno (FILE *_File );
char *_tempnam (const char *_DirName ,const char *_FilePrefix );
int _flushall (void );
FILE *fopen (const char *_Filename ,const char *_Mode );
FILE *fopen64 (const char *filename ,const char *mode );
int fputc (int _Ch ,FILE *_File );
int _fputchar (int _Ch );
int fputs (const char *_Str ,FILE *_File );
size_t fread (void *_DstBuf ,size_t _ElementSize ,size_t _Count ,FILE *_File );
FILE *freopen (const char *_Filename ,const char *_Mode ,FILE *_File );
int fsetpos (FILE *_File ,const fpos_t *_Pos );
int fsetpos64 (FILE *_File ,const fpos_t *_Pos );
int fseek (FILE *_File ,long _Offset ,int _Origin );
int fseeko64 (FILE *stream ,_off64_t offset ,int whence );
int fseeko (FILE *stream ,_off_t offset ,int whence );
long ftell (FILE *_File );
_off_t ftello (FILE *stream );
_off64_t ftello64 (FILE *stream );
int _fseeki64 (FILE *_File ,long long _Offset ,int _Origin );
long long _ftelli64 (FILE *_File );
size_t fwrite (const void *_Str ,size_t _Size ,size_t _Count ,FILE *_File );
int getc (FILE *_File );
int getchar (void );
int _getmaxstdio (void );
char *gets (char *_Buffer );
int _getw (FILE *_File );
void perror (const char *_ErrMsg );
int _pclose (FILE *_File );
FILE *_popen (const char *_Command ,const char *_Mode );
int putc (int _Ch ,FILE *_File );
int putchar (int _Ch );
int puts (const char *_Str );
int _putw (int _Word ,FILE *_File );
int remove (const char *_Filename );
int rename (const char *_OldFilename ,const char *_NewFilename );
int _unlink (const char *_Filename );
int unlink (const char *_Filename );
void rewind (FILE *_File );
int _rmtmp (void );
void setbuf (FILE *_File ,char *_Buffer );
int _setmaxstdio (int _Max );
unsigned int _set_output_format (unsigned int _Format );
unsigned int _get_output_format (void );
int setvbuf (FILE *_File ,char *_Buf ,int _Mode ,size_t _Size );
int _scprintf (const char *_Format ,...);
int _snscanf (const char *_Src ,size_t _MaxCount ,const char *_Format ,...);
FILE *tmpfile (void );
char *tmpnam (char *_Buffer );
int ungetc (int _Ch ,FILE *_File );
int _snprintf (char *_Dest ,size_t _Count ,const char *_Format ,...);
int _vsnprintf (char *_Dest ,size_t _Count ,const char *_Format ,va_list _Args );
int __ms_vsnprintf (char *d ,size_t n ,const char *format ,va_list arg );
int __ms_snprintf (char *s ,size_t n ,const char *format ,...);
int _vscprintf (const char *_Format ,va_list _ArgList );
int _set_printf_count_output (int _Value );
int _get_printf_count_output (void );
int __mingw_swscanf (const wchar_t *_Src ,const wchar_t *_Format ,...);
int __mingw_vswscanf (const wchar_t *_Str ,const wchar_t *Format ,va_list argp );
int __mingw_wscanf (const wchar_t *_Format ,...);
int __mingw_vwscanf (const wchar_t *Format ,va_list argp );
int __mingw_fwscanf (FILE *_File ,const wchar_t *_Format ,...);
int __mingw_vfwscanf (FILE *fp ,const wchar_t *Format ,va_list argp );
int __mingw_fwprintf (FILE *_File ,const wchar_t *_Format ,...);
int __mingw_wprintf (const wchar_t *_Format ,...);
int __mingw_vfwprintf (FILE *_File ,const wchar_t *_Format ,va_list _ArgList );
int __mingw_vwprintf (const wchar_t *_Format ,va_list _ArgList );
int __mingw_snwprintf (wchar_t *s ,size_t n ,const wchar_t *format ,...);
int __mingw_vsnwprintf (wchar_t *,size_t ,const wchar_t *,va_list );
int __mingw_swprintf (wchar_t *,const wchar_t *,...);
int __mingw_vswprintf (wchar_t *,const wchar_t *,va_list );
int fwscanf (FILE *_File ,const wchar_t *_Format ,...);
int swscanf (const wchar_t *_Src ,const wchar_t *_Format ,...);
int wscanf (const wchar_t *_Format ,...);
int __ms_vwscanf (const wchar_t *,va_list );
int __ms_vfwscanf (FILE *,const wchar_t *,va_list );
int __ms_vswscanf (const wchar_t *,const wchar_t *,va_list );
int fwprintf (FILE *_File ,const wchar_t *_Format ,...);
int wprintf (const wchar_t *_Format ,...);
int vfwprintf (FILE *_File ,const wchar_t *_Format ,va_list _ArgList );
int vwprintf (const wchar_t *_Format ,va_list _ArgList );
FILE *_wfsopen (const wchar_t *_Filename ,const wchar_t *_Mode ,int _ShFlag );
wint_t fgetwc (FILE *_File );
wint_t _fgetwchar (void );
wint_t fputwc (wchar_t _Ch ,FILE *_File );
wint_t _fputwchar (wchar_t _Ch );
wint_t getwc (FILE *_File );
wint_t getwchar (void );
wint_t putwc (wchar_t _Ch ,FILE *_File );
wint_t putwchar (wchar_t _Ch );
wint_t ungetwc (wint_t _Ch ,FILE *_File );
wchar_t *fgetws (wchar_t *_Dst ,int _SizeInWords ,FILE *_File );
int fputws (const wchar_t *_Str ,FILE *_File );
wchar_t *_getws (wchar_t *_String );
int _putws (const wchar_t *_Str );
int _scwprintf (const wchar_t *_Format ,...);
int _swprintf_c (wchar_t *_DstBuf ,size_t _SizeInWords ,const wchar_t *_Format ,...);
int _vswprintf_c (wchar_t *_DstBuf ,size_t _SizeInWords ,const wchar_t *_Format ,va_list _ArgList );
int _snwprintf (wchar_t *_Dest ,size_t _Count ,const wchar_t *_Format ,...);
int _vsnwprintf (wchar_t *_Dest ,size_t _Count ,const wchar_t *_Format ,va_list _Args );
int __ms_snwprintf (wchar_t *s ,size_t n ,const wchar_t *format ,...);
int __ms_vsnwprintf (wchar_t *,size_t ,const wchar_t *,va_list );
int _swprintf (wchar_t *_Dest ,const wchar_t *_Format ,...);
int _vswprintf (wchar_t *_Dest ,const wchar_t *_Format ,va_list _Args );
wchar_t *_wtempnam (const wchar_t *_Directory ,const wchar_t *_FilePrefix );
int _vscwprintf (const wchar_t *_Format ,va_list _ArgList );
int _snwscanf (const wchar_t *_Src ,size_t _MaxCount ,const wchar_t *_Format ,...);
FILE *_wfdopen (int _FileHandle ,const wchar_t *_Mode );
FILE *_wfopen (const wchar_t *_Filename ,const wchar_t *_Mode );
FILE *_wfreopen (const wchar_t *_Filename ,const wchar_t *_Mode ,FILE *_OldFile );
void _wperror (const wchar_t *_ErrMsg );
FILE *_wpopen (const wchar_t *_Command ,const wchar_t *_Mode );
int _wremove (const wchar_t *_Filename );
wchar_t *_wtmpnam (wchar_t *_Buffer );
wint_t _fgetwc_nolock (FILE *_File );
wint_t _fputwc_nolock (wchar_t _Ch ,FILE *_File );
wint_t _ungetwc_nolock (wint_t _Ch ,FILE *_File );
void _lock_file (FILE *_File );
void _unlock_file (FILE *_File );
int _fclose_nolock (FILE *_File );
int _fflush_nolock (FILE *_File );
size_t _fread_nolock (void *_DstBuf ,size_t _ElementSize ,size_t _Count ,FILE *_File );
int _fseek_nolock (FILE *_File ,long _Offset ,int _Origin );
long _ftell_nolock (FILE *_File );
int _fseeki64_nolock (FILE *_File ,long long _Offset ,int _Origin );
long long _ftelli64_nolock (FILE *_File );
size_t _fwrite_nolock (const void *_DstBuf ,size_t _Size ,size_t _Count ,FILE *_File );
int _ungetc_nolock (int _Ch ,FILE *_File );
char *tempnam (const char *_Directory ,const char *_FilePrefix );
int fcloseall (void );
FILE *fdopen (int _FileHandle ,const char *_Format );
int fgetchar (void );
int fileno (FILE *_File );
int flushall (void );
int fputchar (int _Ch );
int getw (FILE *_File );
int putw (int _Ch ,FILE *_File );
int rmtmp (void );
int __mingw_str_wide_utf8 (const wchar_t *const wptr ,char **mbptr ,size_t *buflen );
int __mingw_str_utf8_wide (const char *const mbptr ,wchar_t **wptr ,size_t *buflen );
void __mingw_str_free (void *ptr );
intptr_t _wspawnl (int _Mode ,const wchar_t *_Filename ,const wchar_t *_ArgList ,...);
intptr_t _wspawnle (int _Mode ,const wchar_t *_Filename ,const wchar_t *_ArgList ,...);
intptr_t _wspawnlp (int _Mode ,const wchar_t *_Filename ,const wchar_t *_ArgList ,...);
intptr_t _wspawnlpe (int _Mode ,const wchar_t *_Filename ,const wchar_t *_ArgList ,...);
intptr_t _wspawnv (int _Mode ,const wchar_t *_Filename ,const wchar_t *const *_ArgList );
intptr_t _wspawnve (int _Mode ,const wchar_t *_Filename ,const wchar_t *const *_ArgList ,const wchar_t *const *_Env );
intptr_t _wspawnvp (int _Mode ,const wchar_t *_Filename ,const wchar_t *const *_ArgList );
intptr_t _wspawnvpe (int _Mode ,const wchar_t *_Filename ,const wchar_t *const *_ArgList ,const wchar_t *const *_Env );
intptr_t _spawnv (int _Mode ,const char *_Filename ,const char *const *_ArgList );
intptr_t _spawnve (int _Mode ,const char *_Filename ,const char *const *_ArgList ,const char *const *_Env );
intptr_t _spawnvp (int _Mode ,const char *_Filename ,const char *const *_ArgList );
intptr_t _spawnvpe (int _Mode ,const char *_Filename ,const char *const *_ArgList ,const char *const *_Env );
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define SEEK_SET (0)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_4(__ret_type, __ret_policy, __decl_spec, __name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1, __arg2_type, __arg2, __arg3_type, __arg3, __arg4_type, __arg4) __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_4_EX ( __ret_type , __ret_policy , __decl_spec , __func_name , __func_name ## _s , __dst_attr , __dst_type , __dst , __arg1_type , __arg1 , __arg2_type , __arg2 , __arg3_type , __arg3 , __arg4_type , __arg4 )
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define L_tmpnam ( sizeof ( _P_tmpdir ) + 12 )
#define pclose _pclose
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\_mingw_off_t.h 

#define _OFF_T_ 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define FOPEN_MAX (20)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _INC_CRTDEFS 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define _wP_tmpdir "\\"
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _TAGLC_ID_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define _INC_STDIO 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _CRTRESTRICT 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define _P_DETACH (4)
#define STDERR_FILENO (2)
#define __MINGW_PRINTF_FORMAT ms_printf
#define SEEK_CUR (1)
#define _getwc_nolock(_c) _fgetwc_nolock ( _c )
#define SEEK_END (2)
#define _iob __iob_func ( )
#define popen _popen
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_1_2(__ret, __func, __type0, __arg0, __dsttype, __dst, __type1, __arg1, __type2, __arg2) 
#define _RSIZE_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define _putchar_nolock(_c) _putc_nolock ( ( _c ) , stdout )
#define BUFSIZ (512)
#define _WSTDIO_DEFINED 
#define _putc_nolock(_c, _stream) _fputc_nolock ( _c , _stream )
#define P_tmpdir _P_tmpdir
#define _IOLBF (64)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_3(__ret_type, __ret_policy, __decl_spec, __name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1, __arg2_type, __arg2, __arg3_type, __arg3) __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_3_EX ( __ret_type , __ret_policy , __decl_spec , __func_name , __func_name ## _s , __dst_attr , __dst_type , __dst , __arg1_type , __arg1 , __arg2_type , __arg2 , __arg3_type , __arg3 )
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define _SYS_OPEN (20)
#define putwc(_c, _stm) fputwc ( _c , _stm )
#define _fgetc_nolock(_stream) ( -- ( _stream ) -> _cnt >= 0 ? 0xff & * ( _stream ) -> _ptr ++ : _filbuf ( _stream ) )
#define _WSPAWN_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_2(__ret, __func, __dsttype, __dst, __type1, __arg1, __type2, __arg2) 
#define _TIME64_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define TMP_MAX (32767)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_1_3(__ret, __func, __type0, __arg0, __dsttype, __dst, __type1, __arg1, __type2, __arg2, __type3, __arg3) 
#define __intptr_t_defined 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\_mingw_off_t.h 

#define _OFF64_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define _FILE_OFFSET_BITS_SET_FTELLO 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_3(__ret, __func, __dsttype, __dst, __type1, __arg1, __type2, __arg2, __type3, __arg3) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\_mingw_off_t.h 

#define _FILE_OFFSET_BITS_SET_OFFT 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __uintptr_t_defined 
#define _CRT_PACKING (8)
#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_3_EX(__ret_type, __ret_policy, __decl_spec, __name, __sec_name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1, __arg2_type, __arg2, __arg3_type, __arg3) 
#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_1_1(__ret, __func, __type0, __arg0, __dsttype, __dst, __type1, __arg1) 
#define _INTPTR_T_DEFINED 
#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_2_0(__ret, __func, __type1, __arg1, __type2, __arg2, __dsttype, __dst) 
#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_4_EX(__ret_type, __ret_policy, __decl_spec, __name, __sec_name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1, __arg2_type, __arg2, __arg3_type, __arg3, __arg4_type, __arg4) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define _FPOSOFF(fp) ( ( long ) ( fp ) )
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __crt_typefix(ctype) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define _OLD_P_OVERLAY (2)
#define _FPOS_T_DEFINED 
#define _TWO_DIGIT_EXPONENT (1)
#define NULL ( ( void * ) 0 )
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _PTRDIFF_T_ 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define STDOUT_FILENO (1)
#define _getwchar_nolock() _getwc_nolock ( stdin )
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _PTRDIFF_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define putwchar(_c) fputwc ( ( _c ) , stdout )
#define _P_OVERLAY (2)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_1(__ret, __func, __dsttype, __dst, __type1, __arg1) 
#define _SIZE_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define _IORW (128)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\_mingw_off_t.h 

#define _OFF_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define getwchar() fgetwc ( stdin )
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _TIME32_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define _P_tmpdir "\\"
#define FILENAME_MAX (260)
#define _WAIT_CHILD (0)
#define _P_NOWAITO (3)
#define _getchar_nolock() _getc_nolock ( stdin )
#define _NFILE _NSTREAM_
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _CRTNOALIAS 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define _IOERR (32)
#define fseeko fseeko64
#define _SPAWNV_DEFINED 
#define _P_WAIT (0)
#define wpopen _wpopen
#define _putwc_nolock(_c, _stm) _fputwc_nolock ( _c , _stm )
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_SPLITPATH(__ret, __func, __dsttype, __src) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define SYS_OPEN _SYS_OPEN
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_1_EX(__ret_type, __ret_policy, __decl_spec, __name, __sec_name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define _CRT_PERROR_DEFINED 
#define STDIN_FILENO (0)
#define _IOEOF (16)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_0(__ret_type, __ret_policy, __decl_spec, __name, __dst_attr, __dst_type, __dst) __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_0_EX ( __ret_type , __ret_policy , __decl_spec , __func_name , __func_name ## _s , __dst_attr , __dst_type , __dst )
#define _THREADLOCALEINFO 
#define _WINT_T 
#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_2(__ret_type, __ret_policy, __decl_spec, __name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1, __arg2_type, __arg2) __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_2_EX ( __ret_type , __ret_policy , __decl_spec , __func_name , __func_name ## _s , __dst_attr , __dst_type , __dst , __arg1_type , __arg1 , __arg2_type , __arg2 )
#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_0(__ret, __func, __dsttype, __dst) 
#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_1(__ret_type, __ret_policy, __decl_spec, __name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1) __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_2_EX ( __ret_type , __ret_policy , __decl_spec , __func_name , __func_name ## _s , __dst_attr , __dst_type , __dst , __arg1_type , __arg1 , __arg2_type , __arg2 )
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define _CRT_WPERROR_DEFINED 
#define _STDIO_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_1_ARGLIST(__ret, __func, __vfunc, __dsttype, __dst, __type1, __arg1) 
#define _ERRCODE_DEFINED 
#define _CRT_SECURE_CPP_NOTHROW throw ( )
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define EOF (-1)
#define _IOSTRG (64)
#define _IOREAD (1)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_4(__ret, __func, __dsttype, __dst, __type1, __arg1, __type2, __arg2, __type3, __arg3, __type4, __arg4) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define _IOFBF (0)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _UINTPTR_T_DEFINED 
#define __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_2_ARGLIST(__ret, __func, __vfunc, __dsttype, __dst, __type1, __arg1, __type2, __arg2) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define _IOWRT (2)
#define _CRT_DIRECTORY_DEFINED 
#define _getc_nolock(_stream) _fgetc_nolock ( _stream )
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _WCTYPE_T_DEFINED 
#define _SSIZE_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define _P_NOWAIT (1)
#define _FILE_OFFSET_BITS_SET_FSEEKO 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_0_EX(__ret_type, __ret_policy, __decl_spec, __name, __sec_name, __dst_attr, __dst_type, __dst) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define __MINGW_SCANF_FORMAT ms_scanf
#define _IONBF (4)
#define _fputc_nolock(_c, _stream) ( -- ( _stream ) -> _cnt >= 0 ? 0xff & ( * ( _stream ) -> _ptr ++ = ( char ) ( _c ) ) : _flsbuf ( ( _c ) , ( _stream ) ) )
#define _IOMYBUF (8)
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _TIME_T_DEFINED 
#define __DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_2_EX(__ret_type, __ret_policy, __decl_spec, __name, __sec_name, __dst_attr, __dst_type, __dst, __arg1_type, __arg1, __arg2_type, __arg2) 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define _IOB_ENTRIES (20)
#define ftello ftello64
#define __MINGW_MBWC_CONVERT_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\crtdefs.h 

#define _WCHAR_T_DEFINED 
// BEGIN OF FILE m:\mingw\x86_64-w64-mingw32\include\stdio.h 

#define _NSTREAM_ (512)
#define WEOF ( wint_t ) ( 0xFFFF )
#define _putwchar_nolock(_c) _putwc_nolock ( ( _c ) , stdout )
#define _WAIT_GRANDCHILD (1)
#define getwc(_stm) fgetwc ( _stm )
