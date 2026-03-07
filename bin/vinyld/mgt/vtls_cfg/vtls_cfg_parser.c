/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1




/* First part of user prologue.  */
#line 1 "mgt/vtls_cfg/vtls_cfg_parser.y"

/*-
 * Copyright (c) 2019 Varnish Software AS
 * All rights reserved.
 *
 * Author: Dag Haavi Finstad <daghf@varnish-software.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * TLS config file parser
 */

#include "config.h"

/*
 * OpenSSL headers include pthread.h, and mgt.h has a check for
 * pthread being included. Define MGT_ALLOW_PTHREAD first.
 */
#define MGT_ALLOW_PTHREAD

#include <openssl/ssl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "mgt/mgt.h"
#include "mgt/mgt_tls_conf.h"
#include "common/heritage.h"

extern FILE *yyin;
int yyget_lineno(void);
void yyerror(struct vtls_cfg *, const char *);
int yylex(void);
extern char vtls_cfg_input_line[512];

static struct vtls_frontend_cfg *cur_fr;
static struct vtls_cert_cfg *cur_cert;


#line 135 "mgt/vtls_cfg/vtls_cfg_parser.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

/* Use api.header.include to #include this header
   instead of duplicating it here.  */
#ifndef YY_YY_MGT_VTLS_CFG_VTLS_CFG_PARSER_H_INCLUDED
# define YY_YY_MGT_VTLS_CFG_VTLS_CFG_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    INT = 258,                     /* INT  */
    UINT = 259,                    /* UINT  */
    BOOL = 260,                    /* BOOL  */
    STRING = 261,                  /* STRING  */
    TOK_CIPHERS = 262,             /* TOK_CIPHERS  */
    TOK_CIPHERSUITES = 263,        /* TOK_CIPHERSUITES  */
    TOK_PREFER_SERVER_CIPHERS = 264, /* TOK_PREFER_SERVER_CIPHERS  */
    TOK_FRONTEND = 265,            /* TOK_FRONTEND  */
    TOK_TLS_PROTOS = 266,          /* TOK_TLS_PROTOS  */
    TOK_SSLv3 = 267,               /* TOK_SSLv3  */
    TOK_TLSv1_0 = 268,             /* TOK_TLSv1_0  */
    TOK_TLSv1_1 = 269,             /* TOK_TLSv1_1  */
    TOK_TLSv1_2 = 270,             /* TOK_TLSv1_2  */
    TOK_TLSv1_3 = 271,             /* TOK_TLSv1_3  */
    TOK_SNI_NOMATCH_ABORT = 272,   /* TOK_SNI_NOMATCH_ABORT  */
    TOK_HOST = 273,                /* TOK_HOST  */
    TOK_PORT = 274,                /* TOK_PORT  */
    TOK_MATCH_GLOBAL = 275,        /* TOK_MATCH_GLOBAL  */
    TOK_PB_CERT = 276,             /* TOK_PB_CERT  */
    TOK_PEM_FILE = 277,            /* TOK_PEM_FILE  */
    TOK_PRIVATE_KEY = 278,         /* TOK_PRIVATE_KEY  */
    TOK_DHPARAM = 279,             /* TOK_DHPARAM  */
    TOK_ECDH_CURVE = 280,          /* TOK_ECDH_CURVE  */
    TOK_NAME = 281                 /* TOK_NAME  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif
/* Token kinds.  */
#define YYEMPTY -2
#define YYEOF 0
#define YYerror 256
#define YYUNDEF 257
#define INT 258
#define UINT 259
#define BOOL 260
#define STRING 261
#define TOK_CIPHERS 262
#define TOK_CIPHERSUITES 263
#define TOK_PREFER_SERVER_CIPHERS 264
#define TOK_FRONTEND 265
#define TOK_TLS_PROTOS 266
#define TOK_SSLv3 267
#define TOK_TLSv1_0 268
#define TOK_TLSv1_1 269
#define TOK_TLSv1_2 270
#define TOK_TLSv1_3 271
#define TOK_SNI_NOMATCH_ABORT 272
#define TOK_HOST 273
#define TOK_PORT 274
#define TOK_MATCH_GLOBAL 275
#define TOK_PB_CERT 276
#define TOK_PEM_FILE 277
#define TOK_PRIVATE_KEY 278
#define TOK_DHPARAM 279
#define TOK_ECDH_CURVE 280
#define TOK_NAME 281

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 65 "mgt/vtls_cfg/vtls_cfg_parser.y"

	int	i;
	char	*s;

#line 245 "mgt/vtls_cfg/vtls_cfg_parser.c"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;


int yyparse (struct vtls_cfg *cfg);


#endif /* !YY_YY_MGT_VTLS_CFG_VTLS_CFG_PARSER_H_INCLUDED  */
/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_INT = 3,                        /* INT  */
  YYSYMBOL_UINT = 4,                       /* UINT  */
  YYSYMBOL_BOOL = 5,                       /* BOOL  */
  YYSYMBOL_STRING = 6,                     /* STRING  */
  YYSYMBOL_TOK_CIPHERS = 7,                /* TOK_CIPHERS  */
  YYSYMBOL_TOK_CIPHERSUITES = 8,           /* TOK_CIPHERSUITES  */
  YYSYMBOL_TOK_PREFER_SERVER_CIPHERS = 9,  /* TOK_PREFER_SERVER_CIPHERS  */
  YYSYMBOL_TOK_FRONTEND = 10,              /* TOK_FRONTEND  */
  YYSYMBOL_TOK_TLS_PROTOS = 11,            /* TOK_TLS_PROTOS  */
  YYSYMBOL_TOK_SSLv3 = 12,                 /* TOK_SSLv3  */
  YYSYMBOL_TOK_TLSv1_0 = 13,               /* TOK_TLSv1_0  */
  YYSYMBOL_TOK_TLSv1_1 = 14,               /* TOK_TLSv1_1  */
  YYSYMBOL_TOK_TLSv1_2 = 15,               /* TOK_TLSv1_2  */
  YYSYMBOL_TOK_TLSv1_3 = 16,               /* TOK_TLSv1_3  */
  YYSYMBOL_TOK_SNI_NOMATCH_ABORT = 17,     /* TOK_SNI_NOMATCH_ABORT  */
  YYSYMBOL_TOK_HOST = 18,                  /* TOK_HOST  */
  YYSYMBOL_TOK_PORT = 19,                  /* TOK_PORT  */
  YYSYMBOL_TOK_MATCH_GLOBAL = 20,          /* TOK_MATCH_GLOBAL  */
  YYSYMBOL_TOK_PB_CERT = 21,               /* TOK_PB_CERT  */
  YYSYMBOL_TOK_PEM_FILE = 22,              /* TOK_PEM_FILE  */
  YYSYMBOL_TOK_PRIVATE_KEY = 23,           /* TOK_PRIVATE_KEY  */
  YYSYMBOL_TOK_DHPARAM = 24,               /* TOK_DHPARAM  */
  YYSYMBOL_TOK_ECDH_CURVE = 25,            /* TOK_ECDH_CURVE  */
  YYSYMBOL_TOK_NAME = 26,                  /* TOK_NAME  */
  YYSYMBOL_27_ = 27,                       /* '='  */
  YYSYMBOL_28_ = 28,                       /* '{'  */
  YYSYMBOL_29_ = 29,                       /* '}'  */
  YYSYMBOL_YYACCEPT = 30,                  /* $accept  */
  YYSYMBOL_CFG = 31,                       /* CFG  */
  YYSYMBOL_CFG_RECORDS = 32,               /* CFG_RECORDS  */
  YYSYMBOL_CFG_RECORD = 33,                /* CFG_RECORD  */
  YYSYMBOL_FRONTEND_REC = 34,              /* FRONTEND_REC  */
  YYSYMBOL_35_1 = 35,                      /* $@1  */
  YYSYMBOL_FRONTEND_BLK = 36,              /* FRONTEND_BLK  */
  YYSYMBOL_FB_RECS = 37,                   /* FB_RECS  */
  YYSYMBOL_FB_REC = 38,                    /* FB_REC  */
  YYSYMBOL_FB_HOST = 39,                   /* FB_HOST  */
  YYSYMBOL_FB_PORT = 40,                   /* FB_PORT  */
  YYSYMBOL_FB_NAME = 41,                   /* FB_NAME  */
  YYSYMBOL_PEM_BLK = 42,                   /* PEM_BLK  */
  YYSYMBOL_PB_RECS = 43,                   /* PB_RECS  */
  YYSYMBOL_PB_REC = 44,                    /* PB_REC  */
  YYSYMBOL_PB_CERT = 45,                   /* PB_CERT  */
  YYSYMBOL_PRIVATE_KEY = 46,               /* PRIVATE_KEY  */
  YYSYMBOL_PB_DHPARAM = 47,                /* PB_DHPARAM  */
  YYSYMBOL_PB_CIPHERS = 48,                /* PB_CIPHERS  */
  YYSYMBOL_PB_CIPHERSUITES = 49,           /* PB_CIPHERSUITES  */
  YYSYMBOL_PB_NAME = 50,                   /* PB_NAME  */
  YYSYMBOL_FB_MATCH_GLOBAL = 51,           /* FB_MATCH_GLOBAL  */
  YYSYMBOL_FB_SNI_NOMATCH_ABORT = 52,      /* FB_SNI_NOMATCH_ABORT  */
  YYSYMBOL_FB_TLS_PROTOS = 53,             /* FB_TLS_PROTOS  */
  YYSYMBOL_FB_TLS_PROTOS_LIST = 54,        /* FB_TLS_PROTOS_LIST  */
  YYSYMBOL_FB_TLS_PROTO = 55,              /* FB_TLS_PROTO  */
  YYSYMBOL_FB_CIPHERS = 56,                /* FB_CIPHERS  */
  YYSYMBOL_FB_CIPHERSUITES = 57,           /* FB_CIPHERSUITES  */
  YYSYMBOL_FB_PREF_SRV_CIPH = 58,          /* FB_PREF_SRV_CIPH  */
  YYSYMBOL_TLS_PROTOS_REC = 59,            /* TLS_PROTOS_REC  */
  YYSYMBOL_TLS_PROTOS_LIST = 60,           /* TLS_PROTOS_LIST  */
  YYSYMBOL_TLS_PROTO = 61,                 /* TLS_PROTO  */
  YYSYMBOL_PREFER_SERVER_CIPHERS_REC = 62, /* PREFER_SERVER_CIPHERS_REC  */
  YYSYMBOL_PEM_FILE_REC = 63,              /* PEM_FILE_REC  */
  YYSYMBOL_64_2 = 64,                      /* $@2  */
  YYSYMBOL_SNI_NOMATCH_ABORT_REC = 65,     /* SNI_NOMATCH_ABORT_REC  */
  YYSYMBOL_CIPHERS_REC = 66,               /* CIPHERS_REC  */
  YYSYMBOL_CIPHERSUITES_REC = 67,          /* CIPHERSUITES_REC  */
  YYSYMBOL_ECDH_CURVE_REC = 68             /* ECDH_CURVE_REC  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;




#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_int8 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
#if defined __GNUC__ && ! defined __ICC && 406 <= __GNUC__ * 100 + __GNUC_MINOR__
# if __GNUC__ * 100 + __GNUC_MINOR__ < 407
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")
# else
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# endif
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if !defined yyoverflow

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* !defined yyoverflow */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  28
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   90

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  30
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  39
/* YYNRULES -- Number of rules.  */
#define YYNRULES  75
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  127

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   281


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    27,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    28,     2,    29,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26
};

#if YYDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,    85,    85,    89,    90,    94,    95,    96,    97,    98,
      99,   100,   101,   105,   113,   113,   122,   124,   125,   129,
     130,   131,   132,   133,   134,   135,   136,   137,   138,   141,
     146,   151,   156,   159,   160,   164,   165,   166,   167,   168,
     169,   172,   178,   184,   190,   197,   204,   211,   216,   221,
     223,   223,   225,   226,   227,   228,   229,   231,   238,   245,
     250,   252,   252,   254,   255,   256,   257,   258,   260,   265,
     280,   280,   294,   298,   303,   308
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if YYDEBUG || 0
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "INT", "UINT", "BOOL",
  "STRING", "TOK_CIPHERS", "TOK_CIPHERSUITES", "TOK_PREFER_SERVER_CIPHERS",
  "TOK_FRONTEND", "TOK_TLS_PROTOS", "TOK_SSLv3", "TOK_TLSv1_0",
  "TOK_TLSv1_1", "TOK_TLSv1_2", "TOK_TLSv1_3", "TOK_SNI_NOMATCH_ABORT",
  "TOK_HOST", "TOK_PORT", "TOK_MATCH_GLOBAL", "TOK_PB_CERT",
  "TOK_PEM_FILE", "TOK_PRIVATE_KEY", "TOK_DHPARAM", "TOK_ECDH_CURVE",
  "TOK_NAME", "'='", "'{'", "'}'", "$accept", "CFG", "CFG_RECORDS",
  "CFG_RECORD", "FRONTEND_REC", "$@1", "FRONTEND_BLK", "FB_RECS", "FB_REC",
  "FB_HOST", "FB_PORT", "FB_NAME", "PEM_BLK", "PB_RECS", "PB_REC",
  "PB_CERT", "PRIVATE_KEY", "PB_DHPARAM", "PB_CIPHERS", "PB_CIPHERSUITES",
  "PB_NAME", "FB_MATCH_GLOBAL", "FB_SNI_NOMATCH_ABORT", "FB_TLS_PROTOS",
  "FB_TLS_PROTOS_LIST", "FB_TLS_PROTO", "FB_CIPHERS", "FB_CIPHERSUITES",
  "FB_PREF_SRV_CIPH", "TLS_PROTOS_REC", "TLS_PROTOS_LIST", "TLS_PROTO",
  "PREFER_SERVER_CIPHERS_REC", "PEM_FILE_REC", "$@2",
  "SNI_NOMATCH_ABORT_REC", "CIPHERS_REC", "CIPHERSUITES_REC",
  "ECDH_CURVE_REC", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-39)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-1)

#define yytable_value_is_error(Yyn) \
  0

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int8 yypact[] =
{
      24,   -25,   -24,   -23,   -17,   -14,   -13,    -8,    -1,    29,
      24,   -39,   -39,   -39,   -39,   -39,   -39,   -39,   -39,   -39,
      30,    31,    33,    -6,    38,    34,    -5,    36,   -39,   -39,
     -39,   -39,   -39,   -39,   -39,   -39,   -39,   -39,   -39,   -39,
      38,   -39,   -39,   -39,   -39,   -39,    -2,   -39,     4,    13,
      16,    17,    18,    20,    21,    35,    37,    39,    32,    -2,
     -39,   -39,   -39,   -39,   -39,   -39,   -39,   -39,   -39,   -39,
     -39,    40,    41,    42,    44,    45,    46,    47,     4,   -39,
     -39,   -39,   -39,   -39,   -39,   -39,    54,    57,    60,    43,
      65,    68,    69,    72,    73,   -39,   -39,    74,    75,    76,
      77,    78,    79,   -39,   -39,   -39,   -39,   -39,   -39,   -39,
     -39,   -39,   -39,    43,   -39,   -39,   -39,   -39,   -39,   -39,
     -39,   -39,   -39,   -39,   -39,   -39,   -39
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_int8 yydefact[] =
{
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       2,     3,     5,     9,    10,     6,    11,     7,     8,    12,
       0,     0,     0,     0,     0,     0,     0,     0,     1,     4,
      73,    74,    68,    13,    14,    63,    64,    65,    66,    67,
      60,    61,    72,    69,    70,    75,     0,    62,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    16,
      17,    19,    20,    21,    23,    24,    25,    26,    27,    28,
      22,     0,     0,     0,     0,     0,     0,     0,    32,    33,
      35,    36,    37,    38,    39,    40,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    15,    18,     0,     0,     0,
       0,     0,     0,    71,    34,    57,    58,    59,    52,    53,
      54,    55,    56,    49,    50,    48,    29,    30,    47,    31,
      44,    45,    41,    42,    43,    46,    51
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -39,   -39,   -39,    80,   -39,   -39,   -39,   -39,    19,   -39,
     -39,   -39,   -39,   -39,     8,   -39,   -39,   -39,   -39,   -39,
     -39,   -39,   -39,   -39,   -39,   -26,   -39,   -39,   -39,   -39,
     -39,    48,   -39,   -38,   -39,   -39,   -39,   -39,   -39
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
       0,     9,    10,    11,    12,    46,    58,    59,    60,    61,
      62,    63,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    64,    65,    66,   113,   114,    67,    68,    69,    13,
      40,    41,    14,    15,    48,    16,    17,    18,    19
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int8 yytable[] =
{
      33,    43,    20,    21,    22,    49,    50,    51,    70,    52,
      23,    71,    72,    24,    25,    53,    54,    55,    56,    26,
       7,    70,    34,    44,    57,    73,    27,    74,    75,    28,
      76,     1,     2,     3,     4,     5,    30,    31,    32,    42,
      86,     6,    45,    87,    88,    89,     7,    90,    91,     8,
      35,    36,    37,    38,    39,   108,   109,   110,   111,   112,
     105,    95,    92,   106,    93,   107,    94,    97,    98,    99,
     115,   100,   101,   102,   116,   117,   103,   118,    96,   119,
     120,   121,   122,   123,   124,   125,   104,   126,    47,     0,
      29
};

static const yytype_int8 yycheck[] =
{
       6,     6,    27,    27,    27,     7,     8,     9,    46,    11,
      27,     7,     8,    27,    27,    17,    18,    19,    20,    27,
      22,    59,    28,    28,    26,    21,    27,    23,    24,     0,
      26,     7,     8,     9,    10,    11,     6,     6,     5,     5,
      27,    17,     6,    27,    27,    27,    22,    27,    27,    25,
      12,    13,    14,    15,    16,    12,    13,    14,    15,    16,
       6,    29,    27,     6,    27,     5,    27,    27,    27,    27,
       5,    27,    27,    27,     6,     6,    29,     5,    59,     6,
       6,     6,     6,     6,     6,     6,    78,   113,    40,    -1,
      10
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,     7,     8,     9,    10,    11,    17,    22,    25,    31,
      32,    33,    34,    59,    62,    63,    65,    66,    67,    68,
      27,    27,    27,    27,    27,    27,    27,    27,     0,    33,
       6,     6,     5,     6,    28,    12,    13,    14,    15,    16,
      60,    61,     5,     6,    28,     6,    35,    61,    64,     7,
       8,     9,    11,    17,    18,    19,    20,    26,    36,    37,
      38,    39,    40,    41,    51,    52,    53,    56,    57,    58,
      63,     7,     8,    21,    23,    24,    26,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    27,    27,    27,    27,
      27,    27,    27,    27,    27,    29,    38,    27,    27,    27,
      27,    27,    27,    29,    44,     6,     6,     5,    12,    13,
      14,    15,    16,    54,    55,     5,     6,     6,     5,     6,
       6,     6,     6,     6,     6,     6,    55
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr1[] =
{
       0,    30,    31,    32,    32,    33,    33,    33,    33,    33,
      33,    33,    33,    34,    35,    34,    36,    37,    37,    38,
      38,    38,    38,    38,    38,    38,    38,    38,    38,    39,
      40,    41,    42,    43,    43,    44,    44,    44,    44,    44,
      44,    45,    46,    47,    48,    49,    50,    51,    52,    53,
      54,    54,    55,    55,    55,    55,    55,    56,    57,    58,
      59,    60,    60,    61,    61,    61,    61,    61,    62,    63,
      64,    63,    65,    66,    67,    68
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     1,     1,     2,     1,     1,     1,     1,     1,
       1,     1,     1,     3,     0,     6,     1,     1,     2,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     3,
       3,     3,     1,     1,     2,     1,     1,     1,     1,     1,
       1,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       1,     2,     1,     1,     1,     1,     1,     3,     3,     3,
       3,     1,     2,     1,     1,     1,     1,     1,     3,     3,
       0,     6,     3,     3,     3,     3
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYNOMEM         goto yyexhaustedlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (cfg, YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Backward compatibility with an undocumented macro.
   Use YYerror or YYUNDEF. */
#define YYERRCODE YYUNDEF


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)




# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value, cfg); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, struct vtls_cfg *cfg)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  YY_USE (cfg);
  if (!yyvaluep)
    return;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, struct vtls_cfg *cfg)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  yy_symbol_value_print (yyo, yykind, yyvaluep, cfg);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp,
                 int yyrule, struct vtls_cfg *cfg)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)], cfg);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule, cfg); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif






/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep, struct vtls_cfg *cfg)
{
  YY_USE (yyvaluep);
  YY_USE (cfg);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/* Lookahead token kind.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;




/*----------.
| yyparse.  |
`----------*/

int
yyparse (struct vtls_cfg *cfg)
{
    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = YYEMPTY; /* Cause a token to be read.  */

  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    YYNOMEM;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        YYNOMEM;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          YYNOMEM;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */


  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = YYEOF;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == YYerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = YYUNDEF;
      yytoken = YYSYMBOL_YYerror;
      goto yyerrlab1;
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 13: /* FRONTEND_REC: TOK_FRONTEND '=' STRING  */
#line 105 "mgt/vtls_cfg/vtls_cfg_parser.y"
                                  {
		AZ(cur_fr);
		cur_fr = VTLS_frontend_cfg_alloc();
		CHECK_OBJ_NOTNULL(cur_fr, VTLS_FRONTEND_CFG_MAGIC);
		REPLACE(cur_fr->argspec, (yyvsp[0].s));
		VTAILQ_INSERT_TAIL(&cfg->frontends, cur_fr, list);
		cur_fr = NULL;
	}
#line 1385 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 14: /* $@1: %empty  */
#line 113 "mgt/vtls_cfg/vtls_cfg_parser.y"
                               {
		AZ(cur_fr);
		cur_fr = VTLS_frontend_cfg_alloc();
		CHECK_OBJ_NOTNULL(cur_fr, VTLS_FRONTEND_CFG_MAGIC);
	}
#line 1395 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 15: /* FRONTEND_REC: TOK_FRONTEND '=' '{' $@1 FRONTEND_BLK '}'  */
#line 117 "mgt/vtls_cfg/vtls_cfg_parser.y"
                           {
		VTAILQ_INSERT_TAIL(&cfg->frontends, cur_fr, list);
		cur_fr = NULL;
	}
#line 1404 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 29: /* FB_HOST: TOK_HOST '=' STRING  */
#line 141 "mgt/vtls_cfg/vtls_cfg_parser.y"
                             {
	if ((yyvsp[0].s))
		REPLACE(cur_fr->host, (yyvsp[0].s));
}
#line 1413 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 30: /* FB_PORT: TOK_PORT '=' STRING  */
#line 146 "mgt/vtls_cfg/vtls_cfg_parser.y"
                             {
	if ((yyvsp[0].s))
		REPLACE(cur_fr->port, (yyvsp[0].s));
}
#line 1422 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 31: /* FB_NAME: TOK_NAME '=' STRING  */
#line 151 "mgt/vtls_cfg/vtls_cfg_parser.y"
                             {
	if ((yyvsp[0].s))
		REPLACE(cur_fr->name, (yyvsp[0].s));
}
#line 1431 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 41: /* PB_CERT: TOK_PB_CERT '=' STRING  */
#line 172 "mgt/vtls_cfg/vtls_cfg_parser.y"
                                {
	CHECK_OBJ_NOTNULL(cur_cert, VTLS_CERT_CFG_MAGIC);
	if ((yyvsp[0].s))
		REPLACE(cur_cert->cert, (yyvsp[0].s));
}
#line 1441 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 42: /* PRIVATE_KEY: TOK_PRIVATE_KEY '=' STRING  */
#line 178 "mgt/vtls_cfg/vtls_cfg_parser.y"
                                        {
	CHECK_OBJ_NOTNULL(cur_cert, VTLS_CERT_CFG_MAGIC);
	if ((yyvsp[0].s))
		REPLACE(cur_cert->priv, (yyvsp[0].s));
}
#line 1451 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 43: /* PB_DHPARAM: TOK_DHPARAM '=' STRING  */
#line 184 "mgt/vtls_cfg/vtls_cfg_parser.y"
                                   {
	CHECK_OBJ_NOTNULL(cur_cert, VTLS_CERT_CFG_MAGIC);
	if ((yyvsp[0].s))
		REPLACE(cur_cert->dhparam, (yyvsp[0].s));
}
#line 1461 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 44: /* PB_CIPHERS: TOK_CIPHERS '=' STRING  */
#line 190 "mgt/vtls_cfg/vtls_cfg_parser.y"
                                   {
	CHECK_OBJ_NOTNULL(cur_cert, VTLS_CERT_CFG_MAGIC);
	if ((yyvsp[0].s)) {
		REPLACE(cur_cert->ciphers, (yyvsp[0].s));
	}
}
#line 1472 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 45: /* PB_CIPHERSUITES: TOK_CIPHERSUITES '=' STRING  */
#line 197 "mgt/vtls_cfg/vtls_cfg_parser.y"
                                             {
	CHECK_OBJ_NOTNULL(cur_cert, VTLS_CERT_CFG_MAGIC);
	if ((yyvsp[0].s)) {
		REPLACE(cur_cert->ciphersuites, (yyvsp[0].s));
	}
}
#line 1483 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 46: /* PB_NAME: TOK_NAME '=' STRING  */
#line 204 "mgt/vtls_cfg/vtls_cfg_parser.y"
                             {
	CHECK_OBJ_NOTNULL(cur_cert, VTLS_CERT_CFG_MAGIC);
	if ((yyvsp[0].s)) {
		REPLACE(cur_cert->id, (yyvsp[0].s));
	}
}
#line 1494 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 47: /* FB_MATCH_GLOBAL: TOK_MATCH_GLOBAL '=' BOOL  */
#line 211 "mgt/vtls_cfg/vtls_cfg_parser.y"
                                           {
	CHECK_OBJ_NOTNULL(cur_fr, VTLS_FRONTEND_CFG_MAGIC);
	cur_fr->sni_match_global = (yyvsp[0].i);
}
#line 1503 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 48: /* FB_SNI_NOMATCH_ABORT: TOK_SNI_NOMATCH_ABORT '=' BOOL  */
#line 216 "mgt/vtls_cfg/vtls_cfg_parser.y"
                                                    {
	CHECK_OBJ_NOTNULL(cur_fr, VTLS_FRONTEND_CFG_MAGIC);
	cur_fr->opts->sni_nomatch_abort = (yyvsp[0].i);
}
#line 1512 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 52: /* FB_TLS_PROTO: TOK_SSLv3  */
#line 225 "mgt/vtls_cfg/vtls_cfg_parser.y"
                      { cur_fr->opts->protos |= SSLv3_PROTO;   }
#line 1518 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 53: /* FB_TLS_PROTO: TOK_TLSv1_0  */
#line 226 "mgt/vtls_cfg/vtls_cfg_parser.y"
                      { cur_fr->opts->protos |= TLSv1_0_PROTO; }
#line 1524 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 54: /* FB_TLS_PROTO: TOK_TLSv1_1  */
#line 227 "mgt/vtls_cfg/vtls_cfg_parser.y"
                      { cur_fr->opts->protos |= TLSv1_1_PROTO; }
#line 1530 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 55: /* FB_TLS_PROTO: TOK_TLSv1_2  */
#line 228 "mgt/vtls_cfg/vtls_cfg_parser.y"
                      { cur_fr->opts->protos |= TLSv1_2_PROTO; }
#line 1536 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 56: /* FB_TLS_PROTO: TOK_TLSv1_3  */
#line 229 "mgt/vtls_cfg/vtls_cfg_parser.y"
                      { cur_fr->opts->protos |= TLSv1_3_PROTO; }
#line 1542 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 57: /* FB_CIPHERS: TOK_CIPHERS '=' STRING  */
#line 231 "mgt/vtls_cfg/vtls_cfg_parser.y"
                                   {
	if ((yyvsp[0].s)) {
		CHECK_OBJ_NOTNULL(cur_fr, VTLS_FRONTEND_CFG_MAGIC);
		REPLACE(cur_fr->opts->ciphers, (yyvsp[0].s));
	}
}
#line 1553 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 58: /* FB_CIPHERSUITES: TOK_CIPHERSUITES '=' STRING  */
#line 238 "mgt/vtls_cfg/vtls_cfg_parser.y"
                                             {
	if ((yyvsp[0].s)) {
		CHECK_OBJ_NOTNULL(cur_fr, VTLS_FRONTEND_CFG_MAGIC);
		REPLACE(cur_fr->opts->ciphersuites, (yyvsp[0].s));
	}
}
#line 1564 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 59: /* FB_PREF_SRV_CIPH: TOK_PREFER_SERVER_CIPHERS '=' BOOL  */
#line 245 "mgt/vtls_cfg/vtls_cfg_parser.y"
                                                     {
	CHECK_OBJ_NOTNULL(cur_fr, VTLS_FRONTEND_CFG_MAGIC);
	cur_fr->opts->prefer_server_ciphers = (yyvsp[0].i);
}
#line 1573 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 63: /* TLS_PROTO: TOK_SSLv3  */
#line 254 "mgt/vtls_cfg/vtls_cfg_parser.y"
                      { cfg->opts->protos |= SSLv3_PROTO;   }
#line 1579 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 64: /* TLS_PROTO: TOK_TLSv1_0  */
#line 255 "mgt/vtls_cfg/vtls_cfg_parser.y"
                      { cfg->opts->protos |= TLSv1_0_PROTO; }
#line 1585 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 65: /* TLS_PROTO: TOK_TLSv1_1  */
#line 256 "mgt/vtls_cfg/vtls_cfg_parser.y"
                      { cfg->opts->protos |= TLSv1_1_PROTO; }
#line 1591 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 66: /* TLS_PROTO: TOK_TLSv1_2  */
#line 257 "mgt/vtls_cfg/vtls_cfg_parser.y"
                      { cfg->opts->protos |= TLSv1_2_PROTO; }
#line 1597 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 67: /* TLS_PROTO: TOK_TLSv1_3  */
#line 258 "mgt/vtls_cfg/vtls_cfg_parser.y"
                      { cfg->opts->protos |= TLSv1_3_PROTO; }
#line 1603 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 68: /* PREFER_SERVER_CIPHERS_REC: TOK_PREFER_SERVER_CIPHERS '=' BOOL  */
#line 260 "mgt/vtls_cfg/vtls_cfg_parser.y"
                                                              {
	cfg->opts->prefer_server_ciphers = (yyvsp[0].i);
}
#line 1611 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 69: /* PEM_FILE_REC: TOK_PEM_FILE '=' STRING  */
#line 265 "mgt/vtls_cfg/vtls_cfg_parser.y"
                                  {
		if ((yyvsp[0].s)) {
			ALLOC_OBJ(cur_cert, VTLS_CERT_CFG_MAGIC);
			AN(cur_cert);
			REPLACE(cur_cert->cert, (yyvsp[0].s));
			if (cur_fr != NULL) {
				CHECK_OBJ_NOTNULL(cur_fr,
				    VTLS_FRONTEND_CFG_MAGIC);
				VTAILQ_INSERT_TAIL(&cur_fr->certs,
				    cur_cert, list);
			} else
				VTAILQ_INSERT_TAIL(&cfg->certs, cur_cert, list);
			cur_cert = NULL;
		}
	}
#line 1631 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 70: /* $@2: %empty  */
#line 280 "mgt/vtls_cfg/vtls_cfg_parser.y"
                               {
		/* NB: Mid-rule action */
		AZ(cur_cert);
		ALLOC_OBJ(cur_cert, VTLS_CERT_CFG_MAGIC);
	}
#line 1641 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 71: /* PEM_FILE_REC: TOK_PEM_FILE '=' '{' $@2 PEM_BLK '}'  */
#line 285 "mgt/vtls_cfg/vtls_cfg_parser.y"
                    {
		if (cur_fr != NULL) {
			CHECK_OBJ_NOTNULL(cur_fr, VTLS_FRONTEND_CFG_MAGIC);
			VTAILQ_INSERT_TAIL(&cur_fr->certs, cur_cert, list);
		} else
			VTAILQ_INSERT_TAIL(&cfg->certs, cur_cert, list);
		cur_cert = NULL;
	}
#line 1654 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 72: /* SNI_NOMATCH_ABORT_REC: TOK_SNI_NOMATCH_ABORT '=' BOOL  */
#line 294 "mgt/vtls_cfg/vtls_cfg_parser.y"
                                                       {
	cfg->opts->sni_nomatch_abort = (yyvsp[0].i);
}
#line 1662 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 73: /* CIPHERS_REC: TOK_CIPHERS '=' STRING  */
#line 298 "mgt/vtls_cfg/vtls_cfg_parser.y"
                                    {
	if ((yyvsp[0].s))
		REPLACE(cfg->opts->ciphers, (yyvsp[0].s));
}
#line 1671 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 74: /* CIPHERSUITES_REC: TOK_CIPHERSUITES '=' STRING  */
#line 303 "mgt/vtls_cfg/vtls_cfg_parser.y"
                                              {
	if ((yyvsp[0].s))
		REPLACE(cfg->opts->ciphersuites, (yyvsp[0].s));
}
#line 1680 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;

  case 75: /* ECDH_CURVE_REC: TOK_ECDH_CURVE '=' STRING  */
#line 308 "mgt/vtls_cfg/vtls_cfg_parser.y"
                                          {
	if ((yyvsp[0].s))
		REPLACE(cfg->opts->ecdh_curve, (yyvsp[0].s));
}
#line 1689 "mgt/vtls_cfg/vtls_cfg_parser.c"
    break;


#line 1693 "mgt/vtls_cfg/vtls_cfg_parser.c"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      yyerror (cfg, YY_("syntax error"));
    }

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval, cfg);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;
  ++yynerrs;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp, cfg);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturnlab;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturnlab;


/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
  yyerror (cfg, YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturnlab;


/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval, cfg);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp, cfg);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif

  return yyresult;
}

#line 313 "mgt/vtls_cfg/vtls_cfg_parser.y"


void
yyerror(struct vtls_cfg *cfg, const char *s)
{
	(void) cfg;
	ARGV_ERR("-A: "
	    "Parsing error in line %d: %s: '%s'\n",
	    yyget_lineno(), s, strlen(vtls_cfg_input_line) > 0 ?
	    vtls_cfg_input_line : "");
}
