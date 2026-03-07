/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

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

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

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

#line 124 "mgt/vtls_cfg/vtls_cfg_parser.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;


int yyparse (struct vtls_cfg *cfg);


#endif /* !YY_YY_MGT_VTLS_CFG_VTLS_CFG_PARSER_H_INCLUDED  */
