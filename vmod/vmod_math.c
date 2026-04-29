
/* this code is auto-generated. Do not edit */
#include "config.h"

#include <float.h>
#include <math.h>

#include "vdef.h"
#include "vas.h"
#include "vrt.h"
#include "vcc_math_if.h"

// macros in math.h code are generic-ish across float/double/long double
//lint --e{506} Constant value Boolean
//lint --e{736} Loss of precision

VCL_REAL
vmod_constant(VRT_CTX, VCL_ENUM name)
{
    (void)ctx;

    if (name == VENUM(DBL_MANT_DIG)) return (DBL_MANT_DIG);

    if (name == VENUM(DBL_DIG)) return (DBL_DIG);

    if (name == VENUM(DBL_MIN_EXP)) return (DBL_MIN_EXP);

    if (name == VENUM(DBL_MIN_10_EXP)) return (DBL_MIN_10_EXP);

    if (name == VENUM(DBL_MAX_EXP)) return (DBL_MAX_EXP);

    if (name == VENUM(DBL_MAX_10_EXP)) return (DBL_MAX_10_EXP);

    if (name == VENUM(DBL_MAX)) return (DBL_MAX);

    if (name == VENUM(DBL_EPSILON)) return (DBL_EPSILON);

    if (name == VENUM(DBL_MIN)) return (DBL_MIN);

    if (name == VENUM(HUGE_VAL)) return (HUGE_VAL);

    if (name == VENUM(M_E)) return (M_E);

    if (name == VENUM(M_LOG2E)) return (M_LOG2E);

    if (name == VENUM(M_LOG10E)) return (M_LOG10E);

    if (name == VENUM(M_LN2)) return (M_LN2);

    if (name == VENUM(M_LN10)) return (M_LN10);

    if (name == VENUM(M_PI)) return (M_PI);

    if (name == VENUM(M_PI_2)) return (M_PI_2);

    if (name == VENUM(M_PI_4)) return (M_PI_4);

    if (name == VENUM(M_1_PI)) return (M_1_PI);

    if (name == VENUM(M_2_PI)) return (M_2_PI);

    if (name == VENUM(M_2_SQRTPI)) return (M_2_SQRTPI);

    if (name == VENUM(M_SQRT2)) return (M_SQRT2);

    if (name == VENUM(M_SQRT1_2)) return (M_SQRT1_2);

    WRONG("constant enum");
}

VCL_INT
vmod_fpclass(VRT_CTX, VCL_ENUM name)
{
    (void)ctx;

    if (name == VENUM(FP_INFINITE)) return (FP_INFINITE);

    if (name == VENUM(FP_NAN)) return (FP_NAN);

    if (name == VENUM(FP_NORMAL)) return (FP_NORMAL);

    if (name == VENUM(FP_SUBNORMAL)) return (FP_SUBNORMAL);

    if (name == VENUM(FP_ZERO)) return (FP_ZERO);

    WRONG("fpclass enum");
}

VCL_INT
vmod_fpclassify(VRT_CTX, VCL_REAL  x)
{
	(void)ctx;
	return (fpclassify(x));
}

VCL_INT
vmod_isfinite(VRT_CTX, VCL_REAL  x)
{
	(void)ctx;
	return (isfinite(x));
}

VCL_INT
vmod_isgreater(VRT_CTX, VCL_REAL  x, VCL_REAL  y)
{
	(void)ctx;
	return (isgreater(x, y));
}

VCL_INT
vmod_isgreaterequal(VRT_CTX, VCL_REAL  x, VCL_REAL  y)
{
	(void)ctx;
	return (isgreaterequal(x, y));
}

VCL_INT
vmod_isinf(VRT_CTX, VCL_REAL  x)
{
	(void)ctx;
	return (isinf(x));
}

VCL_INT
vmod_isless(VRT_CTX, VCL_REAL  x, VCL_REAL  y)
{
	(void)ctx;
	return (isless(x, y));
}

VCL_INT
vmod_islessequal(VRT_CTX, VCL_REAL  x, VCL_REAL  y)
{
	(void)ctx;
	return (islessequal(x, y));
}

VCL_INT
vmod_islessgreater(VRT_CTX, VCL_REAL  x, VCL_REAL  y)
{
	(void)ctx;
	return (islessgreater(x, y));
}

VCL_INT
vmod_isnan(VRT_CTX, VCL_REAL  x)
{
	(void)ctx;
	return (isnan(x));
}

VCL_INT
vmod_isnormal(VRT_CTX, VCL_REAL  x)
{
	(void)ctx;
	return (isnormal(x));
}

VCL_INT
vmod_isunordered(VRT_CTX, VCL_REAL  x, VCL_REAL  y)
{
	(void)ctx;
	return (isunordered(x, y));
}

VCL_INT
vmod_signbit(VRT_CTX, VCL_REAL  x)
{
	(void)ctx;
	return (signbit(x));
}

VCL_REAL
vmod_acos(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (acos(x));
}

VCL_REAL
vmod_acosh(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (acosh(x));
}

VCL_REAL
vmod_asin(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (asin(x));
}

VCL_REAL
vmod_asinh(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (asinh(x));
}

VCL_REAL
vmod_atan(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (atan(x));
}

VCL_REAL
vmod_atan2(VRT_CTX, VCL_REAL y, VCL_REAL x)
{
	(void)ctx;
	return (atan2(y, x));
}

VCL_REAL
vmod_atanh(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (atanh(x));
}

VCL_REAL
vmod_cbrt(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (cbrt(x));
}

VCL_REAL
vmod_ceil(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (ceil(x));
}

VCL_REAL
vmod_copysign(VRT_CTX, VCL_REAL x, VCL_REAL y)
{
	(void)ctx;
	return (copysign(x, y));
}

VCL_REAL
vmod_cos(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (cos(x));
}

VCL_REAL
vmod_cosh(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (cosh(x));
}

VCL_REAL
vmod_erf(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (erf(x));
}

VCL_REAL
vmod_erfc(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (erfc(x));
}

VCL_REAL
vmod_exp(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (exp(x));
}

VCL_REAL
vmod_exp2(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (exp2(x));
}

VCL_REAL
vmod_expm1(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (expm1(x));
}

VCL_REAL
vmod_fabs(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (fabs(x));
}

VCL_REAL
vmod_fdim(VRT_CTX, VCL_REAL x, VCL_REAL y)
{
	(void)ctx;
	return (fdim(x, y));
}

VCL_REAL
vmod_floor(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (floor(x));
}

VCL_REAL
vmod_fma(VRT_CTX, VCL_REAL x, VCL_REAL y, VCL_REAL z)
{
	(void)ctx;
	return (fma(x, y, z));
}

VCL_REAL
vmod_fmax(VRT_CTX, VCL_REAL x, VCL_REAL y)
{
	(void)ctx;
	return (fmax(x, y));
}

VCL_REAL
vmod_fmin(VRT_CTX, VCL_REAL x, VCL_REAL y)
{
	(void)ctx;
	return (fmin(x, y));
}

VCL_REAL
vmod_fmod(VRT_CTX, VCL_REAL x, VCL_REAL y)
{
	(void)ctx;
	return (fmod(x, y));
}

VCL_REAL
vmod_hypot(VRT_CTX, VCL_REAL x, VCL_REAL y)
{
	(void)ctx;
	return (hypot(x, y));
}

VCL_INT
vmod_ilogb(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (ilogb(x));
}

VCL_REAL
vmod_j0(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (j0(x));
}

VCL_REAL
vmod_j1(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (j1(x));
}

VCL_REAL
vmod_jn(VRT_CTX, VCL_INT x, VCL_REAL y)
{
	(void)ctx;
	return (jn(x, y));
}

VCL_REAL
vmod_ldexp(VRT_CTX, VCL_REAL x, VCL_INT e)
{
	(void)ctx;
	return (ldexp(x, e));
}

VCL_REAL
vmod_lgamma(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (lgamma(x));
}

VCL_REAL
vmod_log(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (log(x));
}

VCL_REAL
vmod_log10(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (log10(x));
}

VCL_REAL
vmod_log1p(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (log1p(x));
}

VCL_REAL
vmod_log2(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (log2(x));
}

VCL_REAL
vmod_logb(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (logb(x));
}

VCL_INT
vmod_lrint(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (lrint(x));
}

VCL_INT
vmod_lround(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (lround(x));
}

VCL_REAL
vmod_nan(VRT_CTX, VCL_STRING tag)
{
	(void)ctx;
	return (nan(tag));
}

VCL_REAL
vmod_nearbyint(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (nearbyint(x));
}

VCL_REAL
vmod_nextafter(VRT_CTX, VCL_REAL x, VCL_REAL y)
{
	(void)ctx;
	return (nextafter(x, y));
}

VCL_REAL
vmod_pow(VRT_CTX, VCL_REAL x, VCL_REAL y)
{
	(void)ctx;
	return (pow(x, y));
}

VCL_REAL
vmod_remainder(VRT_CTX, VCL_REAL x, VCL_REAL y)
{
	(void)ctx;
	return (remainder(x, y));
}

VCL_REAL
vmod_rint(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (rint(x));
}

VCL_REAL
vmod_round(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (round(x));
}

VCL_REAL
vmod_scalbln(VRT_CTX, VCL_REAL x, VCL_INT e)
{
	(void)ctx;
	return (scalbln(x, e));
}

VCL_REAL
vmod_scalbn(VRT_CTX, VCL_REAL x, VCL_INT y)
{
	(void)ctx;
	return (scalbn(x, y));
}

VCL_REAL
vmod_sin(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (sin(x));
}

VCL_REAL
vmod_sinh(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (sinh(x));
}

VCL_REAL
vmod_sqrt(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (sqrt(x));
}

VCL_REAL
vmod_tan(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (tan(x));
}

VCL_REAL
vmod_tanh(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (tanh(x));
}

VCL_REAL
vmod_tgamma(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (tgamma(x));
}

VCL_REAL
vmod_trunc(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (trunc(x));
}

VCL_REAL
vmod_y0(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (y0(x));
}

VCL_REAL
vmod_y1(VRT_CTX, VCL_REAL x)
{
	(void)ctx;
	return (y1(x));
}

VCL_REAL
vmod_yn(VRT_CTX, VCL_INT n, VCL_REAL x)
{
	(void)ctx;
	return (yn(n, x));
}
