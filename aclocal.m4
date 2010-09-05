AC_DEFUN(AC_CHECK_DEF,
[ac_hdrs=""
for ac_hdr in $1
do
ac_hdrs="$ac_hdrs
#include <$ac_hdr>"
done
for ac_obj in $2
do
ac_hdrs="$ac_hdrs
extern float $ac_obj;"
done
AC_TRY_COMPILE([$ac_hdrs],,[$4],[$3])])
