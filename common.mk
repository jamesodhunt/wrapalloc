# Note we disable all optimisation and add debug symbols - the whole
# point of this library is to be useful in debugging some other failing
# application so make it as useful as possible.
AM_CFLAGS = \
  -Wall \
  -pedantic \
  -std=gnu99 \
  -O0 \
  -ggdb
