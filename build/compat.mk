# Conditionals via include, compatible with most implementations of make

# GNU make 3.81 or earlier
MAKE_FLAVOR:= gnu
# POSIX 2024, BSD, GNU make 3.82+, etc
MAKE_FLAVOR!= echo posix

include	build/compat-$(MAKE_FLAVOR).mk
