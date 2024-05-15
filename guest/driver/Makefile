veil_driver-y := main.o log.o
obj-m += veil_driver.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules -j$(nproc)
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
install:
	sudo insmod veil_driver.ko
install-logging:
	sudo insmod veil_driver.ko logging_service = true
remove:
	sudo rmmod veil_driver

# host-* are mainly for debugging purposes
host:
	make -C `pwd`/../kernel/linux M=$(PWD) modules -j$(nproc)
host-clean:
	make -C `pwd`/../kernel/linux M=$(PWD) clean