# 內核模組設定
obj-m += firewall.o
KDIR := /lib/modules/$(shell uname -r)/build

# 編譯器設定
CC = gcc       # C 編譯器
CXX = g++      # C++ 編譯器

# 用戶空間程式
C_PROG := main
CPP_PROG := server

# 預設目標
all: kernel_module $(C_PROG) $(CPP_PROG)

# 編譯內核模組
kernel_module:
	make -C $(KDIR) M=$(PWD) modules

# 編譯 C 程式
$(C_PROG): $(C_PROG).c
	$(CC) -o $@ $<

# 編譯 C++ 程式
$(CPP_PROG): $(CPP_PROG).cpp
	$(CXX) -o $@ $<

# 清理目標
clean:
	make -C $(KDIR) M=$(PWD) clean
	$(RM) $(C_PROG) $(CPP_PROG)