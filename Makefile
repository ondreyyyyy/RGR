COMPILER = g++
CFLAGS = -std=c++17 -Wall -fPIC
LDFLAGS = -ldl

OUTPUT = rgrApp
SOURCE = AES.cpp rabbit.cpp chacha20.cpp file.cpp main.cpp

OBJECT_AES = AES.o file.o
OBJECT_RABBIT = rabbit.o file.o
OBJECT_CHACHA = chacha20.o file.o
OBJECT_MAIN = main.o file.o
ALL_OBJECTS = $(OBJECT_AES) $(OBJECT_RABBIT) $(OBJECT_CHACHA) $(OBJECT_MAIN)

LIBRARY_CHACHA = libchacha.so
LIBRARY_RABBIT = librabbit.so
LIBRARY_AES = libaes.so
ALL_LIBS = $(LIBRARY_CHACHA) $(LIBRARY_RABBIT) $(LIBRARY_AES)

.PHONY: all clean

all: $(OUTPUT) $(LIBRARY_CHACHA) $(LIBRARY_RABBIT) $(LIBRARY_AES)

$(LIBRARY_CHACHA): $(OBJECT_CHACHA)
	$(COMPILER) $(CFLAGS) -shared $(OBJECT_CHACHA) -o $@

$(LIBRARY_RABBIT): $(OBJECT_RABBIT)
	$(COMPILER) $(CFLAGS) -shared $(OBJECT_RABBIT) -o $@

$(LIBRARY_AES): $(OBJECT_AES)
	$(COMPILER) $(CFLAGS) -shared $(OBJECT_AES) -o $@

$(OUTPUT): $(OBJECT_MAIN)
	$(COMPILER) $(OBJECT_MAIN) $(LDFLAGS) -o $@

%.o: %.cpp
	$(COMPILER) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(ALL_OBJECTS) $(OUTPUT) $(ALL_LIBS)
