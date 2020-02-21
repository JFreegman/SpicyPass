CPPFLAGS = -std=c++17 -Wall -Werror -g -fstack-protector-all
CFLAGS = `pkg-config --cflags  libsodium`
LDFLAGS = `pkg-config --libs libsodium`
OBJ = based.o load.o password.o util.o crypto.o
SRC_DIR = ./src

all: $(OBJ)
	@echo "  LD    $@"
	@$(CXX) $(CPPFLAGS) $(CFLAGS) -o based $(OBJ) $(LDFLAGS)

%.o: $(SRC_DIR)/%.cpp
	@echo "  $(CXX)   $@"
	@$(CXX) $(CPPFLAGS) $(CFLAGS) -o $*.o -c $(SRC_DIR)/$*.cpp

clean:
	rm -f *.o based

.PHONY: clean all
