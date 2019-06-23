CPPFLAGS = -std=c++17 -Wall -Werror -g
OBJ = based.o load.o password.o
SRC_DIR = ./src

all: $(OBJ)
	@echo "  LD    $@"
	@$(CXX) $(CPPFLAGS) -o based $(OBJ)

%.o: $(SRC_DIR)/%.cpp
	@echo "  $(CXX)   $@"
	@$(CXX) $(CPPFLAGS) -o $*.o -c $(SRC_DIR)/$*.cpp

clean:
	rm -f *.o based

.PHONY: clean all
