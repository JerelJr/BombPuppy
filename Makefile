CPP_FLAGS := -Wall -std=c++20
DEBUG_FLAGS := -g -pg
CXX := g++
CXX_SOURCES := src/*.cpp
OBJECTS := *.o
PROJ_NAME := BombPuppy
EXEC_NAME := sniffer

$(PROJ_NAME): $(CXX_SOURCES) 
	$(CXX) $(CXX_SOURCES) -o $(EXEC_NAME) $(CPP_FLAGS) 

debug-cpp: $(CXX_SOURCES) 
	$(CXX) $(DEBUG_FLAGS) $(CXX_SOURCES) -o $(EXEC_NAME)-debug $(CPP_FLAGS)
	
clean: 
	rm -f *~ include/*~ src/*~