CPP_FLAGS := -Wall 
DEBUG_FLAGS := -g -pg
CXX := g++
CXX_SOURCES := src/*.cpp
OBJECTS := *.o
PROJ_NAME := BombPuppy

$(PROJ_NAME): $(CXX_SOURCES) 
	$(CXX) $(CXX_SOURCES) -o $(PROJ_NAME) $(CPP_FLAGS) 

debug-cpp: $(CXX_SOURCES) 
	$(CXX) $(DEBUG_FLAGS) $(CXX_SOURCES) -o $(PROJ_NAME)-debug $(CPP_FLAGS)
	
clean: 
	rm -f *~ include/*~ src/*~