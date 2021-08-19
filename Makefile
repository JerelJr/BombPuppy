CPP_FLAGS := -Wall 
DEBUG_FLAGS := -g -pg
CXX := g++
CXX_SOURCES := $(wildcard *.cpp)
OBJECTS := *.o
PROJ_NAME := PacketSniffer

debug-cpp: $(CXX_SOURCES) 
	$(CXX) $(DEBUG_FLAGS) $(CXX_SOURCES) -o $(PROJ_NAME)-debug $(CPP_FLAGS)

$(PROJ_NAME): $(CXX_SOURCES) 
	$(CXX) $(CXX_SOURCES) -o $(PROJ_NAME) $(CPP_FLAGS) 

clean: 
	rm -f *~ include/*~ src/*~