# Nazwa binarnego pliku wynikowego
TARGET = $(BUILD_DIR)/netclocksync

# Katalogi
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build

# Kompilator i flagi
CC = gcc
DEBUG = -O0 -g
RELEASE = -O2 -DNDEBUG
CFLAGS = -I$(INCLUDE_DIR) -Wall -Wextra $(DEBUG)
LDFLAGS = 

# Pliki źródłowe i obiektowe
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

# Reguła główna
all: $(TARGET)

# Tworzenie pliku binarnego
$(TARGET): $(OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

# Kompilacja plików .c do obiektów .o
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Czyszczenie plików wynikowych
clean:
	rm -rf $(BUILD_DIR)

# Dodanie reguły PHONY (nie dotyczy plików)
.PHONY: all clean