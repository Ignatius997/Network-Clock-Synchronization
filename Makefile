# Kompilator i flagi
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g -Iinclude
TARGET = netclocksync

# Katalogi
SRC_DIR = src
BUILD_DIR = build
INCLUDE_DIR = include

# Pliki źródłowe i obiektowe
SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRC))

# Reguła budowania obiektów
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
    $(CC) $(CFLAGS) -c $< -o $@

# Reguła budowania programu
$(TARGET): $(OBJ)
    $(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $^

# Reguła główna
all: $(BUILD_DIR) $(TARGET)

# Tworzenie katalogu build
$(BUILD_DIR):
    mkdir -p $(BUILD_DIR)

# Czyszczenie
clean:
    rm -f $(OBJ) $(BUILD_DIR)/$(TARGET)
    rm -rf $(BUILD_DIR)