CC = gcc
CFLAGS = -Wall -Wextra -O0 -g
TARGET = netclocksync

SRC_DIR = src
BUILD_DIR = build

SRC = $(SRC_DIR)/main.c
OBJ = $(BUILD_DIR)/main.o

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $^
	@rm -f $(OBJ)

all: $(BUILD_DIR) $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -f $(OBJ) $(BUILD_DIR)/$(TARGET)
	rm -rf $(BUILD_DIR)