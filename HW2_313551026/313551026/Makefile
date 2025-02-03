# Indicate that targets "all" and "clean" are not files
.PHONY: all clean

# Set compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Werror -O3 -Wpedantic
OUTPUT_OPTION = -MMD -MP -o $@

# Define source, object, dependency, and target files
SOURCE = sched_demo_313551026.c
OBJS = $(SOURCE:.c=.o)
DEPS = $(SOURCE:.c=.d)
TARGET = sched_demo_313551026

# Default target
all: $(TARGET)

# Include dependency files if they exist
-include $(DEPS)

# Rule to compile .c files to .o files
%.o: %.c
	$(CC) $(CFLAGS) -c $< $(OUTPUT_OPTION)

# Rule to link object files to create the final executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@

# Clean up generated files
clean:
	@rm -f $(TARGET) $(OBJS) $(DEPS)
