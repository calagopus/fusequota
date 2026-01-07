BUILD_DIR := build
INSTALL_DIR := /usr/local/bin
TARGET_NAME := fusequota

.PHONY: all clean install libfuse help

all: libfuse $(BUILD_DIR)/Makefile
	@echo "--- Building Project ---"
	$(MAKE) -C $(BUILD_DIR)

libfuse:
	@echo "--- Building libfuse (Static) ---"
	@if [ ! -d "external/libfuse/build" ]; then \
		meson setup external/libfuse external/libfuse/build --default-library=static; \
	else \
		meson configure external/libfuse/build --default-library=static; \
	fi
	ninja -C external/libfuse/build

$(BUILD_DIR)/Makefile:
	@echo "--- Configuring CMake ---"
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake ..

install: all
	@echo "--- Installing Binary ---"
	sudo install -m 755 $(BUILD_DIR)/$(TARGET_NAME) $(INSTALL_DIR)

clean:
	@echo "--- Cleaning Build Files ---"
	rm -rf $(BUILD_DIR)
	@# Optional: clean libfuse build as well
	@# rm -rf external/libfuse/build

help:
	@echo "Usage:"
	@echo "  make         - Build libfuse and the main project"
	@echo "  make install - Build and install the binary to $(INSTALL_DIR)"
	@echo "  make clean   - Remove build directories"
