# firmware/

* `original-heltec-v3/`, the original MeshStar v0.1.0-alpha firmware (see its README).
* `bootloader-esp32s3.bin`, stock ESP-IDF 5.2.1 second-stage bootloader for ESP32-S3 (8 MB, DIO, 80 MHz), used by `tools/flash_example.sh … full`.
* `partitions-8mb.bin`, MeshStar partition table: nvs 0x9000, phy_init 0xF000, factory 0x10000 (0x1F0000), spiffs 0x200000.
