#include "Global.h"

UINT16 COM1 = 0x3F8;
UINT16 COM2 = 0x2F8;
UINT16 COM3 = 0x3E8;

UINT16 LastUsedPort = 0x0;

void DebugInit(const UINT16 port)
{
    LastUsedPort = port;

    __outbyte(LastUsedPort + 1, 0x00);  // Disable interrupts
    __outbyte(LastUsedPort + 3, 0x80);  // Enable DLAB (set baud rate divisor)
    __outbyte(LastUsedPort + 0, 0x01);  // Set divisor to 1 (low byte, 115200 baud)
    __outbyte(LastUsedPort + 1, 0x00);  // High byte of divisor
    __outbyte(LastUsedPort + 3, 0x03);  // 8 bits, no parity, one stop bit
    __outbyte(LastUsedPort + 2, 0xC7);  // Enable FIFO, clear them, with 14-byte threshold
    __outbyte(LastUsedPort + 4, 0x0B);  // IRQs enabled, RTS/DSR set
}

void DebugWrite(const char c)
{
    while (!(__inbyte(LastUsedPort + 5) & 0x20))
    {
        /**/
    }

    __outbyte(LastUsedPort, c);
}

void DebugMessage(const char* message)
{
    while (*message)
    {
        DebugWrite(*message++);
    }
}

void DebugFormat(const char* format, ...)
{
    CHAR8 buffer[512];
    VA_LIST marker;

    VA_START(marker, format);
    AsciiVSPrint(buffer, sizeof(buffer), format, marker);
    VA_END(marker);

    DebugMessage(buffer);
}