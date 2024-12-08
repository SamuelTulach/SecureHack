#pragma once

extern UINT16 COM1;
extern UINT16 COM2;
extern UINT16 COM3;

void DebugInit(UINT16 port);
void DebugWrite(char c);
void DebugMessage(const char* message);
void DebugFormat(const char* format, ...);