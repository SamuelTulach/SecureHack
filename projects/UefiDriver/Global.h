#pragma once

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/PrintLib.h>
#include <Protocol/LoadedImage.h>
#include <IndustryStandard/PeImage.h>
#include <intrin.h>

#include "WinDefines.h"
#include "Utils.h"
#include "LightHook.h"
#include "Debug.h"
#include "IA32.h"
#include "HV.h"
#include "SVM.h"
#include "VM.h"
#include "Shared.h"
#include "Memory.h"

#define INFINITE_LOOP() \
    while (TRUE) \
    { \
    }