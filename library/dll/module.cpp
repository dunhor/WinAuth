#include "pch.h"

#include <Windows.h>

#include <activation.h>

#include <module.g.cpp>

STDAPI DllCanUnloadNow()
{
    // Delegate to C++/WinRT
    return WINRT_CanUnloadNow();
}

STDAPI DllGetActivationFactory(HSTRING activatableClassId, IActivationFactory** factory)
{
    // Delegate to C++/WinRT
    return WINRT_GetActivationFactory(activatableClassId, reinterpret_cast<void**>(factory));
}
