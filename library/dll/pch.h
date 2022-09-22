#pragma once

#include <shared_mutex>

#include <Windows.h>

#include <objidlbase.h>

#include <winrt/Microsoft.Security.Authentication.OAuth.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Security.Cryptography.h>
#include <winrt/Windows.Security.Cryptography.Core.h>
#include <winrt/Windows.System.h>

namespace oauth = winrt::Microsoft::Security::Authentication::OAuth;
namespace json = winrt::Windows::Data::Json;
namespace foundation = winrt::Windows::Foundation;
namespace collections = winrt::Windows::Foundation::Collections;
