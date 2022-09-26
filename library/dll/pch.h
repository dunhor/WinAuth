#pragma once

#include <shared_mutex>

#include <Windows.h>

#include <objidlbase.h>

#include <winrt/Microsoft.Security.Authentication.OAuth.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Security.Cryptography.Core.h>
#include <winrt/Windows.Security.Cryptography.h>
#include <winrt/Windows.Storage.Streams.h>

namespace collections = winrt::Windows::Foundation::Collections;
namespace crypto = winrt::Windows::Security::Cryptography;
namespace foundation = winrt::Windows::Foundation;
namespace json = winrt::Windows::Data::Json;
namespace oauth = winrt::Microsoft::Security::Authentication::OAuth;
namespace streams = winrt::Windows::Storage::Streams;

#include "Crypto.h"
