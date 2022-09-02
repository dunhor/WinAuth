#include "pch.h"

#include "AuthFailure.h"
#include <AuthFailure.g.cpp>

using namespace winrt::Microsoft::Security::Authentication::OAuth;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Foundation::Collections;

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    Uri AuthFailure::ResponseUri()
    {
        throw hresult_not_implemented(); // TODO
    }
}
