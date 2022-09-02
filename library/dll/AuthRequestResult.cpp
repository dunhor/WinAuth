#include "pch.h"

#include "AuthRequestResult.h"
#include <AuthRequestResult.g.cpp>

using namespace winrt::Microsoft::Security::Authentication::OAuth;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Foundation::Collections;

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    AuthResponse AuthRequestResult::Response()
    {
        throw hresult_not_implemented(); // TODO
    }

    AuthFailure AuthRequestResult::Failure()
    {
        throw hresult_not_implemented(); // TODO
    }
}
