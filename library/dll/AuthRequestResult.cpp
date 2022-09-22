#include "pch.h"

#include "AuthRequestResult.h"
#include <AuthRequestResult.g.cpp>

using namespace winrt::Microsoft::Security::Authentication::OAuth;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Foundation::Collections;

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    Uri AuthRequestResult::ResponseUri()
    {
        return m_responseUri;
    }

    AuthResponse AuthRequestResult::Response()
    {
        return m_response;
    }

    AuthFailure AuthRequestResult::Failure()
    {
        return m_failure;
    }
}
