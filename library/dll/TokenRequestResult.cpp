#include "TokenRequestResult.h"
#include "pch.h"
#include <TokenRequestResult.g.cpp>

using namespace winrt::Microsoft::Security::Authentication::OAuth;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Foundation::Collections;

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    oauth::TokenResponse TokenRequestResult::Response()
    {
        return m_response;
    }

    oauth::TokenFailure TokenRequestResult::Failure()
    {
        return m_failure;
    }
}
