#include "pch.h"

#include "AuthManager.h"
#include <AuthManager.g.cpp>

using namespace winrt::Microsoft::Security::Authentication::OAuth;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Foundation::Collections;

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    void AuthManager::InitiateAuthRequest(const Uri& authEndpoint, const AuthRequestParams& params)
    {
        InitiateAuthRequest(authEndpoint, params, winrt::hstring{});
    }

    void AuthManager::InitiateAuthRequest(const Uri& authEndpoint, const AuthRequestParams& params,
        const winrt::hstring& clientSecret)
    {
        throw hresult_not_implemented();
    }
}
