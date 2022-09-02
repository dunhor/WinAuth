#include "pch.h"

#include "AuthResponse.h"
#include <AuthResponse.g.cpp>

using namespace winrt::Microsoft::Security::Authentication::OAuth;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Foundation::Collections;

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    Uri AuthResponse::ResponseUri()
    {
        throw hresult_not_implemented(); // TODO
    }

    winrt::hstring AuthResponse::TokenType()
    {
        throw hresult_not_implemented(); // TODO
    }

    winrt::hstring AuthResponse::Code()
    {
        throw hresult_not_implemented(); // TODO
    }

    winrt::hstring AuthResponse::AccessToken()
    {
        throw hresult_not_implemented(); // TODO
    }

    winrt::hstring AuthResponse::State()
    {
        throw hresult_not_implemented(); // TODO
    }

    winrt::hstring AuthResponse::ExpiresIn()
    {
        throw hresult_not_implemented(); // TODO
    }

    winrt::hstring AuthResponse::Scope()
    {
        throw hresult_not_implemented(); // TODO
    }

    IMap<winrt::hstring, winrt::hstring> AuthResponse::AdditionalParams()
    {
        throw hresult_not_implemented(); // TODO
    }
}
