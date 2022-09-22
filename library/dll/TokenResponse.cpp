#include "pch.h"
#include "TokenResponse.h"
#include <TokenResponse.g.cpp>

using namespace winrt::Microsoft::Security::Authentication::OAuth;
using namespace winrt::Windows::Data::Json;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Foundation::Collections;

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    winrt::hstring TokenResponse::AccessToken()
    {
        return m_accessToken;
    }

    winrt::hstring TokenResponse::TokenType()
    {
        return m_tokenType;
    }

    double TokenResponse::ExpiresIn()
    {
        return m_expiresIn;
    }

    winrt::hstring TokenResponse::RefreshToken()
    {
        return m_refreshToken;
    }

    winrt::hstring TokenResponse::Scope()
    {
        return m_scope;
    }

    IMapView<winrt::hstring, IJsonValue> TokenResponse::AdditionalParams()
    {
        return m_additionalParams;
    }
}
