#pragma once
#include <TokenFailure.g.h>

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    struct TokenFailure : TokenFailureT<TokenFailure>
    {
        TokenFailure(const json::JsonObject& jsonObject);

        winrt::hstring Error();
        winrt::hstring ErrorDescription();
        foundation::Uri ErrorUri();
        collections::IMapView<winrt::hstring, json::IJsonValue> AdditionalParams();

    private:
        winrt::hstring m_error;
        winrt::hstring m_errorDescription;
        foundation::Uri m_errorUri{ nullptr };
        collections::IMapView<winrt::hstring, json::IJsonValue> m_additionalParams;
    };
}
