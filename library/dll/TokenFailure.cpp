#include "TokenFailure.h"
#include "pch.h"
#include <TokenFailure.g.cpp>

using namespace std::literals;
using namespace winrt::Microsoft::Security::Authentication::OAuth;
using namespace winrt::Windows::Data::Json;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Foundation::Collections;

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    TokenFailure::TokenFailure(const JsonObject& jsonObject)
    {
        std::map<winrt::hstring, IJsonValue> additionalParams;

        for (auto&& pair : jsonObject)
        {
            auto name = pair.Key();
            if (name == L"error"sv)
            {
                m_error = pair.Value().GetString();
            }
            else if (name == L"error_description"sv)
            {
                m_errorDescription = pair.Value().GetString();
            }
            else if (name == L"error_uri"sv)
            {
                m_errorUri = Uri(pair.Value().GetString());
            }
            else
            {
                additionalParams.emplace(std::move(name), pair.Value());
            }
        }

        m_additionalParams = winrt::single_threaded_map(std::move(additionalParams)).GetView();
    }

    winrt::hstring TokenFailure::Error()
    {
        return m_error;
    }

    winrt::hstring TokenFailure::ErrorDescription()
    {
        return m_errorDescription;
    }

    Uri TokenFailure::ErrorUri()
    {
        return m_errorUri;
    }

    IMapView<winrt::hstring, IJsonValue> TokenFailure::AdditionalParams()
    {
        return m_additionalParams;
    }
}
