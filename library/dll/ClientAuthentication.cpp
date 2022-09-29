#include "pch.h"
#include "ClientAuthentication.h"
#include <ClientAuthentication.g.cpp>

using namespace winrt::Microsoft::Security::Authentication::OAuth;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Foundation::Collections;
using namespace winrt::Windows::Security::Cryptography;
using namespace winrt::Windows::Web::Http::Headers;

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    ClientAuthentication::ClientAuthentication(const HttpCredentialsHeaderValue& authorization) :
        m_authorization(authorization)
    {
    }

    oauth::ClientAuthentication ClientAuthentication::CreateForBasicAuthorization(const winrt::hstring& clientId,
        const winrt::hstring& clientSecret)
    {
        auto authString = clientId + L":" + clientSecret;
        auto buffer = CryptographicBuffer::ConvertStringToBinary(authString, BinaryStringEncoding::Utf8);
        auto base64Token = CryptographicBuffer::EncodeToBase64String(buffer);
        HttpCredentialsHeaderValue header(L"Basic", base64Token);
        return winrt::make<ClientAuthentication>(header);
    }

    HttpCredentialsHeaderValue ClientAuthentication::Authorization()
    {
        std::shared_lock guard{ m_mutex };
        return m_authorization;
    }

    void ClientAuthentication::Authorization(const HttpCredentialsHeaderValue& value)
    {
        std::lock_guard guard{ m_mutex };
        m_authorization = value;
    }

    HttpCredentialsHeaderValue ClientAuthentication::ProxyAuthorization()
    {
        std::shared_lock guard{ m_mutex };
        return m_proxyAuthorization;
    }

    void ClientAuthentication::ProxyAuthorization(const HttpCredentialsHeaderValue& value)
    {
        std::lock_guard guard{ m_mutex };
        m_proxyAuthorization = value;
    }

    winrt::Windows::Foundation::Collections::IMap<hstring, hstring> ClientAuthentication::AdditionalHeaders()
    {
        std::shared_lock guard{ m_mutex };
        return m_additionalHeaders;
    }

    void ClientAuthentication::AdditionalHeaders(winrt::Windows::Foundation::Collections::IMap<hstring, hstring> const& value)
    {
        std::lock_guard guard{ m_mutex };
        m_additionalHeaders = value;
    }
}
