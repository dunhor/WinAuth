#pragma once
#include <ClientAuthentication.g.h>

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    struct ClientAuthentication : ClientAuthenticationT<ClientAuthentication>
    {
        ClientAuthentication() = default;
        ClientAuthentication(http::Headers::HttpCredentialsHeaderValue const& authorization);

        static oauth::ClientAuthentication CreateForBasicAuthorization(const winrt::hstring& clientId,
            const winrt::hstring& clientSecret);

        http::Headers::HttpCredentialsHeaderValue Authorization();
        void Authorization(http::Headers::HttpCredentialsHeaderValue const& value);
        http::Headers::HttpCredentialsHeaderValue ProxyAuthorization();
        void ProxyAuthorization(http::Headers::HttpCredentialsHeaderValue const& value);
        collections::IMap<winrt::hstring, winrt::hstring> AdditionalHeaders();
        void AdditionalHeaders(collections::IMap<winrt::hstring, winrt::hstring> const& value);

    private:
        std::shared_mutex m_mutex;
        http::Headers::HttpCredentialsHeaderValue m_authorization{ nullptr };
        http::Headers::HttpCredentialsHeaderValue m_proxyAuthorization{ nullptr };
        collections::IMap<winrt::hstring, winrt::hstring> m_additionalHeaders =
            winrt::multi_threaded_map<winrt::hstring, winrt::hstring>();
    };
}
namespace winrt::Microsoft::Security::Authentication::OAuth::factory_implementation
{
    struct ClientAuthentication : ClientAuthenticationT<ClientAuthentication, implementation::ClientAuthentication>
    {
    };
}
