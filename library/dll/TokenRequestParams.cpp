#include "TokenRequestParams.h"
#include "pch.h"
#include <TokenRequestParams.g.cpp>

#include "AuthResponse.h"

using namespace winrt::Microsoft::Security::Authentication::OAuth;
using namespace winrt::Windows::Foundation;
using namespace Collections;

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    TokenRequestParams::TokenRequestParams(const winrt::hstring& grantType) : m_grantType(grantType) {}

    oauth::TokenRequestParams TokenRequestParams::CreateForAuthorizationCodeRequest(
        const oauth::AuthResponse& authResponse)
    {
        auto result = winrt::make_self<TokenRequestParams>(L"authorization_code");
        result->m_code = authResponse.Code();

        auto implResponse = winrt::get_self<AuthResponse>(authResponse);
        if (auto redirectUri = implResponse->request_params()->RedirectUri())
        {
            result->m_redirectUri = std::move(redirectUri);
        }

        if (auto clientId = implResponse->request_params()->ClientId(); !clientId.empty())
        {
            result->m_clientId = std::move(clientId);
        }

        if (auto codeVerifier = implResponse->request_params()->CodeVerifier(); !codeVerifier.empty())
        {
            result->m_codeVerifier = std::move(codeVerifier);
        }

        return *result;
    }

    oauth::TokenRequestParams TokenRequestParams::CreateForResourceOwnerPasswordCredentials(
        const winrt::hstring& username, const winrt::hstring& password)
    {
        auto result = winrt::make_self<TokenRequestParams>(L"password");
        result->m_username = username;
        result->m_password = password;

        return *result;
    }

    oauth::TokenRequestParams TokenRequestParams::CreateForClientCredentials()
    {
        return winrt::make<TokenRequestParams>(L"client_credentials");
    }

    oauth::TokenRequestParams TokenRequestParams::CreateForExtension(const Uri& extensionUri)
    {
        return winrt::make<TokenRequestParams>(extensionUri.RawUri());
    }

    oauth::TokenRequestParams TokenRequestParams::CreateForRefreshToken(const winrt::hstring& refreshToken)
    {
        auto result = winrt::make_self<TokenRequestParams>(L"refresh_token");
        result->m_refreshToken = refreshToken;

        return *result;
    }

    winrt::hstring TokenRequestParams::GrantType()
    {
        std::shared_lock guard{ m_mutex };
        return m_grantType;
    }

    void TokenRequestParams::GrantType(const winrt::hstring& value)
    {
        std::lock_guard guard{ m_mutex };
        check_not_finalized();
        m_grantType = value;
    }

    winrt::hstring TokenRequestParams::Code()
    {
        std::shared_lock guard{ m_mutex };
        return m_code;
    }

    void TokenRequestParams::Code(const winrt::hstring& value)
    {
        std::lock_guard guard{ m_mutex };
        check_not_finalized();
        m_code = value;
    }

    Uri TokenRequestParams::RedirectUri()
    {
        std::shared_lock guard{ m_mutex };
        return m_redirectUri;
    }

    void TokenRequestParams::RedirectUri(const Uri& value)
    {
        std::lock_guard guard{ m_mutex };
        check_not_finalized();
        m_redirectUri = value;
    }

    winrt::hstring TokenRequestParams::CodeVerifier()
    {
        std::shared_lock guard{ m_mutex };
        return m_codeVerifier;
    }

    void TokenRequestParams::CodeVerifier(const winrt::hstring& value)
    {
        std::lock_guard guard{ m_mutex };
        check_not_finalized();
        m_codeVerifier = value;
    }

    winrt::hstring TokenRequestParams::ClientId()
    {
        std::shared_lock guard{ m_mutex };
        return m_clientId;
    }

    void TokenRequestParams::ClientId(const winrt::hstring& value)
    {
        std::lock_guard guard{ m_mutex };
        check_not_finalized();
        m_clientId = value;
    }

    winrt::hstring TokenRequestParams::Username()
    {
        std::shared_lock guard{ m_mutex };
        return m_username;
    }

    void TokenRequestParams::Username(const winrt::hstring& value)
    {
        std::lock_guard guard{ m_mutex };
        check_not_finalized();
        m_username = value;
    }

    winrt::hstring TokenRequestParams::Password()
    {
        std::shared_lock guard{ m_mutex };
        return m_password;
    }

    void TokenRequestParams::Password(const winrt::hstring& value)
    {
        std::lock_guard guard{ m_mutex };
        check_not_finalized();
        m_password = value;
    }

    winrt::hstring TokenRequestParams::Scope()
    {
        std::shared_lock guard{ m_mutex };
        return m_scope;
    }

    void TokenRequestParams::Scope(const winrt::hstring& value)
    {
        std::lock_guard guard{ m_mutex };
        check_not_finalized();
        m_scope = value;
    }

    winrt::hstring TokenRequestParams::RefreshToken()
    {
        std::shared_lock guard{ m_mutex };
        return m_refreshToken;
    }

    void TokenRequestParams::RefreshToken(const winrt::hstring& value)
    {
        std::lock_guard guard{ m_mutex };
        check_not_finalized();
        m_refreshToken = value;
    }

    IMap<winrt::hstring, winrt::hstring> TokenRequestParams::AdditionalParams()
    {
        std::shared_lock guard{ m_mutex };
        return m_additionalParams;
    }

    void TokenRequestParams::AdditionalParams(const IMap<winrt::hstring, winrt::hstring>& value)
    {
        std::lock_guard guard{ m_mutex };
        check_not_finalized();
        m_additionalParams = value;
    }
}
