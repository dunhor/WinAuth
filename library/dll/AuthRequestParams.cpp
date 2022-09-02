#include "pch.h"

#include "AuthManager.h"
#include "AuthRequestParams.h"
#include <AuthRequestParams.g.cpp>

using namespace winrt::Microsoft::Security::Authentication::OAuth;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Foundation::Collections;
using namespace winrt::Windows::Security::Cryptography;
using namespace winrt::Windows::Security::Cryptography::Core;

namespace winrt::Microsoft::Security::Authentication::OAuth::implementation
{
    AuthRequestParams::AuthRequestParams(const winrt::hstring& clientId, const winrt::hstring& responseType) :
        m_clientId(clientId),
        m_responseType(responseType)
    {
    }

    AuthRequestParams::AuthRequestParams(const winrt::hstring& clientId, const winrt::hstring& responseType,
        const Uri& redirectUri) :
        m_clientId(clientId),
        m_responseType(responseType),
        m_redirectUri(redirectUri)
    {
    }

    winrt::hstring AuthRequestParams::ResponseType()
    {
        std::shared_lock guard{ m_mutex };
        return m_responseType;
    }

    void AuthRequestParams::ResponseType(const winrt::hstring& value)
    {
        std::lock_guard guard{ m_mutex };
        check_not_finalized();
        m_responseType = value;
    }

    winrt::hstring AuthRequestParams::ClientId()
    {
        std::shared_lock guard{ m_mutex };
        return m_clientId;
    }

    void AuthRequestParams::ClientId(const winrt::hstring& value)
    {
        std::lock_guard guard{ m_mutex };
        check_not_finalized();
        m_clientId = value;
    }

    Uri AuthRequestParams::RedirectUri()
    {
        std::shared_lock guard{ m_mutex };
        return m_redirectUri;
    }

    void AuthRequestParams::RedirectUri(const Uri& value)
    {
        std::lock_guard guard{ m_mutex };
        check_not_finalized();
        m_redirectUri = value;
    }

    winrt::hstring AuthRequestParams::Scope()
    {
        std::shared_lock guard{ m_mutex };
        return m_scope;
    }

    void AuthRequestParams::Scope(const winrt::hstring& value)
    {
        std::lock_guard guard{ m_mutex };
        check_not_finalized();
        m_scope = value;
    }

    winrt::hstring AuthRequestParams::State()
    {
        std::shared_lock guard{ m_mutex };
        return m_state;
    }

    void AuthRequestParams::State(const winrt::hstring& value)
    {
        std::lock_guard guard{ m_mutex };
        check_not_finalized();
        m_state = value;
    }

    winrt::hstring AuthRequestParams::CodeVerifier()
    {
        std::shared_lock guard{ m_mutex };
        return m_codeVerifier;
    }

    void AuthRequestParams::CodeVerifier(const winrt::hstring& value)
    {
        std::lock_guard guard{ m_mutex };
        check_not_finalized();
        m_codeVerifier = value;
    }

    CodeChallengeMethodKind AuthRequestParams::CodeChallengeMethod()
    {
        std::shared_lock guard{ m_mutex };
        return m_codeChallengeMethod;
    }

    void AuthRequestParams::CodeChallengeMethod(CodeChallengeMethodKind value)
    {
        std::lock_guard guard{ m_mutex };
        check_not_finalized();
        m_codeChallengeMethod = value;
    }

    IMap<winrt::hstring, winrt::hstring> AuthRequestParams::AdditionalParams()
    {
        std::shared_lock guard{ m_mutex };
        return m_additionalParams;
    }

    void AuthRequestParams::AdditionalParams(IMap<winrt::hstring, winrt::hstring> const& value)
    {
        std::lock_guard guard{ m_mutex };
        check_not_finalized();
        m_additionalParams = value;
    }

    void AuthRequestParams::finalize()
    {
        std::lock_guard guard{ m_mutex };
        if (m_finalized)
        {
            throw winrt::hresult_illegal_method_call(L"AuthRequestParams can only be used for a single request call");
        }

        m_finalized = true;

        if (!m_codeVerifier.empty() && (m_codeChallengeMethod == CodeChallengeMethodKind::None))
        {
            throw winrt::hresult_illegal_method_call(L"'CodeChallenge' cannot be set when 'CodeChallengeMethod' is set to 'None'");
        }

        if (m_state.empty())
        {
            m_state = winrt::make_self<factory_implementation::AuthManager>()->generate_unique_state();
        }

        if (m_codeVerifier.empty() && (m_codeChallengeMethod != CodeChallengeMethodKind::None))
        {
            // TODO: Set m_codeVerifier
        }
    }

    std::wstring AuthRequestParams::query_string()
    {
        std::shared_lock guard{ m_mutex };

        std::wstring result = L"?state=";
        result += Uri::EscapeComponent(m_state);

        if (!m_responseType.empty())
        {
            result += L"&response_type=";
            result += Uri::EscapeComponent(m_responseType);
        }

        if (!m_clientId.empty())
        {
            result += L"&client_id=";
            result += Uri::EscapeComponent(m_clientId);
        }

        if (m_redirectUri)
        {
            result += L"&redirect_uri=";
            result += Uri::EscapeComponent(m_redirectUri.RawUri());
        }

        if (!m_scope.empty())
        {
            result += L"&scope=";
            result += Uri::EscapeComponent(m_scope);
        }

        if (m_codeChallengeMethod == CodeChallengeMethodKind::S256)
        {
            result += L"&code_challenge_method=S256&code_challenge=";

            auto sha256 = HashAlgorithmProvider::OpenAlgorithm(HashAlgorithmNames::Sha256());
            auto buffer = CryptographicBuffer::ConvertStringToBinary(m_codeVerifier, BinaryStringEncoding::Utf8);
            auto encodedHash = CryptographicBuffer::EncodeToBase64String(sha256.HashData(buffer));
            // NOTE: WinRT doesn't have a 'Base64UrlEncode' function, so we need to manually convert
            for (auto ch : encodedHash)
            {
                if (ch == '+')
                {
                    result.push_back('-');
                }
                else if (ch == '/')
                {
                    result.push_back('_');
                }
                else if (ch != '=')
                {
                    result.push_back(ch);
                }
            }
        }
        else if (m_codeChallengeMethod == CodeChallengeMethodKind::Plain)
        {
            result += L"&code_challenge_method=plain&code_challenge=";
            result += Uri::EscapeComponent(m_codeVerifier);
        }

        for (auto&& pair : m_additionalParams)
        {
            result += L"&";
            result += Uri::EscapeComponent(pair.Key());
            result += L"=";
            result += Uri::EscapeComponent(pair.Value());
        }

        return result;
    }
}
