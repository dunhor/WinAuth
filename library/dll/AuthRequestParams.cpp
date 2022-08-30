#include "pch.h"

#include "AuthRequestParams.h"
#include <AuthRequestParams.g.cpp>

using namespace winrt::Microsoft::Security::Authentication::OAuth;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Foundation::Collections;

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
        return read_op([&]() { return m_responseType; });
    }

    void AuthRequestParams::ResponseType(const winrt::hstring& value)
    {
        modify_op([&]() { m_responseType = value; });
    }

    winrt::hstring AuthRequestParams::ClientId()
    {
        return read_op([&]() { return m_clientId; });
    }

    void AuthRequestParams::ClientId(const winrt::hstring& value)
    {
        modify_op([&]() { m_clientId = value; });
    }

    Uri AuthRequestParams::RedirectUri()
    {
        return read_op([&]() { return m_redirectUri; });
    }

    void AuthRequestParams::RedirectUri(const Uri& value)
    {
        modify_op([&]() { m_redirectUri = value; });
    }

    winrt::hstring AuthRequestParams::Scope()
    {
        return read_op([&]() { return m_scope; });
    }

    void AuthRequestParams::Scope(const winrt::hstring& value)
    {
        modify_op([&]() { m_scope = value; });
    }

    winrt::hstring AuthRequestParams::State()
    {
        return read_op([&]() { return m_state; });
    }

    void AuthRequestParams::State(const winrt::hstring& value)
    {
        modify_op([&]() { m_state = value; });
    }

    winrt::hstring AuthRequestParams::CodeChallenge()
    {
        return read_op([&]() { return m_codeChallenge; });
    }

    void AuthRequestParams::CodeChallenge(const winrt::hstring& value)
    {
        modify_op([&]() { m_codeChallenge = value; });
    }

    CodeChallengeMethodKind AuthRequestParams::CodeChallengeMethod()
    {
        return read_op([&]() { return m_codeChallengeMethod; });
    }

    void AuthRequestParams::CodeChallengeMethod(CodeChallengeMethodKind value)
    {
        modify_op([&]() { m_codeChallengeMethod = value; });
    }

    IMap<winrt::hstring, winrt::hstring> AuthRequestParams::AdditionalParams()
    {
        return read_op([&]() { return m_additionalParams; });
    }

    void AuthRequestParams::AdditionalParams(IMap<winrt::hstring, winrt::hstring> const& value)
    {
        modify_op([&]() { m_additionalParams = value; });
    }

    void AuthRequestParams::Finalize()
    {
        std::uint8_t expected = 0;
        if (!m_guard.compare_exchange_strong(expected, 2))
        {
            // State 1 is modification; state 2 is the final state
            if (expected == 1)
            {
                throw winrt::hresult_changed_state(L"Concurrent modification of AuthRequestParams is not allowed");
            }

            throw winrt::hresult_illegal_method_call(L"AuthRequestParams can only be used for a single auth request");
        }
    }
}
