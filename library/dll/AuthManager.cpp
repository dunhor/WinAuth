#include "AuthManager.h"
#include "pch.h"
#include <AuthManager.g.cpp>

#include <format>

#include "AuthRequestParams.h"

using namespace winrt::Microsoft::Security::Authentication::OAuth;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Foundation::Collections;

namespace winrt::Microsoft::Security::Authentication::OAuth::factory_implementation
{
    IAsyncOperation<AuthRequestResult> AuthManager::InitiateAuthRequestAsync(Uri authEndpoint,
        oauth::AuthRequestParams params)
    {
        auto asyncOp = winrt::make_self<AuthRequestAsyncOperation>(authEndpoint,
            winrt::get_self<implementation::AuthRequestParams>(params));

        {
            std::lock_guard guard{ m_mutex };
            m_pendingAuthRequests.push_back(AuthRequestState{ params.State(), asyncOp });
        }

        return *asyncOp;
    }

    bool AuthManager::CompleteAuthRequest(const Uri& responseUri)
    {
        // We need to extract the state in order to find the original request
        winrt::hstring state;
        for (auto&& entry : responseUri.QueryParsed())
        {
            if (entry.Name() == L"state")
            {
                state = entry.Value();
                break;
            }
        }

        // TODO: If we could not find the state, we need to check the fragment

        // Don't throw an error. It could be the case that the application just blindly calls this function first
        if (state.empty())
        {
            return false;
        }

        // First check in our local pending list
        if (false && try_complete_local(state, responseUri)) // TODO: Short circuiting for testing
        {
            return true;
        }

        // Not found locally; we need to check to see if the request originated in another process
        auto pipeName = request_pipe_name(state);

        // We encrypt the URI using the state as the key. This accomplishes a couple things: (1) it helps protect the
        // server from another process attaching and sending bogus data, and (2) it helps protect against sending the
        // authorization grant information to the wrong client. Both of these points of course become moot if the bad
        // party intercepts the state value, and because the state value is somewhat exposed through the browser launch/
        // URL, these steps are intended more as a defense in depth. Other features such as PKCE should be used to
        // ensure that codes/tokens are safe in the event that the state is compromised.
        auto encryptedUri = encrypt(responseUri.RawUri(), state);

        // When we create the named pipe, we only allow a single pipe instance. This should be fine under normal
        // circumstances, however it might be the case that another process attaches to the pipe. This may be
        // innocuous - e.g. the browser did multiple redirects - or it could be a bad actor - e.g. a process sending
        // random garbage to any pipe it can open or another process specifically targeting oauth. Therefore we make
        // multiple attempts to connect to the pipe
        HANDLE pipe = INVALID_HANDLE_VALUE;
        while (true) // TODO: Bound this? Need to remember to return false if we do
        {
            pipe = ::CreateFileW(pipeName.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (pipe != INVALID_HANDLE_VALUE) break;

            if (auto err = ::GetLastError(); err != ERROR_PIPE_BUSY)
            {
                // The pipe no longer exist; e.g. flow already completed, client cancelled, etc.
                return false;
            }

            if (!::WaitNamedPipeW(pipeName.c_str(), 100))
            {
                // 100ms should be enough time to wrap up any business. So either the system is bogged down (perhaps too
                // many requests to open the pipe), the pipe was closed, or the pipe was closed and opened by another
                // process who isn't being responsive.
                return false;
            }
        }

        ULONG serverPid = 0;
        if (::GetNamedPipeServerProcessId(pipe, &serverPid))
        {
            ::AllowSetForegroundWindow(serverPid);

            // TODO: We can also possibly verify other things about the server process (exe path, etc.)
        }

        DWORD bytesToWrite = encryptedUri.Length();
        DWORD bytesWritten = 0;
        if (!::WriteFile(pipe, encryptedUri.data(), bytesToWrite, &bytesWritten, nullptr) ||
            (bytesWritten != bytesToWrite))
        {
            // TODO: Actual error? This could be because the server timed out...
            ::CloseHandle(pipe);
            return false;
        }

        // The client should have the URI and the operation should be considered handled
        ::CloseHandle(pipe);
        return true;
    }

    IAsyncOperation<oauth::TokenRequestResult> AuthManager::RequestTokenAsync(Uri tokenEndpoint,
        oauth::TokenRequestParams params)
    {
        throw winrt::hresult_not_implemented(); // TODO
    }

    bool AuthManager::try_complete_local(const winrt::hstring& state, const foundation::Uri& responseUri)
    {
        AuthRequestState requestState;
        {
            std::lock_guard guard{ m_mutex };
            auto itr = std::find_if(m_pendingAuthRequests.begin(), m_pendingAuthRequests.end(),
                [&](auto&& entry) { return entry.state == state; });

            if (itr != m_pendingAuthRequests.end())
            {
                requestState = std::move(*itr);
                *itr = std::move(m_pendingAuthRequests.back());
                m_pendingAuthRequests.pop_back();
            }
        }

        if (requestState.async_op)
        {
            // Found locally
            requestState.async_op->complete(responseUri);
            return true;
        }

        return false;
    }

    void AuthManager::cancel(AuthRequestAsyncOperation* op)
    {
        auto requestState = try_remove(op);
        if (requestState.async_op)
        {
            requestState.async_op->cancel();
        }
    }

    void AuthManager::error(AuthRequestAsyncOperation* op, winrt::hresult hr)
    {
        auto requestState = try_remove(op);
        if (requestState.async_op)
        {
            requestState.async_op->error(hr);
        }
    }

    AuthRequestState AuthManager::try_remove(AuthRequestAsyncOperation* op)
    {
        std::lock_guard guard{ m_mutex };
        auto itr = std::find_if(m_pendingAuthRequests.begin(), m_pendingAuthRequests.end(),
            [&](auto&& entry) { return entry.async_op.get() == op; });

        AuthRequestState result;
        if (itr != m_pendingAuthRequests.end())
        {
            result = std::move(*itr);
            *itr = std::move(m_pendingAuthRequests.back());
            m_pendingAuthRequests.pop_back();
        }

        return result;
    }
}
