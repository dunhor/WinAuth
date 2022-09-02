
#include <cstdio>
#include <iostream>
#include <string>
#include <string_view>

#include <Windows.h>

#include <http.h>

#include <winrt/Microsoft.Security.Authentication.OAuth.h>
#include <winrt/Windows.Foundation.h>

#pragma comment(lib, "httpapi.lib")
#pragma comment(lib, "shell32.lib")

using namespace std::literals;
using namespace winrt::Microsoft::Security::Authentication::OAuth;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Foundation::Collections;

#define THROW_IF_WIN32_ERROR(err)                                                                                      \
    if (err != NO_ERROR) winrt::check_hresult(HRESULT_FROM_WIN32(err))

// Global server data
static HTTP_SERVER_SESSION_ID session_id = 0;
static HANDLE request_queue = nullptr;
static HTTP_URL_GROUP_ID url_group = 0;

static std::uint16_t port = 50001;
static std::wstring callback_url;

// Threadpool/callback data
static PTP_IO threadpool_io = nullptr;
static OVERLAPPED overlapped = {};
static char request_buffer[4096];

// Static server data
static constexpr const auto auth_url = L"https://github.com/login/oauth/authorize"sv;
static constexpr const auto token_url = L"https://github.com/login/oauth/access_token"sv;
static constexpr const auto response_html =
    "<html><head><meta title='Authentication Complete'></head><body>Authentication is complete. You may now close this page and return to the application.</body></html>"sv;

static void set_known_header(HTTP_RESPONSE& response, int knownHeaderId, std::string_view str)
{
    auto& header = response.Headers.KnownHeaders[knownHeaderId];
    header.pRawValue = str.data();
    header.RawValueLength = static_cast<USHORT>(str.size());
}

// NOTE: This should probably be synchronized better, but for proof of concept it's fine
static void CALLBACK server_io_completion_callback(PTP_CALLBACK_INSTANCE, PVOID, PVOID, ULONG ioResult, ULONG_PTR,
    PTP_IO)
{
    auto& request = *reinterpret_cast<HTTP_REQUEST*>(request_buffer);
    if (ioResult == ERROR_MORE_DATA)
    {
        // TODO: This should never happen in practice for this example
        assert(false);
        return;
    }
    else if (ioResult != NO_ERROR)
    {
        // Unexpected error; nothing we can really do here
        return;
    }
    else if (request.Verb == HttpVerbGET)
    {
        // Should ideally validate that this is from a request...
        auto& request = *reinterpret_cast<HTTP_REQUEST*>(request_buffer);
        if (!AuthManager::CompleteAuthRequest(Uri(request.CookedUrl.pFullUrl)))
        {
            std::printf("Unable to complete request for uri %ls\n", request.CookedUrl.pFullUrl);
            // TODO: Ideally would send a response back to the user agent, however this shouldn't really happen in
            // practice for this example, so we'll skip it for now
            return;
        }

        HTTP_RESPONSE response = {};
        response.StatusCode = 200;
        response.pReason = "OK";
        response.ReasonLength = 2;

        set_known_header(response, HttpHeaderContentType, "text/html"sv);

        HTTP_DATA_CHUNK dataChunk = {};
        dataChunk.DataChunkType = HttpDataChunkFromMemory;
        dataChunk.FromMemory.pBuffer = const_cast<char*>(response_html.data());
        dataChunk.FromMemory.BufferLength = static_cast<ULONG>(response_html.size());

        response.EntityChunkCount = 1;
        response.pEntityChunks = &dataChunk;

        [[maybe_unused]] auto err = ::HttpSendHttpResponse(request_queue, request.RequestId, 0, &response, nullptr,
            nullptr, nullptr, 0, nullptr, nullptr);
        assert(err == NO_ERROR);
    }
    else
    {
        // TODO: This should never happen in practice for this example
    }

    // TODO: Would ideally start listening for more requests, however that's not entirely necessary for this example
    // since all we need is the result
    // ::StartThreadpoolIo(threadpool_io); // TODO: Is this right?
}

void start_server()
{
    auto err = ::HttpInitialize(HTTPAPI_VERSION_2, HTTP_INITIALIZE_SERVER, nullptr);
    THROW_IF_WIN32_ERROR(err);

    err = ::HttpCreateServerSession(HTTPAPI_VERSION_2, &session_id, 0);
    THROW_IF_WIN32_ERROR(err);

    err = ::HttpCreateRequestQueue(HTTPAPI_VERSION_2, nullptr, nullptr, 0, &request_queue);
    THROW_IF_WIN32_ERROR(err);

    err = ::HttpCreateUrlGroup(session_id, &url_group, 0);
    THROW_IF_WIN32_ERROR(err);

    HTTP_BINDING_INFO bindingInfo{};
    bindingInfo.Flags.Present = 1;
    bindingInfo.RequestQueueHandle = request_queue;
    err = ::HttpSetUrlGroupProperty(url_group, HttpServerBindingProperty, &bindingInfo,
        static_cast<ULONG>(sizeof(bindingInfo)));
    THROW_IF_WIN32_ERROR(err);

    // Try and find a port that works. Note that ports around the low 50000 are frequently claimed, hence the large
    // iteration bounds
    for (std::uint16_t i = 0; i < 500; ++i)
    {
        wchar_t buffer[18 + 5 + 1];
        std::swprintf(buffer, std::size(buffer), L"http://127.0.0.1:%d/", port);

        err = ::HttpAddUrlToUrlGroup(url_group, buffer, 0, 0);
        if (err == NO_ERROR)
        {
            callback_url = buffer;
            break;
        }

        ++port;
    }

    THROW_IF_WIN32_ERROR(err);

    // Start listening for requests asynchronously
    threadpool_io = ::CreateThreadpoolIo(request_queue, server_io_completion_callback, nullptr, nullptr);
    if (!threadpool_io) THROW_IF_WIN32_ERROR(::GetLastError());
    ::StartThreadpoolIo(threadpool_io);

    err = ::HttpReceiveHttpRequest(request_queue, HTTP_NULL_ID, HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY,
        reinterpret_cast<HTTP_REQUEST*>(request_buffer), sizeof(request_buffer), nullptr, &overlapped);
    if (err != ERROR_IO_PENDING)
    {
        THROW_IF_WIN32_ERROR(err);
    }
}

int main()
try
{
    start_server();
    std::printf("Server started at: %ls\n", callback_url.c_str());

    std::wstring clientId, clientSecret;
    std::printf("Client id: ");
    std::wcin >> clientId;
    std::printf("Client secret: ");
    std::wcin >> clientSecret;

    AuthRequestParams params(clientId, L"code", Uri(callback_url));
    params.Scope(L"read:user user:email");

    auto event = ::CreateEventW(nullptr, true, false, nullptr);

    auto op = AuthManager::InitiateAuthRequestAsync(Uri(auth_url), params, clientSecret);
    op.Completed([&](const IAsyncOperation<AuthRequestResult>& result, AsyncStatus status) {
        switch (status)
        {
        case AsyncStatus::Completed: {
            auto requestResult = result.GetResults();
            if (auto response = requestResult.Response())
            {
                std::printf("Authorization code: %ls\n", response.Code().c_str());
            }
            else
            {
                // TODO auto failure = requestResult.Failure();
                std::printf("Received a failure response from the server\n");
            }
        }
        break;

        case AsyncStatus::Canceled: std::printf("Request cancelled by caller\n"); break;

        case AsyncStatus::Error: std::printf("Request completed with error 0x%08X\n", result.ErrorCode().value); break;

        case AsyncStatus::Started:
        default: std::printf("Unexpected async completion\n"); break;
        }

        ::SetEvent(event);
    });

    auto waitResult = ::WaitForSingleObject(event, 60000);
    switch (waitResult)
    {
    case WAIT_OBJECT_0:
        // Success; nothing to do
        break;

    case WAIT_TIMEOUT:
        std::printf("Operation took longer than one minute; cancelling\n");
        op.Cancel();
        ::WaitForSingleObject(event, INFINITY);
        return ERROR_TIMEOUT;

    default:
        std::printf("ERROR: Failure waiting for request to complete (%lu)\n", ::GetLastError());
        return ::GetLastError();
    }

    return 0;
}
catch (winrt::hresult_error& err)
{
    std::printf("ERROR: Unhandled exception\n");
    std::printf("ERROR: %ls (0x%08X)\n", err.message().c_str(), err.code().value);
    return err.code().value;
}
catch (std::exception& err)
{
    std::printf("ERROR: Unhandled exception\n");
    std::printf("ERROR: %s\n", err.what());
    return ERROR_UNHANDLED_EXCEPTION;
}
