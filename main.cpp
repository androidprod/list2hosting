#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "logger.hpp"

#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <mutex>
#include <random>
#include <algorithm>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <cctype>

namespace fs = std::filesystem;

static std::string tolower_s(const std::string &s){ std::string r=s; for(char &c: r) c = (char)std::tolower((unsigned char)c); return r; }
static std::string stripq(const std::string &s){ if(s.size()>=2 && ((s.front()=='"'&&s.back()=='"')||(s.front()=='\''&&s.back()=='\''))) return s.substr(1,s.size()-2); return s; }

#ifdef _WIN32
#pragma warning(disable:4996)
#include <wincrypt.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
using sock_t = SOCKET;
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
using sock_t = int;
#define INVALID_SOCKET (-1)
#endif

// ================================
// Base64 + SHA1
// ================================
#ifdef _WIN32
std::string base64_encode(const unsigned char* data, size_t len) {
    DWORD outLen = 0;
    CryptBinaryToStringA(data, (DWORD)len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &outLen);
    if (outLen == 0) return {};
    std::string out(outLen, '\0');
    CryptBinaryToStringA(data, (DWORD)len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &out[0], &outLen);
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

std::string sha1_base64(const std::string& input) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    BYTE digest[20];
    DWORD digestLen = sizeof(digest);

    if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    }
    CryptCreateHash(prov, CALG_SHA1, 0, 0, &hash);
    CryptHashData(hash, reinterpret_cast<const BYTE*>(input.data()), (DWORD)input.size(), 0);
    CryptGetHashParam(hash, HP_HASHVAL, digest, &digestLen, 0);
    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);

    return base64_encode(digest, digestLen);
}
#else
std::string base64_encode(const unsigned char* data, size_t len) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, data, (int)len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

std::string sha1_base64(const std::string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    return base64_encode(hash, SHA_DIGEST_LENGTH);
}

#endif

static std::queue<std::string> g_cmd_queue; static std::mutex g_queue_mtx; static std::condition_variable g_queue_cv;
static std::atomic<int> g_delay_ms{0};

// server control globals
static std::atomic<bool> server_active{false};
static std::mutex server_mtx;
static sock_t server_sock = INVALID_SOCKET;
static std::thread server_thread;
static std::thread sender_thread;

static std::atomic<bool> app_running{true};

// Client and websocket helper declarations
struct Client {
    sock_t sock = INVALID_SOCKET;
    sockaddr_in addr{};
    bool websocket = false;
    std::string recvbuf;
};

static std::vector<Client> clients;
static std::mutex clients_mtx;

// Use implementation closely matching the working .old files
static std::string escape_json(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\\') out += "\\\\";
        else if (c == '"') out += "\\\"";
        else if (c == '\n') out += "\\n";
        else out += c;
    }
    return out;
}

static std::string makeCommandJSON(const std::string& command) {
    static std::mt19937_64 rng{ std::random_device{}() };
    unsigned long long id = rng();

    std::ostringstream ss;
    ss << "{"
       << "\"header\":{"
       << "\"version\":1,"
       << "\"requestId\":\"" << id << "\"," 
       << "\"messagePurpose\":\"commandRequest\""
       << "},"
       << "\"body\":{"
       << "\"version\":1,"
       << "\"commandLine\":\"" << escape_json(command) << "\""
       << "}"
       << "}";
    return ss.str();
}

static void ws_send(sock_t s, const std::string& msg) {
    std::vector<uint8_t> frame;
    frame.push_back(0x81); // FIN + text

    size_t len = msg.size();
    if (len < 126) {
        frame.push_back((uint8_t)len);
    } else if (len <= 0xFFFF) {
        frame.push_back(126);
        frame.push_back((uint8_t)((len >> 8) & 0xFF));
        frame.push_back((uint8_t)(len & 0xFF));
    } else {
        frame.push_back(127);
        for (int i = 7; i >= 0; --i) frame.push_back((uint8_t)((len >> (i*8)) & 0xFF));
    }

    frame.insert(frame.end(), msg.begin(), msg.end());
    send(s, reinterpret_cast<const char*>(frame.data()), (int)frame.size(), 0);
}

static void broadcast(const std::string& msg) {
    std::lock_guard<std::mutex> lk(clients_mtx);
    for (auto& c : clients) {
        if (c.websocket) ws_send(c.sock, msg);
    }
}

static void remove_client_by_socket_locked(sock_t s) {
    clients.erase(std::remove_if(clients.begin(), clients.end(), [&](const Client& c){ return c.sock == s; }), clients.end());
}

static bool websocket_handshake(Client& c) {
    std::istringstream ss(c.recvbuf);
    std::string line;
    std::string key;
    while (std::getline(ss, line)) {
        if (line.rfind("Sec-WebSocket-Key:", 0) == 0) {
            size_t pos = line.find(':');
            if (pos != std::string::npos) {
                key = line.substr(pos + 1);
                while (!key.empty() && (key.front() == ' ')) key.erase(key.begin());
                while (!key.empty() && (key.back() == '\r' || key.back() == '\n')) key.pop_back();
            }
        }
    }
    if (key.empty()) return false;

    const std::string GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string accept = sha1_base64(key + GUID);
    std::ostringstream resp;
    resp << "HTTP/1.1 101 Switching Protocols\r\n"
         << "Upgrade: websocket\r\n"
         << "Connection: Upgrade\r\n"
         << "Sec-WebSocket-Accept: " << accept << "\r\n\r\n";

    std::string r = resp.str();
    send(c.sock, r.c_str(), (int)r.size(), 0);
    c.websocket = true;
    c.recvbuf.clear();
    return true;
}

static bool handle_websocket_frames(Client& c) {
    while (true) {
        if (c.recvbuf.size() < 2) return false;
        uint8_t b1 = (uint8_t)c.recvbuf[0];
        uint8_t b2 = (uint8_t)c.recvbuf[1];
        bool fin = (b1 & 0x80) != 0;
        uint8_t opcode = b1 & 0x0F;
        bool masked = (b2 & 0x80) != 0;
        uint64_t payload_len = b2 & 0x7F;
        size_t pos = 2;

        if (payload_len == 126) {
            if (c.recvbuf.size() < pos + 2) return false;
            payload_len = ((uint8_t)c.recvbuf[pos] << 8) | (uint8_t)c.recvbuf[pos+1];
            pos += 2;
        } else if (payload_len == 127) {
            if (c.recvbuf.size() < pos + 8) return false;
            payload_len = 0;
            for (int i = 0; i < 8; ++i) payload_len = (payload_len << 8) | (uint8_t)c.recvbuf[pos + i];
            pos += 8;
        }

        uint8_t mask[4] = {0,0,0,0};
        if (masked) {
            if (c.recvbuf.size() < pos + 4) return false;
            mask[0] = (uint8_t)c.recvbuf[pos];
            mask[1] = (uint8_t)c.recvbuf[pos+1];
            mask[2] = (uint8_t)c.recvbuf[pos+2];
            mask[3] = (uint8_t)c.recvbuf[pos+3];
            pos += 4;
        }

        if (c.recvbuf.size() < pos + payload_len) return false;

        std::string payload;
        if (payload_len) payload.assign(c.recvbuf.begin() + pos, c.recvbuf.begin() + pos + (size_t)payload_len);

        c.recvbuf.erase(0, pos + (size_t)payload_len);

        if (masked && payload_len) {
            for (size_t i = 0; i < payload.size(); ++i) payload[i] ^= mask[i % 4];
        }

        if (opcode == 0x8) {
            std::vector<uint8_t> close_frame = { 0x88, 0x00 };
            send(c.sock, reinterpret_cast<const char*>(close_frame.data()), (int)close_frame.size(), 0);
            return true;
        } else if (opcode == 0x9) {
            std::vector<uint8_t> pong;
            pong.push_back(0x8A);
            if (payload.size() < 126) {
                pong.push_back((uint8_t)payload.size());
            } else if (payload.size() <= 0xFFFF) {
                pong.push_back(126);
                pong.push_back((payload.size() >> 8) & 0xFF);
                pong.push_back(payload.size() & 0xFF);
            } else {
                pong.push_back(127);
                for (int i = 7; i >= 0; --i) pong.push_back((payload.size() >> (i*8)) & 0xFF);
            }
            pong.insert(pong.end(), payload.begin(), payload.end());
            send(c.sock, reinterpret_cast<const char*>(pong.data()), (int)pong.size(), 0);
        } else if (opcode == 0x1) {
            logf(INF, "[WS][%s:%d] %s", inet_ntoa(c.addr.sin_addr), ntohs(c.addr.sin_port), payload.c_str());
        } else {
            // ignore other opcodes
        }
    }

    return false;
}

void print_help() {
    logf(INF, "Usage:\n  app --port <port> [--delay <ms>]");
}

void enqueue_command(const std::string& cmd) { { std::lock_guard<std::mutex> lk(g_queue_mtx); g_cmd_queue.push(cmd); } g_queue_cv.notify_one(); logf(DBG, "[ENQUEUE] %s", cmd.c_str()); }

// run server loop on this thread
static void run_server(int p){
    sock_t server = socket(AF_INET, SOCK_STREAM,
#ifdef _WIN32
        IPPROTO_TCP
#else
        0
#endif
    );
    if (server == INVALID_SOCKET) { logf(ERR, "socket failed"); server_active = false; return; }
#ifndef _WIN32
    int opt = 1; setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons((unsigned short)p); addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(server, (sockaddr*)&addr, sizeof(addr))
#ifdef _WIN32
        == SOCKET_ERROR
#else
        < 0
#endif
    ) { logf(ERR, "bind failed");
#ifdef _WIN32
        closesocket(server);
#else
        close(server);
#endif
        server_active = false; return; }
    if (listen(server, SOMAXCONN)
#ifdef _WIN32
        == SOCKET_ERROR
#else
        < 0
#endif
    ) { logf(ERR, "listen failed");
#ifdef _WIN32
        closesocket(server);
#else
        close(server);
#endif
        server_active = false; return; }

    logf(INF, "Server is ready on port %d", p);

    // sender thread
    sender_thread = std::thread([&](){
        auto last_send = std::chrono::steady_clock::now() - std::chrono::hours(1);
        while (server_active) {
            std::unique_lock<std::mutex> lk(g_queue_mtx);
            g_queue_cv.wait(lk, [&]{ return !g_cmd_queue.empty() || !server_active; });
            if (!server_active && g_cmd_queue.empty()) break;
            std::string cmd = g_cmd_queue.front(); g_cmd_queue.pop(); lk.unlock();
            int delay_ms = g_delay_ms.load();
            if (delay_ms > 0) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_send).count();
                if (elapsed < delay_ms) std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms - elapsed));
            }
            std::string json = makeCommandJSON(cmd);
            broadcast(json);
            last_send = std::chrono::steady_clock::now();
            logf(INF, "[SENT] %s", cmd.c_str());
        }
    });

    // main accept loop
    server_sock = server;
    while (server_active) {
#ifdef _WIN32
        fd_set readfds; FD_ZERO(&readfds); FD_SET(server, &readfds);
        SOCKET maxfd = server;
        { std::lock_guard<std::mutex> lk(clients_mtx); for (auto& c : clients) { FD_SET(c.sock, &readfds); if (c.sock > maxfd) maxfd = c.sock; } }
        timeval tv; tv.tv_sec = 1; tv.tv_usec = 0; int sel = select((int)maxfd + 1, &readfds, NULL, NULL, &tv);
        if (sel <= 0) continue;
        if (FD_ISSET(server, &readfds)) {
            sockaddr_in claddr; int len = sizeof(claddr);
            SOCKET cs = accept(server, (sockaddr*)&claddr, &len);
            if (cs != INVALID_SOCKET) { Client c; c.sock = cs; c.addr = claddr; c.websocket = false; std::lock_guard<std::mutex> lk(clients_mtx); clients.push_back(std::move(c)); logf(INF, "Client connected: %s:%d", inet_ntoa(claddr.sin_addr), ntohs(claddr.sin_port)); }
        }

        std::vector<sock_t> to_close;
        { std::lock_guard<std::mutex> lk(clients_mtx); for (auto& c : clients) {
            if (!FD_ISSET(c.sock, &readfds)) continue;
            char buf[4096]; int n = recv(c.sock, buf, (int)sizeof(buf), 0);
            if (n <= 0) { logf(INF, "Client disconnected: %s:%d", inet_ntoa(c.addr.sin_addr), ntohs(c.addr.sin_port)); to_close.push_back(c.sock); continue; }
            c.recvbuf.append(buf, buf + n);
            if (!c.websocket) { if (c.recvbuf.find("\r\n\r\n") != std::string::npos) { if (websocket_handshake(c)) logf(INF, "WebSocket handshake OK! (%s:%d)", inet_ntoa(c.addr.sin_addr), ntohs(c.addr.sin_port)); else c.recvbuf.clear(); } }
            else { if (handle_websocket_frames(c)) to_close.push_back(c.sock); }
        } }
        if (!to_close.empty()) { std::lock_guard<std::mutex> lk(clients_mtx); for (sock_t s : to_close) { closesocket(s); remove_client_by_socket_locked(s); } }
#else
        std::vector<pollfd> pfds; pfds.push_back({server, POLLIN,0}); { std::lock_guard<std::mutex> lk(clients_mtx); for(auto &c:clients) pfds.push_back({c.sock,POLLIN,0}); }
        int ret = poll(pfds.data(), pfds.size(), 1000); if(ret<=0) continue;
        if(pfds[0].revents & POLLIN){ sockaddr_in claddr; socklen_t len=sizeof(claddr); int cs = accept(server,(sockaddr*)&claddr,&len); if(cs>=0){ Client c; c.sock=cs; c.addr=claddr; std::lock_guard<std::mutex> lk(clients_mtx); clients.push_back(c); logf(INF, "Client connected: %s:%d", inet_ntoa(claddr.sin_addr), ntohs(claddr.sin_port)); } }
        std::vector<int> to_close;
        { std::lock_guard<std::mutex> lk(clients_mtx); for(size_t i=0;i<clients.size();++i){ Client &c=clients[i]; if(pfds[i+1].revents & POLLIN){ char buf[4096]; int n = recv(c.sock, buf, sizeof(buf),0); if(n<=0){ logf(INF, "Client disconnected: %s:%d", inet_ntoa(c.addr.sin_addr), ntohs(c.addr.sin_port)); to_close.push_back(c.sock); continue; } c.recvbuf.append(buf,buf+n); if(!c.websocket){ if(c.recvbuf.find("\r\n\r\n")!=std::string::npos){ if(websocket_handshake(c)) logf(INF, "WebSocket handshake OK! (%s:%d)", inet_ntoa(c.addr.sin_addr), ntohs(c.addr.sin_port)); else c.recvbuf.clear(); } } else { if(handle_websocket_frames(c)) to_close.push_back(c.sock); } } }
        if(!to_close.empty()){ std::lock_guard<std::mutex> lk(clients_mtx); for(int s:to_close){ close(s); remove_client_by_socket_locked(s); } }}
#endif
    }
    // cleanup
    { std::lock_guard<std::mutex> lk(clients_mtx); for(auto &c:clients){ if (c.sock!=INVALID_SOCKET){
#ifdef _WIN32
                closesocket(c.sock);
#else
                close(c.sock);
#endif
            } } clients.clear(); }

    // stop sender
    g_queue_cv.notify_one(); if(sender_thread.joinable()) 
    //sender_thread.join();

#ifdef _WIN32
    closesocket(server);
#else
    close(server);
#endif
    server_sock = INVALID_SOCKET;
    server_active = false;
}

// interactive CLI from your example
static void interactive(){
    // settings available before start
    int setting_port = 19134;
    int setting_delay = 10;
    logf(INF,"Interactive mode. Commands: setting start stop exit quit help");
    interactive_mode.store(true);
    std::string line;
    while (std::cout << "list2hosting> ", std::getline(std::cin, line)) {
        if(line.empty()) continue;
        std::istringstream ss(line); std::string cmd; ss>>cmd;
        std::string lcmd = tolower_s(cmd);
        if(lcmd=="exit"||lcmd=="quit"){
            if(server_active){
                server_active = false;
                std::lock_guard<std::mutex> lk(server_mtx);
                if(server_sock!=INVALID_SOCKET){
#ifdef _WIN32
                    closesocket(server_sock);
#else
                    close(server_sock);
#endif
                    server_sock = INVALID_SOCKET;
                }
                g_queue_cv.notify_one();
                if(server_thread.joinable()) server_thread.join();
                if(sender_thread.joinable()) sender_thread.join();
#ifdef _WIN32
                WSACleanup();
#endif
            }
            break;
        }
        if(lcmd=="help"){ std::cout<<"setting <key> <value>\nstart [port]\nstop\nqueue\nexit\n<any other line> -> send as Minecraft command\n"; continue; }

        if(lcmd=="setting"){
            std::string key, val; ss>>key>>val; if(key.empty()||val.empty()){ logf(WARN,"usage: setting <port|delay> <value>"); continue; }
            if(key=="port"){ try{ setting_port = std::stoi(val); logf(INF,"port=%d",setting_port);}catch(...){ logf(WARN,"bad port"); } }
            else if(key=="delay"){ try{ setting_delay = std::stoi(val); logf(INF,"delay=%d",setting_delay);}catch(...){ logf(WARN,"bad delay"); } }
            else { logf(WARN,"unknown setting"); }
            continue;
        }

        if(lcmd=="start"){
            int p = setting_port; if(ss>>p) { /* if provided */ }
            if(server_active){ logf(WARN,"server already running"); continue; }
            g_delay_ms = setting_delay;
            // initialize WinSock on Windows
#ifdef _WIN32
            {
                WSADATA wsa;
                if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) { logf(ERR, "WSAStartup failed"); continue; }
            }
#endif
            // start server in background
            {
                std::lock_guard<std::mutex> lk(server_mtx);
                server_active = true;
                server_thread = std::thread(run_server, p);
            }
            continue;
        }

        if(lcmd=="stop"){
            if(!server_active){ logf(WARN,"server not running"); continue; }
            // stop server
            server_active = false;
            // close listening socket to break accept/poll
            std::lock_guard<std::mutex> lk(server_mtx);
            if(server_sock!=INVALID_SOCKET){
#ifdef _WIN32
                closesocket(server_sock);
#else
                close(server_sock);
#endif
                server_sock = INVALID_SOCKET;
            }
            // wake sender
            g_queue_cv.notify_one();
            if(server_thread.joinable()) server_thread.join();
            if(sender_thread.joinable()) sender_thread.join();
#ifdef _WIN32
            WSACleanup();
#endif
            logf(INF,"server stopped");
            continue;
        }

        if(lcmd=="queue"){ enqueue_command("/say queue"); continue; }
        // any other line is treated as a raw command to send
        {
            std::string raw = line;
            if(!raw.empty()) { enqueue_command(raw); continue; }
        }
        logf(WARN,"unknown cmd");
    }
    interactive_mode.store(false);
}

int main(int argc, char** argv) {
    // If no args, run the interactive CLI
    if (argc <= 1) { interactive(); return 0; }

    // strict parsing: only allow --port <port> and optional --delay <ms>
    int port = -1;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) { try { port = std::stoi(argv[++i]); } catch(...) { print_help(); return 1; } }
        else if (arg == "--delay" && i + 1 < argc) { try { g_delay_ms = std::stoi(argv[++i]); } catch(...) { print_help(); return 1; } }
        else { print_help(); return 1; }
    }
    if (port <= 0) { print_help(); return 1; }

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) { logf(ERR, "WSAStartup failed"); return 1; }
#endif

    // set delay from args already stored in g_delay_ms
    g_delay_ms = g_delay_ms.load();
    // start server on this thread
    {
        std::lock_guard<std::mutex> lk(server_mtx);
        server_active = true;
    }
    run_server(port);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}