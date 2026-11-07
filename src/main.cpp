#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <shellapi.h>

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <string>
#include <vector>

typedef NTSTATUS(NTAPI* nt_open_dir_fn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* nt_query_dir_fn)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);

struct dir_entry {
    UNICODE_STRING name;
    UNICODE_STRING type;
};

static const int kind_event   = 0;
static const int kind_mutex   = 1;
static const int kind_section = 2;

struct held {
    const wchar_t* name;
    int kind;
    HANDLE h;
    bool we_made;
    DWORD err;
};

static const wchar_t* default_names[] = {
    L"ROBLOX_singletonEvent.pioneer",
    L"ROBLOX_singletonMutex.pioneer",
    L"ROBLOX_singletonEvent",
    L"ROBLOX_singletonMutex"
};

static HANDLE stop_evt;

static BOOL WINAPI on_break(DWORD) {
    if (stop_evt) SetEvent(stop_evt);
    return TRUE;
}

static bool has_ci(const wchar_t* s, USHORT n, const wchar_t* needle) {
    const size_t m = wcslen(needle);
    if (n < m) return false;
    for (size_t i = 0; i + m <= n; ++i) {
        size_t k = 0;
        while (k < m && towlower(s[i + k]) == towlower(needle[k])) ++k;
        if (k == m) return true;
    }
    return false;
}

static int classify(const wchar_t* name) {
    const size_t n = wcslen(name);
    if (n >= 4 && _wcsicmp(name + n - 4, L".shm") == 0) return kind_section;
    if (n >= 4 && _wcsicmp(name + n - 4, L".mtx") == 0) return kind_mutex;
    if (has_ci(name, USHORT(n), L"mutex")) return kind_mutex;
    if (has_ci(name, USHORT(n), L"section") || has_ci(name, USHORT(n), L"fmap")) return kind_section;
    return kind_event;
}

static const char* kind_str(int k) {
    return k == kind_event ? "event" : k == kind_mutex ? "mutex" : "section";
}

static int probe(bool show_all) {
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    auto open_dir  = reinterpret_cast<nt_open_dir_fn >(GetProcAddress(nt, "NtOpenDirectoryObject"));
    auto query_dir = reinterpret_cast<nt_query_dir_fn>(GetProcAddress(nt, "NtQueryDirectoryObject"));
    if (!open_dir || !query_dir) { fputs("ntdll: entry points missing\n", stderr); return 1; }

    DWORD sid = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sid);

    wchar_t path_session[64];
    wchar_t path_global[] = L"\\BaseNamedObjects";
    _snwprintf_s(path_session, _countof(path_session), _TRUNCATE, L"\\Sessions\\%lu\\BaseNamedObjects", (unsigned long)sid);

    HANDLE dir = nullptr;
    NTSTATUS s = 0;
    for (int tier = 0; tier < 2 && !dir; ++tier) {
        wchar_t* p = tier == 0 ? path_session : path_global;
        UNICODE_STRING uname{};
        uname.Buffer = p;
        uname.Length = USHORT(wcslen(p) * sizeof(wchar_t));
        uname.MaximumLength = USHORT(uname.Length + sizeof(wchar_t));
        OBJECT_ATTRIBUTES oa{};
        oa.Length = sizeof(oa);
        oa.ObjectName = &uname;
        s = open_dir(&dir, DIRECTORY_QUERY, &oa);
        if (s < 0 || !dir) { dir = nullptr; if (tier == 1) { fprintf(stderr, "open BaseNamedObjects: 0x%08lX\n", (unsigned long)s); return 1; } }
        else { printf("# %ls\n", p); }
    }

    std::vector<unsigned char> buf(1 << 18);
    ULONG ctx = 0, shown = 0, total = 0;
    BOOLEAN first = TRUE;
    for (;;) {
        ULONG got = 0;
        s = query_dir(dir, buf.data(), ULONG(buf.size()), FALSE, first, &ctx, &got);
        first = FALSE;
        if (s != 0 && s != (NTSTATUS)0x00000105) break;
        auto* e = reinterpret_cast<dir_entry*>(buf.data());
        for (; e->name.Length; ++e) {
            ++total;
            const wchar_t* nm = e->name.Buffer;
            const USHORT nc = e->name.Length / sizeof(wchar_t);
            const bool hit =
                has_ci(nm, nc, L"roblox") ||
                has_ci(nm, nc, L"singleton") ||
                has_ci(nm, nc, L".mtx") ||
                has_ci(nm, nc, L".shm") ||
                has_ci(nm, nc, L"pioneer");
            if (show_all || hit) {
                ++shown;
                printf("%-10.*ls  %.*ls\n",
                    int(e->type.Length / sizeof(wchar_t)), e->type.Buffer,
                    int(nc), nm);
            }
        }
        if (s == 0) break;
    }
    CloseHandle(dir);
    printf("%lu shown of %lu\n", (unsigned long)shown, (unsigned long)total);
    return 0;
}

static bool empty_dacl(SECURITY_ATTRIBUTES& sa, SECURITY_DESCRIPTOR& sd, std::vector<unsigned char>& bytes) {
    bytes.assign(sizeof(ACL), 0);
    auto* acl = reinterpret_cast<PACL>(bytes.data());
    if (!InitializeAcl(acl, DWORD(bytes.size()), ACL_REVISION)) return false;
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) return false;
    if (!SetSecurityDescriptorDacl(&sd, TRUE, acl, FALSE)) return false;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;
    return true;
}

static int hold(const std::vector<const wchar_t*>& names) {
    SECURITY_ATTRIBUTES sa{};
    SECURITY_DESCRIPTOR sd{};
    std::vector<unsigned char> acl_bytes;
    if (!empty_dacl(sa, sd, acl_bytes)) { fprintf(stderr, "sd: %lu\n", GetLastError()); return 1; }

    stop_evt = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler(on_break, TRUE);

    std::vector<held> owned;
    for (const wchar_t* nm : names) {
        held h{};
        h.name = nm;
        h.kind = classify(nm);
        SetLastError(0);
        switch (h.kind) {
            case kind_event:   h.h = CreateEventW(&sa, TRUE, FALSE, nm); break;
            case kind_mutex:   h.h = CreateMutexW(&sa, FALSE, nm);       break;
            default:           h.h = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, 0x400, nm); break;
        }
        h.err = GetLastError();
        h.we_made = h.h && h.err != ERROR_ALREADY_EXISTS;
        owned.push_back(h);

        if (!h.h)                printf("  %-8s %-34ls  fail %lu\n",      kind_str(h.kind), nm, (unsigned long)h.err);
        else if (!h.we_made)     printf("  %-8s %-34ls  existed already\n", kind_str(h.kind), nm);
        else                     printf("  %-8s %-34ls  held\n",            kind_str(h.kind), nm);
    }

    int mine = 0;
    for (const held& h : owned) if (h.we_made) ++mine;
    printf("%d/%d held. Ctrl+C to release.\n", mine, int(owned.size()));
    fflush(stdout);

    WaitForSingleObject(stop_evt, INFINITE);

    for (const held& h : owned) {
        if (!h.we_made || !h.h) continue;
        if (h.kind == kind_event) ResetEvent(h.h);
        CloseHandle(h.h);
    }
    return 0;
}

static std::wstring parent_dir(const std::wstring& path) {
    size_t s = path.find_last_of(L"\\/");
    return s == std::wstring::npos ? std::wstring(L".") : path.substr(0, s);
}

static std::wstring base_name(const std::wstring& path) {
    size_t s = path.find_last_of(L"\\/");
    return s == std::wstring::npos ? path : path.substr(s + 1);
}

static bool ntfs_has_hardlinks(const std::wstring& dir) {
    HANDLE h = CreateFileW(dir.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    wchar_t volname[MAX_PATH];
    wchar_t fsname[MAX_PATH];
    DWORD serial = 0, maxcomp = 0, flags = 0;
    BOOL ok = GetVolumeInformationByHandleW(h, volname, MAX_PATH, &serial, &maxcomp, &flags, fsname, MAX_PATH);
    CloseHandle(h);
    return ok && (flags & FILE_SUPPORTS_HARD_LINKS) != 0;
}

static std::wstring derive_secondary(const std::wstring& primary, int slot) {
    size_t sep = primary.find_last_of(L"\\/");
    size_t dot = primary.find_last_of(L'.');
    if (dot == std::wstring::npos || (sep != std::wstring::npos && dot < sep)) dot = primary.length();
    wchar_t suffix[32];
    _snwprintf_s(suffix, _countof(suffix), _TRUNCATE, L"_peer%d", slot);
    return primary.substr(0, dot) + suffix + primary.substr(dot);
}

static int pick_free_slot(const std::wstring& primary) {
    for (int slot = 2; slot < 32; ++slot) {
        std::wstring c = derive_secondary(primary, slot);
        if (GetFileAttributesW(c.c_str()) == INVALID_FILE_ATTRIBUTES) return slot;
    }
    return -1;
}

static bool make_link(const std::wstring& primary, const std::wstring& secondary) {
    DeleteFileW(secondary.c_str());
    if (CreateHardLinkW(secondary.c_str(), primary.c_str(), nullptr)) return true;
    DWORD err = GetLastError();
    fprintf(stderr, "CreateHardLinkW: %lu\n", (unsigned long)err);
    return false;
}

static bool resolve_link(const std::wstring& primary, int& slot, std::wstring& secondary) {
    DWORD attrs = GetFileAttributesW(primary.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "primary not found: %ls\n", primary.c_str());
        return false;
    }
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        fprintf(stderr, "primary is a directory: %ls\n", primary.c_str());
        return false;
    }
    if (!ntfs_has_hardlinks(parent_dir(primary))) {
        fputs("volume does not support hard links\n", stderr);
        return false;
    }
    if (slot < 0) slot = pick_free_slot(primary);
    if (slot < 0) {
        fputs("no free peer slot in 2..31\n", stderr);
        return false;
    }
    secondary = derive_secondary(primary, slot);
    return true;
}

static int do_link(const std::wstring& primary, int slot) {
    std::wstring secondary;
    if (!resolve_link(primary, slot, secondary)) return 1;
    if (!make_link(primary, secondary)) return 1;
    printf("%ls\n", secondary.c_str());
    return 0;
}

struct watcher_ctx {
    const wchar_t* primary;
    const wchar_t* secondary;
    const wchar_t* primary_name;
    HANDLE stop;
};

static DWORD WINAPI watcher_proc(LPVOID p) {
    auto* ctx = reinterpret_cast<watcher_ctx*>(p);
    std::wstring dir = parent_dir(ctx->primary);
    HANDLE hdir = CreateFileW(dir.c_str(), FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
    if (hdir == INVALID_HANDLE_VALUE) return 1;

    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::vector<unsigned char> buf(1 << 14);

    for (;;) {
        ResetEvent(ov.hEvent);
        DWORD unused = 0;
        if (!ReadDirectoryChangesW(hdir, buf.data(), DWORD(buf.size()), FALSE,
                FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_FILE_NAME,
                &unused, &ov, nullptr)) break;

        HANDLE waits[2] = { ov.hEvent, ctx->stop };
        DWORD w = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        if (w != WAIT_OBJECT_0) {
            CancelIoEx(hdir, &ov);
            DWORD g2 = 0;
            GetOverlappedResult(hdir, &ov, &g2, TRUE);
            break;
        }

        DWORD got = 0;
        if (!GetOverlappedResult(hdir, &ov, &got, FALSE)) continue;

        bool need_relink = false;
        unsigned char* q = buf.data();
        while (got >= sizeof(FILE_NOTIFY_INFORMATION)) {
            auto* fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(q);
            USHORT nlen = USHORT(fni->FileNameLength / sizeof(wchar_t));
            std::wstring name(fni->FileName, nlen);
            if (_wcsicmp(name.c_str(), ctx->primary_name) == 0) need_relink = true;
            if (!fni->NextEntryOffset) break;
            q += fni->NextEntryOffset;
        }

        if (need_relink) {
            DeleteFileW(ctx->secondary);
            CreateHardLinkW(ctx->secondary, ctx->primary, nullptr);
        }
    }

    CloseHandle(ov.hEvent);
    CloseHandle(hdir);
    return 0;
}

static std::wstring absolute_path(const std::wstring& p) {
    wchar_t buf[2048];
    DWORD r = GetFullPathNameW(p.c_str(), (DWORD)_countof(buf), buf, nullptr);
    if (r == 0 || r >= _countof(buf)) return p;
    return std::wstring(buf, r);
}

static bool letter_is_free(const wchar_t* letter) {
    wchar_t target[8];
    DWORD r = QueryDosDeviceW(letter, target, (DWORD)_countof(target));
    return r == 0 && GetLastError() == ERROR_FILE_NOT_FOUND;
}

static std::wstring pick_free_letter() {
    wchar_t letter[3] = { 0, L':', 0 };
    for (wchar_t c = L'Z'; c >= L'D'; --c) {
        letter[0] = c;
        if (letter_is_free(letter)) return std::wstring(letter);
    }
    return std::wstring();
}

static bool normalize_letter(std::wstring& letter) {
    if (letter.empty()) return false;
    if (letter.size() == 1) letter.push_back(L':');
    if (letter.size() != 2 || letter[1] != L':') return false;
    wchar_t c = (wchar_t)towupper(letter[0]);
    if (c < L'A' || c > L'Z') return false;
    letter[0] = c;
    return letter_is_free(letter.c_str());
}

struct dos_bind {
    std::wstring letter;
    std::wstring target;
    std::wstring launch_path;
    bool defined;
};

static bool dos_bind_create(const std::wstring& abs_primary, const std::wstring& forced_letter, dos_bind& out, bool quiet) {
    std::wstring letter = forced_letter;
    if (letter.empty()) {
        letter = pick_free_letter();
        if (letter.empty()) { if (!quiet) fputs("no free drive letter\n", stderr); return false; }
    } else if (!normalize_letter(letter)) {
        if (!quiet) fprintf(stderr, "letter busy or invalid: %ls\n", forced_letter.c_str());
        return false;
    }
    std::wstring dir = parent_dir(abs_primary);
    while (!dir.empty() && (dir.back() == L'\\' || dir.back() == L'/')) dir.pop_back();
    if (dir.size() == 2 && dir[1] == L':') dir.push_back(L'\\');
    if (dir.empty()) { if (!quiet) fputs("empty install dir\n", stderr); return false; }
    out.letter = letter;
    out.target = dir;
    out.launch_path = letter + L"\\" + base_name(abs_primary);
    if (!DefineDosDeviceW(0, out.letter.c_str(), out.target.c_str())) {
        if (!quiet) fprintf(stderr, "DefineDosDeviceW: %lu\n", (unsigned long)GetLastError());
        out.defined = false;
        return false;
    }
    out.defined = true;
    return true;
}

static void dos_bind_destroy(dos_bind& b) {
    if (!b.defined) return;
    std::wstring raw = L"\\??\\" + b.target;
    DefineDosDeviceW(DDD_REMOVE_DEFINITION | DDD_RAW_TARGET_PATH, b.letter.c_str(), raw.c_str());
    b.defined = false;
}

static int do_spawn_dos(const std::wstring& primary, const std::wstring& forced_letter, const std::wstring& tail, bool quiet = false) {
    std::wstring abs_primary = absolute_path(primary);
    DWORD attrs = GetFileAttributesW(abs_primary.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        if (!quiet) fprintf(stderr, "primary not found: %ls\n", abs_primary.c_str());
        return 1;
    }
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        if (!quiet) fprintf(stderr, "primary is a directory: %ls\n", abs_primary.c_str());
        return 1;
    }

    dos_bind b{};
    if (!dos_bind_create(abs_primary, forced_letter, b, quiet)) return 1;

    std::wstring cmdline = L"\"" + b.launch_path + L"\"";
    if (!tail.empty()) cmdline += L" " + tail;

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cb(cmdline.begin(), cmdline.end());
    cb.push_back(0);

    std::wstring dir = parent_dir(abs_primary);
    BOOL ok = CreateProcessW(b.launch_path.c_str(), cb.data(), nullptr, nullptr,
        FALSE, 0, nullptr, dir.c_str(), &si, &pi);
    DWORD cperr = GetLastError();

    if (!ok) {
        if (!quiet) fprintf(stderr, "CreateProcessW: %lu\n", (unsigned long)cperr);
        dos_bind_destroy(b);
        return 1;
    }
    if (!quiet) {
        printf("pid %lu  %ls\n", (unsigned long)pi.dwProcessId, b.launch_path.c_str());
        fflush(stdout);
    }

    stop_evt = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler(on_break, TRUE);

    HANDLE waits[2] = { pi.hProcess, stop_evt };
    WaitForMultipleObjects(2, waits, FALSE, INFINITE);

    SetEvent(stop_evt);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    dos_bind_destroy(b);
    return 0;
}

static int do_spawn(const std::wstring& primary, int slot, bool watch, const std::wstring& tail) {
    std::wstring secondary;
    if (!resolve_link(primary, slot, secondary)) return 1;

    HANDLE hpin = CreateFileW(primary.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);

    if (!make_link(primary, secondary)) {
        if (hpin != INVALID_HANDLE_VALUE) CloseHandle(hpin);
        return 1;
    }

    std::wstring cmdline = L"\"" + secondary + L"\"";
    if (!tail.empty()) cmdline += L" " + tail;

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cb(cmdline.begin(), cmdline.end());
    cb.push_back(0);

    std::wstring dir = parent_dir(primary);
    BOOL ok = CreateProcessW(secondary.c_str(), cb.data(), nullptr, nullptr,
        FALSE, 0, nullptr, dir.c_str(), &si, &pi);
    DWORD cperr = GetLastError();

    if (hpin != INVALID_HANDLE_VALUE) CloseHandle(hpin);

    if (!ok) {
        fprintf(stderr, "CreateProcessW: %lu\n", (unsigned long)cperr);
        DeleteFileW(secondary.c_str());
        return 1;
    }
    printf("pid %lu  %ls\n", (unsigned long)pi.dwProcessId, secondary.c_str());
    fflush(stdout);

    stop_evt = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler(on_break, TRUE);

    std::wstring primary_name = base_name(primary);
    watcher_ctx wctx{ primary.c_str(), secondary.c_str(), primary_name.c_str(), stop_evt };
    HANDLE watcher = nullptr;
    if (watch) watcher = CreateThread(nullptr, 0, watcher_proc, &wctx, 0, nullptr);

    HANDLE waits[2] = { pi.hProcess, stop_evt };
    WaitForMultipleObjects(2, waits, FALSE, INFINITE);

    SetEvent(stop_evt);
    if (watcher) {
        WaitForSingleObject(watcher, 3000);
        CloseHandle(watcher);
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    DeleteFileW(secondary.c_str());
    return 0;
}

static bool is_abs(const std::wstring& p) {
    if (p.size() >= 3 && p[1] == L':' && (p[2] == L'\\' || p[2] == L'/')) {
        wchar_t c = p[0];
        if ((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z')) return true;
    }
    if (p.size() >= 2 && p[0] == L'\\' && p[1] == L'\\') return true;
    return false;
}

static bool is_player(const std::wstring& p) {
    static const wchar_t exe[] = L"RobloxPlayerBeta.exe";
    const size_t n = 20;
    if (p.size() < n) return false;
    if (_wcsicmp(p.c_str() + p.size() - n, exe) != 0) return false;
    if (p.size() > n) {
        wchar_t s = p[p.size() - n - 1];
        if (s != L'\\' && s != L'/') return false;
    }
    return true;
}

static bool path_ok(const std::wstring& p) {
    if (!is_abs(p) || !is_player(p)) return false;
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static std::wstring reg_read(HKEY root, const wchar_t* sub, const wchar_t* val) {
    HKEY k = nullptr;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &k) != ERROR_SUCCESS) return {};
    DWORD type = 0, sz = 0;
    LONG r = RegQueryValueExW(k, val, nullptr, &type, nullptr, &sz);
    if (r != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || sz < sizeof(wchar_t)) {
        RegCloseKey(k);
        return {};
    }
    std::wstring buf(sz / sizeof(wchar_t), 0);
    r = RegQueryValueExW(k, val, nullptr, &type, reinterpret_cast<LPBYTE>(&buf[0]), &sz);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS) return {};
    while (!buf.empty() && buf.back() == 0) buf.pop_back();
    if (type == REG_EXPAND_SZ) {
        wchar_t out[2048];
        DWORD n = ExpandEnvironmentStringsW(buf.c_str(), out, (DWORD)_countof(out));
        if (!n || n > _countof(out)) return {};
        return std::wstring(out, n - 1);
    }
    return buf;
}

static std::wstring parse_cmd(const std::wstring& c) {
    size_t i = 0;
    while (i < c.size() && (c[i] == L' ' || c[i] == L'\t')) ++i;
    if (i >= c.size()) return {};
    if (c[i] == L'"') {
        size_t e = c.find(L'"', i + 1);
        if (e == std::wstring::npos) return {};
        return c.substr(i + 1, e - i - 1);
    }
    for (size_t j = i; j + 4 <= c.size(); ++j) {
        if (_wcsnicmp(c.c_str() + j, L".exe", 4) == 0) return c.substr(i, j + 4 - i);
    }
    size_t e = c.find(L' ', i);
    return e == std::wstring::npos ? c.substr(i) : c.substr(i, e - i);
}

static std::wstring newest_ver() {
    wchar_t la[MAX_PATH];
    DWORD n = ExpandEnvironmentStringsW(L"%LOCALAPPDATA%", la, (DWORD)_countof(la));
    if (!n || n > _countof(la)) return {};
    std::wstring base(la, n - 1);
    base += L"\\Roblox\\Versions\\";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((base + L"version-*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return {};
    std::wstring best;
    FILETIME bt{};
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        std::wstring cand = base + fd.cFileName + L"\\RobloxPlayerBeta.exe";
        DWORD a = GetFileAttributesW(cand.c_str());
        if (a == INVALID_FILE_ATTRIBUTES || (a & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (best.empty() || CompareFileTime(&fd.ftLastWriteTime, &bt) > 0) {
            best = cand;
            bt = fd.ftLastWriteTime;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return best;
}

static std::wstring find_roblox_player() {
    std::wstring p = reg_read(HKEY_CURRENT_USER,
        L"Software\\ROBLOX Corporation\\Environments\\roblox-player", L"clientExe");
    if (path_ok(p)) return p;

    p = parse_cmd(reg_read(HKEY_CLASSES_ROOT, L"roblox-player\\shell\\open\\command", nullptr));
    if (path_ok(p)) return p;

    p = parse_cmd(reg_read(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Classes\\roblox-player\\shell\\open\\command", nullptr));
    if (path_ok(p)) return p;

    p = newest_ver();
    if (path_ok(p)) return p;

    return {};
}

struct enum_ctx {
    DWORD pid;
    bool found;
};

static BOOL CALLBACK enum_proc(HWND w, LPARAM l) {
    auto* e = reinterpret_cast<enum_ctx*>(l);
    DWORD p = 0;
    GetWindowThreadProcessId(w, &p);
    if (p == e->pid && IsWindowVisible(w) && GetWindow(w, GW_OWNER) == nullptr) {
        e->found = true;
        return FALSE;
    }
    return TRUE;
}

static bool has_top_window(DWORD pid) {
    enum_ctx e{ pid, false };
    EnumWindows(enum_proc, reinterpret_cast<LPARAM>(&e));
    return e.found;
}

static int do_run() {
    std::wstring exe = find_roblox_player();
    if (exe.empty()) return 2;

    SECURITY_ATTRIBUTES sa{};
    SECURITY_DESCRIPTOR sd{};
    std::vector<unsigned char> acl_bytes;
    if (!empty_dacl(sa, sd, acl_bytes)) return 2;

    std::vector<held> owned;
    for (const wchar_t* nm : default_names) {
        held h{};
        h.name = nm;
        h.kind = classify(nm);
        SetLastError(0);
        h.h = (h.kind == kind_event)
            ? CreateEventW(&sa, TRUE, FALSE, nm)
            : CreateMutexW(&sa, FALSE, nm);
        h.err = GetLastError();
        h.we_made = h.h && h.err != ERROR_ALREADY_EXISTS;
        owned.push_back(h);
    }

    stop_evt = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler(on_break, TRUE);

    HINSTANCE r = ShellExecuteW(nullptr, L"open", L"roblox-player://1", nullptr, nullptr, SW_SHOWNORMAL);
    if ((INT_PTR)r <= 32) {
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        std::vector<wchar_t> cb(exe.begin(), exe.end());
        cb.push_back(0);
        std::wstring dir = parent_dir(exe);
        if (!CreateProcessW(exe.c_str(), cb.data(), nullptr, nullptr, FALSE, 0, nullptr, dir.c_str(), &si, &pi)) {
            for (const held& h : owned) {
                if (!h.we_made || !h.h) continue;
                if (h.kind == kind_event) ResetEvent(h.h);
                CloseHandle(h.h);
            }
            return 2;
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    std::wstring peer1_path;
    DWORD peer1_pid = 0;
    const DWORD deadline = GetTickCount() + 120 * 1000;
    while (!peer1_pid) {
        if (WaitForSingleObject(stop_evt, 500) == WAIT_OBJECT_0) break;
        if (GetTickCount() > deadline) break;

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, L"RobloxPlayerBeta.exe") != 0) continue;
                if (!has_top_window(pe.th32ProcessID)) continue;
                HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (!p) continue;
                wchar_t buf[MAX_PATH * 2];
                DWORD sz = _countof(buf);
                if (QueryFullProcessImageNameW(p, 0, buf, &sz)) {
                    peer1_path.assign(buf, sz);
                    peer1_pid = pe.th32ProcessID;
                }
                CloseHandle(p);
                if (peer1_pid) break;
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }

    int rc = peer1_pid ? do_spawn_dos(peer1_path, L"", L"", true) : 2;

    for (const held& h : owned) {
        if (!h.we_made || !h.h) continue;
        if (h.kind == kind_event) ResetEvent(h.h);
        CloseHandle(h.h);
    }
    return rc;
}

static void usage() {
    fputs(
        "usage: multiclient                                     (one-shot: hold + wait for peer 1 + spawn peer 2)\n"
        "       multiclient run\n"
        "       multiclient probe [--all]\n"
        "       multiclient hold [name ...]\n"
        "       multiclient link <exe> [--slot N]\n"
        "       multiclient spawn <exe> [--via dosdevice|hardlink] [--letter X] [--slot N] [--no-watch] [-- args...]\n",
        stdout);
}

int main(int argc, char** argv) {
    if (argc < 2 || _stricmp(argv[1], "run") == 0) {
        return do_run();
    }

    if (_stricmp(argv[1], "probe") == 0) {
        bool all = false;
        for (int i = 2; i < argc; ++i) if (_stricmp(argv[i], "--all") == 0) all = true;
        return probe(all);
    }

    if (_stricmp(argv[1], "hold") == 0) {
        std::vector<std::wstring> storage;
        std::vector<const wchar_t*> names;
        for (int i = 2; i < argc; ++i) {
            const int need = MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, nullptr, 0);
            std::wstring w(need ? need - 1 : 0, 0);
            if (need) MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, &w[0], need);
            storage.push_back(std::move(w));
        }
        for (const std::wstring& w : storage) names.push_back(w.c_str());
        if (names.empty()) for (const wchar_t* n : default_names) names.push_back(n);
        return hold(names);
    }

    if (_stricmp(argv[1], "link") == 0) {
        std::wstring primary;
        int slot = -1;
        for (int i = 2; i < argc; ++i) {
            if (_stricmp(argv[i], "--slot") == 0 && i + 1 < argc) {
                slot = atoi(argv[++i]);
            } else if (primary.empty()) {
                const int need = MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, nullptr, 0);
                std::wstring w(need ? need - 1 : 0, 0);
                if (need) MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, &w[0], need);
                primary = std::move(w);
            }
        }
        if (primary.empty()) { usage(); return 1; }
        return do_link(primary, slot);
    }

    if (_stricmp(argv[1], "spawn") == 0) {
        std::wstring primary;
        std::wstring tail;
        std::wstring letter;
        int slot = -1;
        bool watch = true;
        bool after_sep = false;
        bool via_dos = true;
        for (int i = 2; i < argc; ++i) {
            if (after_sep) {
                const int need = MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, nullptr, 0);
                std::wstring w(need ? need - 1 : 0, 0);
                if (need) MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, &w[0], need);
                if (!tail.empty()) tail += L" ";
                if (w.find(L' ') != std::wstring::npos) tail += L"\"" + w + L"\"";
                else tail += w;
            } else if (strcmp(argv[i], "--") == 0) {
                after_sep = true;
            } else if (_stricmp(argv[i], "--slot") == 0 && i + 1 < argc) {
                slot = atoi(argv[++i]);
            } else if (_stricmp(argv[i], "--no-watch") == 0) {
                watch = false;
            } else if (_stricmp(argv[i], "--via") == 0 && i + 1 < argc) {
                ++i;
                if (_stricmp(argv[i], "dosdevice") == 0) via_dos = true;
                else if (_stricmp(argv[i], "hardlink") == 0) via_dos = false;
                else { fprintf(stderr, "bad --via: %s\n", argv[i]); return 1; }
            } else if (_stricmp(argv[i], "--letter") == 0 && i + 1 < argc) {
                ++i;
                const int need = MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, nullptr, 0);
                std::wstring w(need ? need - 1 : 0, 0);
                if (need) MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, &w[0], need);
                letter = std::move(w);
            } else if (primary.empty()) {
                const int need = MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, nullptr, 0);
                std::wstring w(need ? need - 1 : 0, 0);
                if (need) MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, &w[0], need);
                primary = std::move(w);
            }
        }
        if (primary.empty()) { usage(); return 1; }
        if (via_dos) return do_spawn_dos(primary, letter, tail);
        return do_spawn(primary, slot, watch, tail);
    }

    usage();
    return 0;
}
