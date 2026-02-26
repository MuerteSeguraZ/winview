/*
 * Signing Key Viewer - Win32 GUI
 * GPG | SSH | CertStore | NCrypt KSP | TPM | Secure Boot
 *
 * Compile (MinGW/MSYS2):
 *   gcc keyviewer.c -o keyviewer.exe -mwindows -lcomctl32 -lcrypt32 \
 *       -lshlwapi -lncrypt -lwbemUuid -lole32 -loleaut32 -Wall
 *
 * Note: WMI (TPM info) requires COM/DCOM. Linked via ole32+oleaut32.
 *
 * UI Improvements v2:
 *  - Status bar with 3 panels: message | key count | last refresh time
 *  - Keyboard shortcuts: F5=Refresh, Ctrl+C=Copy, Ctrl+F=Focus search,
 *                        Escape=Clear search, Ctrl+E=Expand all,
 *                        Ctrl+W=Collapse all, Ctrl+S=Save baseline
 *  - Search box cue banner ("Search keys…")
 *  - Expand All / Collapse All buttons
 *  - Word-wrap toggle for detail pane
 *  - Detail pane font size +/- buttons
 *  - Splitter highlights blue on hover/drag
 *  - Tree item count shown in status bar after populate
 *  - Last refresh timestamp in status bar
 *  - Improved toolbar layout with visual separator
 *  - Copy button copies full detail pane path (Ctrl+Shift+C)
 *  - Window title shows "Key Viewer  [Admin]" when elevated
 */

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define NTDDI_VERSION 0x06010000

#include <windows.h>
#include <commctrl.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <shlobj.h>
#include <wbemidl.h>
#include <objbase.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

/* ── IDs ────────────────────────────────────────────────── */
#define ID_TREEVIEW     1001
#define ID_STATUSBAR    1002
#define ID_REFRESH      1003
#define ID_COPYKEY      1004
#define ID_SEARCH       1005
#define ID_DETAIL       1006
#define ID_SPLITTER     1007
#define ID_BASELINE     1008
#define ID_EXPANDALL    1009
#define ID_COLLAPSEALL  1010
#define ID_WORDWRAP     1011
#define ID_FONTPLUS     1012
#define ID_FONTMINUS    1013

/* ── Status bar panel indices ───────────────────────────── */
#define SB_PANEL_MSG    0
#define SB_PANEL_COUNT  1
#define SB_PANEL_TIME   2

/* ── Layout ─────────────────────────────────────────────── */
#define TOOLBAR_H       44
#define SPLITTER_W      6
#define DETAIL_MIN      180
#define DETAIL_DEF      320
#define BTN_H           28
#define BTN_Y           8

static HWND g_hTree    = NULL;
static HWND g_hStatus  = NULL;
static HWND g_hWnd     = NULL;
static HWND g_hSearch  = NULL;
static HWND g_hDetail  = NULL;
static HWND g_hSplitter= NULL;
static int  g_splitX   = 0;
static BOOL g_dragging = FALSE;
static BOOL g_splitterHot = FALSE;

/* ── Detail pane state ──────────────────────────────────── */
static int  g_detailFontSize = 14;
static BOOL g_wordWrap       = FALSE;
static HFONT g_detailFont    = NULL;

/* ── PCR Baseline ───────────────────────────────────────── */
#define PCR_COUNT 24
#define PCR_HASH_LEN 32

static BYTE g_baseline[PCR_COUNT][PCR_HASH_LEN] = {0};
static BOOL g_baselineValid  = FALSE;
static BOOL g_baselineDirty  = FALSE;

static void GetBaselinePath(wchar_t *out, DWORD outChars)
{
    wchar_t appData[MAX_PATH]={0};
    SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appData);
    swprintf_s(out, outChars, L"%s\\KeyViewer", appData);
    CreateDirectoryW(out, NULL);
    swprintf_s(out, outChars, L"%s\\KeyViewer\\pcr_baseline.bin", appData);
}

static void LoadBaseline(void)
{
    wchar_t path[MAX_PATH]={0};
    GetBaselinePath(path, MAX_PATH);
    HANDLE hF = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, 0, NULL);
    if(hF == INVALID_HANDLE_VALUE){ g_baselineValid=FALSE; return; }
    DWORD nr=0;
    BOOL ok = ReadFile(hF, g_baseline, sizeof(g_baseline), &nr, NULL);
    CloseHandle(hF);
    g_baselineValid = (ok && nr==sizeof(g_baseline));
}

static void SaveBaseline(const BYTE src[PCR_COUNT][PCR_HASH_LEN])
{
    wchar_t path[MAX_PATH]={0};
    GetBaselinePath(path, MAX_PATH);
    HANDLE hF = CreateFileW(path, GENERIC_WRITE, 0,
                             NULL, CREATE_ALWAYS, 0, NULL);
    if(hF == INVALID_HANDLE_VALUE) return;
    DWORD nw=0;
    WriteFile(hF, src, PCR_COUNT*PCR_HASH_LEN, &nw, NULL);
    CloseHandle(hF);
    memcpy(g_baseline, src, sizeof(g_baseline));
    g_baselineValid = TRUE;
}

/* ── Color-coded item data ──────────────────────────────── */
#define COL_DEFAULT  0
#define COL_HARDWARE 1
#define COL_WARN     2
#define COL_GOOD     3
#define COL_BAD      4
#define COL_HEADER   5

static COLORREF g_colors[] = {
    RGB(20,  20,  20),
    RGB(0,   80,  200),
    RGB(200, 120, 0),
    RGB(0,   140, 60),
    RGB(200, 40,  40),
    RGB(80,  80,  80),
};

/* ── Admin elevation check ──────────────────────────────── */
static BOOL IsElevated(void)
{
    BOOL elevated = FALSE;
    HANDLE hToken = NULL;
    if(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)){
        TOKEN_ELEVATION te;
        DWORD cb = sizeof(te);
        if(GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &cb))
            elevated = te.TokenIsElevated;
        CloseHandle(hToken);
    }
    return elevated;
}

/* ── Update window title with elevation indicator ────────── */
static void UpdateWindowTitle(void)
{
    wchar_t title[128];
    if(IsElevated())
        wcscpy_s(title, 128, L"Key Viewer  \u26A1 [Administrator]");
    else
        wcscpy_s(title, 128, L"Key Viewer  (run as Admin for full data)");
    SetWindowTextW(g_hWnd, title);
}

/* ── Status bar helpers ─────────────────────────────────── */
static void SetStatusMsg(const wchar_t *msg)
{
    SendMessage(g_hStatus, SB_SETTEXT, SB_PANEL_MSG, (LPARAM)msg);
}

static void SetStatusCount(int count)
{
    wchar_t buf[64];
    swprintf_s(buf, 63, L"%d items", count);
    SendMessage(g_hStatus, SB_SETTEXT, SB_PANEL_COUNT, (LPARAM)buf);
}

static void SetStatusTime(void)
{
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t buf[64];
    swprintf_s(buf, 63, L"Refreshed %02d:%02d:%02d",
               st.wHour, st.wMinute, st.wSecond);
    SendMessage(g_hStatus, SB_SETTEXT, SB_PANEL_TIME, (LPARAM)buf);
}

/* ── Count all tree items ───────────────────────────────── */
static int CountTreeItems(void)
{
    int count = 0;
    HTREEITEM h = TreeView_GetRoot(g_hTree);
    typedef struct { HTREEITEM h; } Frame;
    Frame stack[1024]; int top = 0;
    if(h){ stack[top++].h = h; }
    while(top > 0){
        Frame f = stack[--top];
        count++;
        HTREEITEM sib = TreeView_GetNextSibling(g_hTree, f.h);
        if(sib && top < 1023) stack[top++].h = sib;
        HTREEITEM ch = TreeView_GetChild(g_hTree, f.h);
        if(ch && top < 1023) stack[top++].h = ch;
    }
    return count;
}

/* ── Expand/Collapse all tree items ─────────────────────── */
static void TreeExpandAll(HWND hTree, HTREEITEM hItem, UINT code)
{
    if(!hItem) return;
    SendMessage(hTree, TVM_EXPAND, code, (LPARAM)hItem);
    HTREEITEM ch = TreeView_GetChild(hTree, hItem);
    while(ch){
        TreeExpandAll(hTree, ch, code);
        ch = TreeView_GetNextSibling(hTree, ch);
    }
}

static void DoExpandAll(void)
{
    HTREEITEM root = TreeView_GetRoot(g_hTree);
    SendMessage(g_hTree, WM_SETREDRAW, FALSE, 0);
    TreeExpandAll(g_hTree, root, TVE_EXPAND);
    SendMessage(g_hTree, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hTree, NULL, TRUE);
    SetStatusMsg(L"Expanded all nodes");
}

static void DoCollapseAll(void)
{
    HTREEITEM root = TreeView_GetRoot(g_hTree);
    SendMessage(g_hTree, WM_SETREDRAW, FALSE, 0);
    TreeExpandAll(g_hTree, root, TVE_COLLAPSE);
    /* Re-expand just the root */
    SendMessage(g_hTree, TVM_EXPAND, TVE_EXPAND, (LPARAM)root);
    SendMessage(g_hTree, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hTree, NULL, TRUE);
    SetStatusMsg(L"Collapsed all nodes");
}

/* ── Rebuild detail pane font ────────────────────────────── */
static void RebuildDetailFont(void)
{
    if(g_detailFont) DeleteObject(g_detailFont);
    g_detailFont = CreateFontW(
        g_detailFontSize, 0, 0, 0, FW_NORMAL,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FIXED_PITCH, L"Consolas");
    SendMessage(g_hDetail, WM_SETFONT, (WPARAM)g_detailFont, TRUE);
}

/* ── Toggle word wrap in detail pane ────────────────────── */
static void ToggleWordWrap(void)
{
    g_wordWrap = !g_wordWrap;

    /* Save current text */
    int len = GetWindowTextLengthW(g_hDetail) + 1;
    wchar_t *txt = (wchar_t*)malloc(len * sizeof(wchar_t));
    if(txt) GetWindowTextW(g_hDetail, txt, len);

    RECT rc; GetWindowRect(g_hDetail, &rc);
    POINT tl = {rc.left, rc.top}; ScreenToClient(g_hWnd, &tl);
    int w = rc.right - rc.left, h = rc.bottom - rc.top;

    DestroyWindow(g_hDetail);

    DWORD style = WS_CHILD|WS_VISIBLE|WS_VSCROLL|
                  ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL;
    if(!g_wordWrap) style |= WS_HSCROLL|ES_AUTOHSCROLL;

    g_hDetail = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        style, tl.x, tl.y, w, h,
        g_hWnd, (HMENU)ID_DETAIL, NULL, NULL);

    RebuildDetailFont();
    if(txt){ SetWindowTextW(g_hDetail, txt); free(txt); }

    /* Update button text */
    HWND hBtn = GetDlgItem(g_hWnd, ID_WORDWRAP);
    SetWindowTextW(hBtn, g_wordWrap ? L"Wrap \u2713" : L"Wrap");

    SetStatusMsg(g_wordWrap ? L"Word wrap ON" : L"Word wrap OFF");
}

/* ── TreeView helper ─────────────────────────────────────── */
static HTREEITEM AddItem(HWND hTree, HTREEITEM hParent,
                          const wchar_t *text, int img, int color)
{
    TVINSERTSTRUCTW tvi  = {0};
    tvi.hParent          = hParent;
    tvi.hInsertAfter     = TVI_LAST;
    tvi.item.mask        = TVIF_TEXT|TVIF_IMAGE|TVIF_SELECTEDIMAGE|TVIF_PARAM;
    tvi.item.pszText     = (LPWSTR)text;
    tvi.item.iImage      = img;
    tvi.item.iSelectedImage = img;
    tvi.item.lParam      = (LPARAM)color;
    return (HTREEITEM)SendMessage(hTree, TVM_INSERTITEMW, 0, (LPARAM)&tvi);
}
#define ADD(parent,text,img,col) AddItem(g_hTree,parent,text,img,col)

/* ── Run command, capture stdout ────────────────────────── */
static BOOL RunCmd(const wchar_t *cmd, char *buf, DWORD sz)
{
    SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};
    HANDLE hR,hW;
    if(!CreatePipe(&hR,&hW,&sa,0)) return FALSE;
    SetHandleInformation(hR,HANDLE_FLAG_INHERIT,0);
    STARTUPINFOW si={0}; si.cb=sizeof(si);
    si.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
    si.hStdOutput=hW; si.hStdError=hW; si.wShowWindow=SW_HIDE;
    wchar_t tmp[1024]; wcsncpy(tmp,cmd,1023);
    PROCESS_INFORMATION pi={0};
    BOOL ok=CreateProcessW(NULL,tmp,NULL,NULL,TRUE,
                            CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
    CloseHandle(hW);
    if(!ok){CloseHandle(hR);return FALSE;}
    DWORD n,total=0;
    while(ReadFile(hR,buf+total,sz-total-1,&n,NULL)&&n) total+=n;
    buf[total]='\0';
    CloseHandle(hR);
    WaitForSingleObject(pi.hProcess,5000);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return total>0;
}

/* ── Registry helpers ───────────────────────────────────── */
static DWORD RegGetDW(HKEY root, const wchar_t *path, const wchar_t *val)
{
    HKEY hk; DWORD data=0, cb=sizeof(data);
    if(RegOpenKeyExW(root,path,0,KEY_READ,&hk)==ERROR_SUCCESS){
        RegQueryValueExW(hk,val,NULL,NULL,(BYTE*)&data,&cb);
        RegCloseKey(hk);
    }
    return data;
}
static BOOL RegGetStr(HKEY root, const wchar_t *path, const wchar_t *val,
                       wchar_t *out, DWORD outChars)
{
    HKEY hk; DWORD cb=outChars*2, type;
    if(RegOpenKeyExW(root,path,0,KEY_READ,&hk)!=ERROR_SUCCESS) return FALSE;
    BOOL ok=(RegQueryValueExW(hk,val,NULL,&type,(BYTE*)out,&cb)==ERROR_SUCCESS);
    RegCloseKey(hk);
    return ok;
}

/* ═══════════════════════════════════════════════════════════
   SECURE BOOT
   ══════════════════════════════════════════════════════════ */
static void LoadSecureBoot(HTREEITEM hRoot)
{
    HTREEITEM hSB = ADD(hRoot, L"Secure Boot", 0, COL_HEADER);

    DWORD state = RegGetDW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        L"UEFISecureBootEnabled");
    ADD(hSB,
        state ? L"Status: ENABLED  \u2714" : L"Status: DISABLED  \u2718",
        state ? 3 : 2,
        state ? COL_GOOD : COL_BAD);

    DWORD setup = RegGetDW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        L"SetupMode");
    ADD(hSB,
        setup ? L"Setup Mode: YES (no PK enrolled)" : L"Setup Mode: NO",
        2, setup ? COL_WARN : COL_DEFAULT);

    wchar_t policy[64]={0};
    if(RegGetStr(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        L"AuditMode", policy, 63)) {
        wchar_t lbl[128];
        swprintf_s(lbl,127,L"Audit Mode: %s", policy[0]?policy:L"N/A");
        ADD(hSB, lbl, 2, COL_DEFAULT);
    }

    static const wchar_t *guidGlobal   = L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}";
    static const wchar_t *guidImageSec = L"{d719b2cb-3d3a-4596-a3bc-dad00e67656f}";
    struct { const wchar_t *name; const wchar_t *label; const wchar_t *guid; } vars[] = {
        {L"PK",  L"Platform Key (PK)",    guidGlobal},
        {L"KEK", L"Key Exchange Key (KEK)", guidGlobal},
        {L"db",  L"Allowed DB",           guidImageSec},
        {L"dbx", L"Forbidden DBX",        guidImageSec},
        {L"dbr", L"Recovery DB",          guidImageSec},
    };

    {
        HANDLE hTok = NULL;
        if (OpenProcessToken(GetCurrentProcess(),
                             TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok)) {
            TOKEN_PRIVILEGES tp = {0};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            LookupPrivilegeValueW(NULL, L"SeSystemEnvironmentPrivilege",
                                  &tp.Privileges[0].Luid);
            AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), NULL, NULL);
            CloseHandle(hTok);
        }
    }

    HTREEITEM hVars = ADD(hSB, L"UEFI Signing Databases", 0, COL_HEADER);
    BOOL anyVar = FALSE;
    for(int v=0;v<(int)(sizeof(vars)/sizeof(vars[0]));v++){
        DWORD bufSize = 65536;
        BYTE *buf = NULL;
        DWORD got = 0;
        for(;;) {
            buf = (BYTE*)realloc(buf, bufSize);
            if(!buf) break;
            got = GetFirmwareEnvironmentVariableW(
                      vars[v].name, vars[v].guid, buf, bufSize);
            if(got != 0) break;
            if(GetLastError() != ERROR_INSUFFICIENT_BUFFER) break;
            bufSize *= 2;
            if(bufSize > 4*1024*1024) break;
        }
        if(!buf || got==0){
            DWORD err=GetLastError();
            wchar_t lbl[128];
            if(err==ERROR_ENVVAR_NOT_FOUND || err==ERROR_INSUFFICIENT_BUFFER
               || err==ERROR_FILE_NOT_FOUND)
                swprintf_s(lbl,127,L"%s: (not present on this firmware)",
                           vars[v].label);
            else
                swprintf_s(lbl,127,L"%s: (not accessible \u2014 err %08X)",
                           vars[v].label, err);
            ADD(hVars, lbl, 2, COL_DEFAULT);
            free(buf); buf=NULL;
            continue;
        }
        anyVar=TRUE;
        wchar_t lbl[128];
        swprintf_s(lbl,127,L"%s: %u bytes raw", vars[v].label, got);
        HTREEITEM hV = ADD(hVars, lbl, 1, COL_HARDWARE);

        BYTE *p = buf;
        DWORD rem = got;
        int sigCount = 0;
        while(rem >= 28){
            DWORD listSize = *(DWORD*)(p+16);
            DWORD hdrSize  = *(DWORD*)(p+20);
            DWORD sigSize  = *(DWORD*)(p+24);
            if(listSize==0||listSize>rem) break;

            GUID *typeGuid = (GUID*)p;
            wchar_t typeStr[64]={0};
            static const BYTE x509Guid[16] = {
                0xa1,0x59,0xc0,0xa5,0xe4,0x94,0xa7,0x4a,
                0x87,0xb5,0xab,0x15,0x5c,0x2b,0xf0,0x72};
            static const BYTE sha256Guid[16] = {
                0x26,0x16,0xc4,0xc1,0x4c,0x50,0x92,0x40,
                0xac,0xa9,0x41,0xf9,0x36,0x93,0x43,0x28};
            if(memcmp(typeGuid,x509Guid,16)==0)
                wcscpy_s(typeStr,63,L"X.509 Cert");
            else if(memcmp(typeGuid,sha256Guid,16)==0)
                wcscpy_s(typeStr,63,L"SHA-256 Hash");
            else
                swprintf_s(typeStr,63,L"Type %08X",typeGuid->Data1);

            BYTE *sigData = p + 28 + hdrSize;
            DWORD sigAreaSize = listSize - 28 - hdrSize;
            DWORD effectiveSigSize = (sigSize>16) ? sigSize-16 : sigSize;

            if(effectiveSigSize>0 && sigAreaSize>=effectiveSigSize){
                DWORD numSigs = sigAreaSize / sigSize;
                for(DWORD i=0;i<numSigs && sigAreaSize>=(i+1)*sigSize;i++){
                    BYTE *entry = sigData + i*sigSize + 16;
                    DWORD entryLen = sigSize-16;
                    if(wcscmp(typeStr,L"X.509 Cert")==0){
                        PCCERT_CONTEXT pCert=CertCreateCertificateContext(
                            X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,
                            entry, entryLen);
                        if(pCert){
                            wchar_t subj[256]=L"(unknown)";
                            CertGetNameStringW(pCert,
                                CERT_NAME_SIMPLE_DISPLAY_TYPE,0,NULL,subj,255);
                            wchar_t iss[256]=L"";
                            CertGetNameStringW(pCert,
                                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                CERT_NAME_ISSUER_FLAG,NULL,iss,255);
                            wchar_t cl[512];
                            swprintf_s(cl,511,L"[X.509] %s",subj);
                            HTREEITEM hSig=ADD(hV,cl,1,COL_HARDWARE);
                            swprintf_s(cl,511,L"Issuer: %s",iss);
                            ADD(hSig,cl,2,COL_DEFAULT);
                            SYSTEMTIME nb,na;
                            FileTimeToSystemTime(&pCert->pCertInfo->NotBefore,&nb);
                            FileTimeToSystemTime(&pCert->pCertInfo->NotAfter,&na);
                            swprintf_s(cl,511,
                                L"Valid: %04d-%02d-%02d \u2192 %04d-%02d-%02d",
                                nb.wYear,nb.wMonth,nb.wDay,
                                na.wYear,na.wMonth,na.wDay);
                            ADD(hSig,cl,2,COL_DEFAULT);
                            CertFreeCertificateContext(pCert);
                            sigCount++;
                        }
                    } else if(wcscmp(typeStr,L"SHA-256 Hash")==0
                               && entryLen>=32){
                        wchar_t hex[72]={0};
                        for(int b=0;b<32;b++)
                            swprintf_s(hex+b*2,3,L"%02X",entry[b]);
                        wchar_t cl[128];
                        swprintf_s(cl,127,L"[SHA-256] %s",hex);
                        ADD(hV,cl,2,COL_DEFAULT);
                        sigCount++;
                    }
                }
            }
            p   += listSize;
            rem -= listSize;
        }
        if(sigCount==0)
            ADD(hV, L"(could not parse entries \u2014 may need admin)", 2, COL_WARN);
        SendMessage(g_hTree,TVM_EXPAND,TVE_EXPAND,(LPARAM)hV);
        free(buf); buf=NULL;
    }
    if(!anyVar)
        ADD(hVars,
            L"(Run as Administrator to read UEFI variables)", 2, COL_WARN);

    SendMessage(g_hTree,TVM_EXPAND,TVE_EXPAND,(LPARAM)hVars);
    SendMessage(g_hTree,TVM_EXPAND,TVE_EXPAND,(LPARAM)hSB);
}

/* ═══════════════════════════════════════════════════════════
   TPM via WMI  (Win32_Tpm)
   ══════════════════════════════════════════════════════════ */
static void WmiGetStr(IWbemClassObject *obj, const wchar_t *prop,
                       wchar_t *out, int outLen)
{
    VARIANT v; VariantInit(&v);
    if(SUCCEEDED(obj->lpVtbl->Get(obj,(BSTR)prop,0,&v,NULL,NULL))){
        if(v.vt==VT_BSTR && v.bstrVal)
            wcsncpy(out, v.bstrVal, outLen-1);
        VariantClear(&v);
    }
}
static BOOL WmiGetBool(IWbemClassObject *obj, const wchar_t *prop)
{
    VARIANT v; VariantInit(&v); BOOL ret=FALSE;
    CIMTYPE ct = 0;
    if(SUCCEEDED(obj->lpVtbl->Get(obj,(BSTR)prop,0,&v,&ct,NULL))){
        if(v.vt==VT_BOOL)        ret=(v.boolVal!=VARIANT_FALSE);
        else if(v.vt==VT_I4||
                v.vt==VT_UI4)   ret=(v.lVal!=0);
        else if(v.vt==VT_I2||
                v.vt==VT_UI2)   ret=(v.iVal!=0);
        else if(v.vt==VT_NULL)  ret=FALSE;
        else if(ct==11)          ret=(v.lVal!=0);
        VariantClear(&v);
    }
    return ret;
}

/* ═══════════════════════════════════════════════════════════
   EK CERTIFICATE  (probe multiple NV indices)
   ══════════════════════════════════════════════════════════ */
static int NvReadPublicSize(void *hCtx,
                             UINT32 (WINAPI *fnSubmit)(void*,UINT32,UINT32,
                                                        const BYTE*,UINT32,
                                                        BYTE*,UINT32*),
                             DWORD nvIndex,
                             BYTE *rspBuf, UINT32 rspBufSz)
{
    BYTE cmd[14];
    cmd[0]=0x80; cmd[1]=0x01;
    cmd[2]=0x00; cmd[3]=0x00; cmd[4]=0x00; cmd[5]=0x0E;
    cmd[6]=0x00; cmd[7]=0x00; cmd[8]=0x01; cmd[9]=0x69;
    cmd[10]=(BYTE)(nvIndex>>24); cmd[11]=(BYTE)(nvIndex>>16);
    cmd[12]=(BYTE)(nvIndex>>8);  cmd[13]=(BYTE)(nvIndex);

    UINT32 rspSize = rspBufSz;
    UINT32 rc = fnSubmit(hCtx, 0, 0, cmd, 14, rspBuf, &rspSize);
    if(rc != 0 || rspSize < 10) return -1;

    UINT32 respCode = ((UINT32)rspBuf[6]<<24)|((UINT32)rspBuf[7]<<16)|
                     ((UINT32)rspBuf[8]<<8)|rspBuf[9];

    if(respCode == 0x0000008B || respCode == 0x0000014B) return 0;
    if(respCode != 0) return -1;

    if(rspSize < 10 + 2 + 12) return -1;
    DWORD off = 10;
    WORD nvPublicSize = ((WORD)rspBuf[off]<<8)|rspBuf[off+1]; off += 2;
    if(off + nvPublicSize > rspSize || nvPublicSize < 12) return -1;
    BYTE *nvp = rspBuf + off;
    WORD authPolicySize = ((WORD)nvp[10]<<8)|nvp[11];
    DWORD dataSizeOff = 12 + authPolicySize;
    if(dataSizeOff + 2 > nvPublicSize) return -1;
    WORD dataSize = ((WORD)nvp[dataSizeOff]<<8)|nvp[dataSizeOff+1];
    return (int)dataSize;
}

static BYTE *NvReadAll(void *hCtx,
                        UINT32 (WINAPI *fnSubmit)(void*,UINT32,UINT32,
                                                   const BYTE*,UINT32,
                                                   BYTE*,UINT32*),
                        DWORD nvIndex, WORD nvDataSize,
                        DWORD *certTotal,
                        wchar_t *errOut, int errLen)
{
    BYTE *buf = (BYTE*)malloc(nvDataSize);
    if(!buf){ swprintf_s(errOut,errLen,L"(out of memory)"); return NULL; }
    *certTotal = 0;

    while(*certTotal < nvDataSize){
        WORD chunkSize = (WORD)(nvDataSize - *certTotal);
        if(chunkSize > 1024) chunkSize = 1024;
        WORD offset = (WORD)*certTotal;

        BYTE cmd[35];
        cmd[0]=0x80; cmd[1]=0x02;
        cmd[2]=0x00; cmd[3]=0x00; cmd[4]=0x00; cmd[5]=0x23;
        cmd[6]=0x00; cmd[7]=0x00; cmd[8]=0x01; cmd[9]=0x4E;
        cmd[10]=(BYTE)(nvIndex>>24); cmd[11]=(BYTE)(nvIndex>>16);
        cmd[12]=(BYTE)(nvIndex>>8);  cmd[13]=(BYTE)(nvIndex);
        cmd[14]=(BYTE)(nvIndex>>24); cmd[15]=(BYTE)(nvIndex>>16);
        cmd[16]=(BYTE)(nvIndex>>8);  cmd[17]=(BYTE)(nvIndex);
        cmd[18]=0x00; cmd[19]=0x00; cmd[20]=0x00; cmd[21]=0x09;
        cmd[22]=0x40; cmd[23]=0x00; cmd[24]=0x00; cmd[25]=0x09;
        cmd[26]=0x00; cmd[27]=0x00; cmd[28]=0x00; cmd[29]=0x00; cmd[30]=0x00;
        cmd[31]=(BYTE)(chunkSize>>8); cmd[32]=(BYTE)(chunkSize);
        cmd[33]=(BYTE)(offset>>8);    cmd[34]=(BYTE)(offset);

        BYTE   rsp[4096]={0};
        UINT32 rspSize=sizeof(rsp);
        UINT32 rc = fnSubmit(hCtx, 0, 0, cmd, 35, rsp, &rspSize);
        if(rc != 0 || rspSize < 10){ free(buf); swprintf_s(errOut,errLen,L"(TBS submit failed)"); return NULL; }

        UINT32 respCode = ((UINT32)rsp[6]<<24)|((UINT32)rsp[7]<<16)|
                         ((UINT32)rsp[8]<<8)|rsp[9];
        if(respCode != 0){
            free(buf);
            swprintf_s(errOut,errLen,
                L"(NV_Read @offset %u failed: TPM rc=0x%08X \u2014 run as Administrator)",
                offset, respCode);
            return NULL;
        }

        if(rspSize < 10+4+2){ free(buf); swprintf_s(errOut,errLen,L"(response too short)"); return NULL; }
        DWORD roff = 10+4;
        WORD got = ((WORD)rsp[roff]<<8)|rsp[roff+1]; roff+=2;
        if(got==0 || roff+got > rspSize){ free(buf); swprintf_s(errOut,errLen,L"(bad data size in response)"); return NULL; }
        if(*certTotal+got > nvDataSize){ free(buf); swprintf_s(errOut,errLen,L"(overflow)"); return NULL; }
        memcpy(buf+*certTotal, rsp+roff, got);
        *certTotal += got;
        if(got < chunkSize) break;
    }
    return buf;
}

static void DisplayCertDer(HTREEITEM hParent, const BYTE *der, DWORD derLen)
{
    PCCERT_CONTEXT pCert = CertCreateCertificateContext(
        X509_ASN_ENCODING|PKCS_7_ASN_ENCODING, der, derLen);

    if(!pCert && derLen > 2){
        WORD skip = ((WORD)der[0]<<8)|der[1];
        if(skip > 0 && (DWORD)skip+2 <= derLen)
            pCert = CertCreateCertificateContext(
                X509_ASN_ENCODING|PKCS_7_ASN_ENCODING, der+2, derLen-2);
    }

    if(!pCert){
        ADD(hParent, L"(could not parse as X.509 DER)", 2, COL_WARN);
        wchar_t hexBuf[128]={0};
        DWORD show = derLen < 24 ? derLen : 24;
        for(DWORD b=0;b<show;b++) swprintf_s(hexBuf+b*3,4,L"%02X ",der[b]);
        wchar_t hexLbl[160]; swprintf_s(hexLbl,159,L"Raw prefix: %s",hexBuf);
        ADD(hParent, hexLbl, 2, COL_DEFAULT);
        return;
    }

    wchar_t lbl[512];

    wchar_t subj[256]=L"(unknown)";
    CertGetNameStringW(pCert,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,NULL,subj,255);
    swprintf_s(lbl,511,L"Subject: %s",subj);
    ADD(hParent,lbl,1,COL_HARDWARE);

    wchar_t iss[256]=L"(unknown)";
    CertGetNameStringW(pCert,CERT_NAME_SIMPLE_DISPLAY_TYPE,CERT_NAME_ISSUER_FLAG,NULL,iss,255);
    swprintf_s(lbl,511,L"Issuer: %s",iss);
    ADD(hParent,lbl,2,COL_DEFAULT);

    wchar_t dn[512]=L"";
    CertGetNameStringW(pCert,CERT_NAME_RDN_TYPE,0,NULL,dn,511);
    if(dn[0]){ swprintf_s(lbl,511,L"Subject DN: %s",dn); ADD(hParent,lbl,2,COL_DEFAULT); }

    {
        DWORD snLen = pCert->pCertInfo->SerialNumber.cbData;
        if(snLen>0 && snLen<=32){
            wchar_t snHex[72]={0};
            for(DWORD b=0;b<snLen;b++)
                swprintf_s(snHex+b*2,3,L"%02X",
                    pCert->pCertInfo->SerialNumber.pbData[snLen-1-b]);
            swprintf_s(lbl,511,L"Serial: %s",snHex);
            ADD(hParent,lbl,2,COL_DEFAULT);
        }
    }

    {
        SYSTEMTIME nb,na;
        FileTimeToSystemTime(&pCert->pCertInfo->NotBefore,&nb);
        FileTimeToSystemTime(&pCert->pCertInfo->NotAfter,&na);
        swprintf_s(lbl,511,L"Valid: %04d-%02d-%02d \u2192 %04d-%02d-%02d",
            nb.wYear,nb.wMonth,nb.wDay,na.wYear,na.wMonth,na.wDay);
        ADD(hParent,lbl,2,COL_DEFAULT);
    }

    {
        BYTE th[20]; DWORD tsz=20;
        if(CryptHashCertificate(0,CALG_SHA1,0,
                                pCert->pbCertEncoded,pCert->cbCertEncoded,th,&tsz)){
            wchar_t hex[48]={0};
            for(DWORD i=0;i<tsz;i++) swprintf_s(hex+i*2,3,L"%02X",th[i]);
            swprintf_s(lbl,511,L"SHA-1 thumbprint: %s",hex);
            ADD(hParent,lbl,2,COL_DEFAULT);
        }
    }

    {
        wchar_t pkAlg[128]=L"";
        if(pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId)
            MultiByteToWideChar(CP_ACP,0,
                pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
                -1,pkAlg,127);

        DWORD keyBits=0;
        DWORD cbPub=0;
        if(CryptDecodeObject(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
            pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
            pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData,
            0,NULL,&cbPub) && cbPub>=16){
            BYTE *blob=(BYTE*)malloc(cbPub);
            if(blob){
                if(CryptDecodeObject(X509_ASN_ENCODING,RSA_CSP_PUBLICKEYBLOB,
                    pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
                    pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData,
                    0,blob,&cbPub))
                    keyBits=*(DWORD*)(blob+12);
                free(blob);
            }
        }
        if(keyBits)
            swprintf_s(lbl,511,L"Public key: %s  (%u bits)",pkAlg[0]?pkAlg:L"?",keyBits);
        else
            swprintf_s(lbl,511,L"Public key algorithm: %s",pkAlg[0]?pkAlg:L"?");
        ADD(hParent,lbl,1,COL_HARDWARE);
    }

    {
        BYTE ku=0;
        if(CertGetIntendedKeyUsage(X509_ASN_ENCODING,pCert->pCertInfo,&ku,1)){
            wchar_t kuStr[256]=L"Key usage:";
            if(ku&CERT_KEY_ENCIPHERMENT_KEY_USAGE)  wcscat(kuStr,L" KeyEncipherment");
            if(ku&CERT_DIGITAL_SIGNATURE_KEY_USAGE) wcscat(kuStr,L" DigitalSignature");
            if(ku&CERT_KEY_CERT_SIGN_KEY_USAGE)     wcscat(kuStr,L" CertSign");
            ADD(hParent,kuStr,2,COL_DEFAULT);
        }
    }

    if(CertFindExtension("2.23.133.8.1",
                          pCert->pCertInfo->cExtension,
                          pCert->pCertInfo->rgExtension))
        ADD(hParent,L"TCG EK Certificate  \u2714  (OID 2.23.133.8.1 present)",3,COL_GOOD);

    CertFreeCertificateContext(pCert);
}

static void LoadEKCert(HTREEITEM hTPM,
                        void *hCtx,
                        UINT32 (WINAPI *fnSubmit)(void*,UINT32,UINT32,
                                                   const BYTE*,UINT32,
                                                   BYTE*,UINT32*))
{
    HTREEITEM hEKRoot = ADD(hTPM, L"EK Certificates  (Endorsement Key)", 0, COL_HEADER);

    static const struct {
        DWORD         index;
        const wchar_t *label;
    } indices[] = {
        { 0x01C00002, L"RSA-2048 EK cert  (NV 0x01C00002 \u2014 TCG standard)" },
        { 0x01C00012, L"ECC P-256 EK cert  (NV 0x01C00012 \u2014 TCG standard)" },
        { 0x01C00014, L"ECC P-384 EK cert  (NV 0x01C00014 \u2014 TCG standard)" },
        { 0x01C0000A, L"EK cert  (NV 0x01C0000A \u2014 vendor alternate)"       },
        { 0x01C00016, L"ECC P-521 EK cert  (NV 0x01C00016 \u2014 TCG standard)" },
    };

    BOOL anyFound = FALSE;
    BYTE rspBuf[1024];

    for(int i=0; i < (int)(sizeof(indices)/sizeof(indices[0])); i++){
        memset(rspBuf,0,sizeof(rspBuf));
        int dataSize = NvReadPublicSize(hCtx, fnSubmit,
                                         indices[i].index,
                                         rspBuf, sizeof(rspBuf));
        if(dataSize == 0) continue;
        if(dataSize < 0){
            wchar_t errLbl[256];
            swprintf_s(errLbl,255,L"%s  \u26A0 (ReadPublic error)",indices[i].label);
            ADD(hEKRoot,errLbl,2,COL_WARN);
            anyFound=TRUE;
            continue;
        }

        HTREEITEM hEK = ADD(hEKRoot, indices[i].label, 1, COL_HARDWARE);
        anyFound = TRUE;

        wchar_t szLbl[128];
        swprintf_s(szLbl,127,L"NV size: %d bytes", dataSize);
        ADD(hEK, szLbl, 2, COL_DEFAULT);

        wchar_t errMsg[256]={0};
        DWORD certTotal=0;
        BYTE *certDer = NvReadAll(hCtx, fnSubmit,
                                   indices[i].index, (WORD)dataSize,
                                   &certTotal, errMsg, 255);
        if(!certDer){
            ADD(hEK, errMsg[0]?errMsg:L"(NV_Read failed)", 2, COL_WARN);
        } else {
            wchar_t rdLbl[128];
            swprintf_s(rdLbl,127,L"Read %u bytes", certTotal);
            ADD(hEK, rdLbl, 2, COL_DEFAULT);
            DisplayCertDer(hEK, certDer, certTotal);
            free(certDer);
        }

        SendMessage(g_hTree, TVM_EXPAND, TVE_EXPAND, (LPARAM)hEK);
    }

    if(!anyFound)
        ADD(hEKRoot,
            L"No EK certs found in NV  (AMD fTPM often doesn't provision them)",
            2, COL_WARN);

    {
        HTREEITEM hDerived = ADD(hEKRoot,
            L"Derived EK Public Key  (TPM2_CC_CreatePrimary, RSA-2048)",
            0, COL_HEADER);

        static const BYTE ekPolicy[32] = {
            0x83,0x71,0x97,0x67,0x44,0x84,0xb3,0xf8,
            0x1a,0x90,0xcc,0x8d,0x46,0xa5,0xd7,0x24,
            0xfd,0x52,0xd7,0x6e,0x06,0x52,0x0b,0x64,
            0xf2,0xa1,0xda,0x1b,0x33,0x14,0x69,0xaa
        };

        BYTE tpmtPublic[320]; DWORD pp = 0;
        tpmtPublic[pp++]=0x00; tpmtPublic[pp++]=0x01;
        tpmtPublic[pp++]=0x00; tpmtPublic[pp++]=0x0B;
        tpmtPublic[pp++]=0x00; tpmtPublic[pp++]=0x03;
        tpmtPublic[pp++]=0x00; tpmtPublic[pp++]=0x72;
        tpmtPublic[pp++]=0x00; tpmtPublic[pp++]=0x20;
        memcpy(tpmtPublic+pp,ekPolicy,32); pp+=32;
        tpmtPublic[pp++]=0x00; tpmtPublic[pp++]=0x06;
        tpmtPublic[pp++]=0x00; tpmtPublic[pp++]=0x80;
        tpmtPublic[pp++]=0x00; tpmtPublic[pp++]=0x43;
        tpmtPublic[pp++]=0x00; tpmtPublic[pp++]=0x10;
        tpmtPublic[pp++]=0x08; tpmtPublic[pp++]=0x00;
        tpmtPublic[pp++]=0x00; tpmtPublic[pp++]=0x00;
        tpmtPublic[pp++]=0x00; tpmtPublic[pp++]=0x00;
        tpmtPublic[pp++]=0x01; tpmtPublic[pp++]=0x00;
        memset(tpmtPublic+pp,0,256); pp+=256;
        DWORD tpmtLen = pp;

        DWORD cmdLen = 41 + tpmtLen;
        BYTE *cmd = (BYTE*)calloc(cmdLen,1);
        if(!cmd){ ADD(hDerived,L"(out of memory)",2,COL_WARN); goto doneEK; }

        DWORD cp = 0;
        cmd[cp++]=0x80; cmd[cp++]=0x02;
        cmd[cp++]=(BYTE)(cmdLen>>24); cmd[cp++]=(BYTE)(cmdLen>>16);
        cmd[cp++]=(BYTE)(cmdLen>>8);  cmd[cp++]=(BYTE)(cmdLen);
        cmd[cp++]=0x00; cmd[cp++]=0x00; cmd[cp++]=0x01; cmd[cp++]=0x31;
        cmd[cp++]=0x40; cmd[cp++]=0x00; cmd[cp++]=0x00; cmd[cp++]=0x0B;
        cmd[cp++]=0x00; cmd[cp++]=0x00; cmd[cp++]=0x00; cmd[cp++]=0x09;
        cmd[cp++]=0x40; cmd[cp++]=0x00; cmd[cp++]=0x00; cmd[cp++]=0x09;
        cmd[cp++]=0x00; cmd[cp++]=0x00;
        cmd[cp++]=0x00;
        cmd[cp++]=0x00; cmd[cp++]=0x00;
        cmd[cp++]=0x00; cmd[cp++]=0x04;
        cmd[cp++]=0x00; cmd[cp++]=0x00;
        cmd[cp++]=0x00; cmd[cp++]=0x00;
        cmd[cp++]=(BYTE)(tpmtLen>>8); cmd[cp++]=(BYTE)(tpmtLen);
        memcpy(cmd+cp,tpmtPublic,tpmtLen); cp+=tpmtLen;
        cmd[cp++]=0x00; cmd[cp++]=0x00;
        cmd[cp++]=0x00; cmd[cp++]=0x00; cmd[cp++]=0x00; cmd[cp++]=0x00;

        BYTE *rsp = (BYTE*)calloc(8192,1);
        if(!rsp){ free(cmd); ADD(hDerived,L"(out of memory)",2,COL_WARN); goto doneEK; }

        UINT32 rspSize = 8192;
        UINT32 rc = fnSubmit(hCtx,0,0,cmd,cmdLen,rsp,&rspSize);
        free(cmd);

        if(rc!=0||rspSize<10){ free(rsp); ADD(hDerived,L"(TBS submit failed)",2,COL_WARN); goto doneEK; }

        UINT32 respCode = ((UINT32)rsp[6]<<24)|((UINT32)rsp[7]<<16)|
                         ((UINT32)rsp[8]<<8)|rsp[9];
        if(respCode!=0){
            wchar_t lbl[128];
            swprintf_s(lbl,127,L"(CreatePrimary TPM rc=0x%08X \u2014 run as Administrator)",respCode);
            ADD(hDerived,lbl,2,COL_WARN);
            free(rsp); goto doneEK;
        }

        if(rspSize < 20){ free(rsp); ADD(hDerived,L"(response too short)",2,COL_WARN); goto doneEK; }
        DWORD roff = 18;
        WORD outPublicSize = ((WORD)rsp[roff]<<8)|rsp[roff+1]; roff+=2;
        if(outPublicSize==0||roff+outPublicSize>rspSize){
            free(rsp); ADD(hDerived,L"(outPublic size invalid)",2,COL_WARN); goto doneEK;
        }

        BYTE *pub = rsp+roff;

        WORD pubType    = ((WORD)pub[0]<<8)|pub[1];
        WORD pubNameAlg = ((WORD)pub[2]<<8)|pub[3];
        DWORD pubAttr   = ((DWORD)pub[4]<<24)|((DWORD)pub[5]<<16)|
                          ((DWORD)pub[6]<<8)|pub[7];

        wchar_t lbl[512];
        swprintf_s(lbl,511,L"Key type: %s",
            pubType==0x0001?L"RSA":pubType==0x0023?L"ECC":L"unknown");
        ADD(hDerived,lbl,1,COL_HARDWARE);
        swprintf_s(lbl,511,L"Name algorithm: %s",
            pubNameAlg==0x000B?L"SHA-256":pubNameAlg==0x0004?L"SHA-1":L"?");
        ADD(hDerived,lbl,2,COL_DEFAULT);

        {
            wchar_t a[256]=L"Attributes:";
            if(pubAttr&0x00000002) wcscat(a,L" fixedTPM");
            if(pubAttr&0x00000010) wcscat(a,L" fixedParent");
            if(pubAttr&0x00000020) wcscat(a,L" sensDataOrigin");
            if(pubAttr&0x00000040) wcscat(a,L" userWithAuth");
            if(pubAttr&0x00000080) wcscat(a,L" adminWithPolicy");
            if(pubAttr&0x00020000) wcscat(a,L" restricted");
            if(pubAttr&0x00040000) wcscat(a,L" decrypt");
            if(pubAttr&0x00080000) wcscat(a,L" sign");
            ADD(hDerived,a,2,COL_DEFAULT);
        }

        DWORD pp2 = 8;
        if(pp2+2 > outPublicSize){ free(rsp); goto doneEK; }
        WORD apSize = ((WORD)pub[pp2]<<8)|pub[pp2+1]; pp2+=2+apSize;

        if(pubType==0x0001){
            if(pp2+14 > outPublicSize){ free(rsp); goto doneEK; }
            WORD keyBits   = ((WORD)pub[pp2+8]<<8)|pub[pp2+9];
            DWORD exponent = ((DWORD)pub[pp2+10]<<24)|((DWORD)pub[pp2+11]<<16)|
                             ((DWORD)pub[pp2+12]<<8)|pub[pp2+13];
            swprintf_s(lbl,511,L"RSA key size: %u bits",keyBits);
            ADD(hDerived,lbl,1,COL_HARDWARE);
            swprintf_s(lbl,511,L"Public exponent: %u",exponent==0?65537:exponent);
            ADD(hDerived,lbl,2,COL_DEFAULT);
            pp2+=14;

            if(pp2+2 > outPublicSize){ free(rsp); goto doneEK; }
            WORD modSize = ((WORD)pub[pp2]<<8)|pub[pp2+1]; pp2+=2;
            if(pp2+modSize > outPublicSize){ free(rsp); goto doneEK; }

            BYTE *mod = pub+pp2;
            swprintf_s(lbl,511,L"Modulus (%u bytes):",modSize);
            HTREEITEM hMod = ADD(hDerived,lbl,1,COL_HARDWARE);

            for(WORD row=0; row<modSize; row+=32){
                WORD rowLen = (modSize-row<32)?(WORD)(modSize-row):32;
                wchar_t hexRow[100]={0};
                for(WORD b=0;b<rowLen;b++) swprintf_s(hexRow+b*2,3,L"%02X",mod[row+b]);
                wchar_t rowLbl[120]; swprintf_s(rowLbl,119,L"%03X: %s",row,hexRow);
                ADD(hMod,rowLbl,2,COL_DEFAULT);
            }
            SendMessage(g_hTree,TVM_EXPAND,TVE_EXPAND,(LPARAM)hMod);

            {
                HCRYPTPROV hProv3=0; HCRYPTHASH hHash=0;
                if(CryptAcquireContextW(&hProv3,NULL,NULL,PROV_RSA_AES,CRYPT_VERIFYCONTEXT)){
                    if(CryptCreateHash(hProv3,CALG_SHA_256,0,0,&hHash)){
                        CryptHashData(hHash,mod,modSize,0);
                        BYTE digest[32]; DWORD dLen=32;
                        if(CryptGetHashParam(hHash,HP_HASHVAL,digest,&dLen,0)){
                            wchar_t hex[68]={0};
                            for(int b=0;b<32;b++) swprintf_s(hex+b*2,3,L"%02X",digest[b]);
                            swprintf_s(lbl,511,L"Modulus SHA-256: %s",hex);
                            ADD(hDerived,lbl,1,COL_HARDWARE);
                            ADD(hDerived,
                                L"\u2191 This fingerprint uniquely identifies your TPM chip  \u2714",
                                2,COL_GOOD);
                        }
                        CryptDestroyHash(hHash);
                    }
                    CryptReleaseContext(hProv3,0);
                }
            }
        }

        free(rsp);
        SendMessage(g_hTree,TVM_EXPAND,TVE_EXPAND,(LPARAM)hDerived);
        doneEK:;
    }

    SendMessage(g_hTree, TVM_EXPAND, TVE_EXPAND, (LPARAM)hEKRoot);
}

static void LoadTPM(HTREEITEM hRoot)
{
    HTREEITEM hTPM = ADD(hRoot, L"TPM  (Trusted Platform Module)", 0, COL_HEADER);

    BOOL tbsPresent = FALSE;
    IWbemLocator   *pLoc  = NULL;
    IWbemServices  *pSvc  = NULL;
    IEnumWbemClassObject *pEnum = NULL;
    BOOL wmiOk = FALSE;

    if(FAILED(CoCreateInstance(&CLSID_WbemLocator,0,CLSCTX_INPROC_SERVER,
                                &IID_IWbemLocator,(void**)&pLoc)))
        goto noWMI;

    {
        BSTR ns = SysAllocString(L"\\\\.\\root\\cimv2\\Security\\MicrosoftTpm");
        HRESULT hr = pLoc->lpVtbl->ConnectServer(pLoc, ns, NULL,NULL,0,0,0,0,&pSvc);
        SysFreeString(ns);
        if(FAILED(hr)) goto noWMI;
    }

    CoSetProxyBlanket((IUnknown*)pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                       NULL, RPC_C_AUTHN_LEVEL_CALL,
                       RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    {
        BSTR lang  = SysAllocString(L"WQL");
        BSTR query = SysAllocString(L"SELECT * FROM Win32_Tpm");
        HRESULT hr = pSvc->lpVtbl->ExecQuery(pSvc, lang, query,
            WBEM_FLAG_FORWARD_ONLY|WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL, &pEnum);
        SysFreeString(lang); SysFreeString(query);
        if(FAILED(hr)) goto noWMI;
    }

    {
        IWbemClassObject *obj = NULL; ULONG ret = 0;
        while(pEnum->lpVtbl->Next(pEnum,WBEM_INFINITE,1,&obj,&ret)==S_OK){
            wmiOk = TRUE;

            BOOL present   = WmiGetBool(obj, L"IsPresent");
            BOOL enabled   = WmiGetBool(obj, L"IsEnabled_InitialValue");
            BOOL activated = WmiGetBool(obj, L"IsActivated_InitialValue");
            BOOL owned     = WmiGetBool(obj, L"IsOwned_InitialValue");

            BOOL actuallyPresent = present || enabled || activated || owned || tbsPresent;
            ADD(hTPM,
                tbsPresent && !present
                    ? L"Present: YES  \u2714  (WMI IsPresent bug \u2014 confirmed via TBS)"
                    : actuallyPresent
                    ? L"Present: YES  \u2714"
                    : L"Present: NO  \u2718",
                actuallyPresent?3:2, actuallyPresent?COL_GOOD:COL_BAD);
            ADD(hTPM,
                enabled ? L"Enabled: YES  \u2714" : L"Enabled: NO  \u2718",
                enabled?3:2, enabled?COL_GOOD:COL_BAD);
            ADD(hTPM,
                activated ? L"Activated: YES  \u2714" : L"Activated: NO  \u2718",
                activated?3:2, activated?COL_GOOD:COL_BAD);
            ADD(hTPM,
                owned ? L"Owned: YES" : L"Owned: NO  (no EK)",
                2, owned?COL_DEFAULT:COL_WARN);

            wchar_t specVer[128]={0};
            WmiGetStr(obj, L"SpecVersion", specVer, 127);
            if(specVer[0]){
                wchar_t lbl[200];
                swprintf_s(lbl,199,L"Spec version: %s",specVer);
                ADD(hTPM,lbl,2,COL_DEFAULT);
            }

            wchar_t mfr[128]={0}, mfrVer[128]={0}, mfrId[128]={0};
            WmiGetStr(obj,L"ManufacturerVersion",mfrVer,127);
            WmiGetStr(obj,L"ManufacturerVersionInfo",mfr,127);
            WmiGetStr(obj,L"ManufacturerId",mfrId,127);

            VARIANT vid; VariantInit(&vid);
            if(SUCCEEDED(obj->lpVtbl->Get(obj,(BSTR)L"ManufacturerId",
                                            0,&vid,NULL,NULL))){
                if(vid.vt==VT_I4||vid.vt==VT_UI4){
                    DWORD id=(DWORD)vid.lVal;
                    wchar_t mfrChars[8]={0}; DWORD mci=0;
                    BYTE mb[4]={(BYTE)((id>>24)&0xFF),(BYTE)((id>>16)&0xFF),
                                (BYTE)((id>>8)&0xFF),(BYTE)(id&0xFF)};
                    for(int b=0;b<4;b++)
                        if(mb[b]>=0x20&&mb[b]<0x7F) mfrChars[mci++]=mb[b];
                    wchar_t idStr[64];
                    swprintf_s(idStr,63,L"Manufacturer ID: 0x%08X  (%s)",id,mfrChars);
                    ADD(hTPM,idStr,2,COL_DEFAULT);
                }
                VariantClear(&vid);
            }
            if(mfrVer[0]){
                wchar_t lbl[200];
                swprintf_s(lbl,199,L"Firmware version: %s",mfrVer);
                ADD(hTPM,lbl,2,COL_DEFAULT);
            }
            if(mfr[0]){
                wchar_t lbl[200];
                swprintf_s(lbl,199,L"Manufacturer info: %s",mfr);
                ADD(hTPM,lbl,2,COL_DEFAULT);
            }

            wchar_t ppVer[128]={0};
            WmiGetStr(obj,L"PhysicalPresenceVersionInfo",ppVer,127);
            if(ppVer[0]){
                wchar_t lbl[200];
                swprintf_s(lbl,199,L"Physical Presence version: %s",ppVer);
                ADD(hTPM,lbl,2,COL_DEFAULT);
            }

            obj->lpVtbl->Release(obj);
        }
    }

    {
        HTREEITEM hPCR = ADD(hTPM,
            L"PCR Values  (Platform Configuration Registers)", 0, COL_HEADER);

        static const wchar_t *pcrDesc[24] = {
            L"PCR 0  \u2014 UEFI firmware / BIOS code",
            L"PCR 1  \u2014 UEFI firmware config & data",
            L"PCR 2  \u2014 Option ROM code",
            L"PCR 3  \u2014 Option ROM config & data",
            L"PCR 4  \u2014 Boot manager & MBR/GPT",
            L"PCR 5  \u2014 Boot manager config (GPT table)",
            L"PCR 6  \u2014 Resume from S4/S5",
            L"PCR 7  \u2014 Secure Boot state & policy",
            L"PCR 8  \u2014 NTFS boot sector",
            L"PCR 9  \u2014 NTFS boot block",
            L"PCR 10 \u2014 Boot manager (BitLocker)",
            L"PCR 11 \u2014 BitLocker access control",
            L"PCR 12 \u2014 Data events & OS config",
            L"PCR 13 \u2014 Boot module details",
            L"PCR 14 \u2014 Boot authorities",
            L"PCR 15 \u2014 OS defined / user",
            L"PCR 16 \u2014 Debug",
            L"PCR 17 \u2014 DRTM ACM",
            L"PCR 18 \u2014 DRTM MLE",
            L"PCR 19 \u2014 DRTM OS",
            L"PCR 20 \u2014 DRTM OS (kernel)",
            L"PCR 21 \u2014 DRTM OS defined",
            L"PCR 22 \u2014 DRTM OS defined",
            L"PCR 23 \u2014 App defined",
        };

        typedef struct { UINT32 version; UINT32 grbitConn; } TBS_CTX_PARAMS2;
        typedef UINT32 (WINAPI *PFN_Tbsi_Context_Create)(TBS_CTX_PARAMS2*, void**);
        typedef UINT32 (WINAPI *PFN_Tbsip_Context_Close)(void*);
        typedef UINT32 (WINAPI *PFN_Tbsip_Submit_Command)(void*,UINT32,UINT32,
                                                            const BYTE*,UINT32,
                                                            BYTE*,UINT32*);
        HMODULE hTbs = LoadLibraryW(L"tbs.dll");
        PFN_Tbsi_Context_Create  fnCreate  = NULL;
        PFN_Tbsip_Context_Close  fnClose   = NULL;
        PFN_Tbsip_Submit_Command fnSubmit  = NULL;
        if(hTbs){
            fnCreate = (PFN_Tbsi_Context_Create) GetProcAddress(hTbs,"Tbsi_Context_Create");
            fnClose  = (PFN_Tbsip_Context_Close) GetProcAddress(hTbs,"Tbsip_Context_Close");
            fnSubmit = (PFN_Tbsip_Submit_Command)GetProcAddress(hTbs,"Tbsip_Submit_Command");
        }

        void *hCtx = NULL;
        BOOL tbsOk = FALSE;

        if(fnCreate && fnClose && fnSubmit){
            TBS_CTX_PARAMS2 params = {2, 4};
            UINT32 rc = fnCreate(&params, &hCtx);
            if(rc != 0){
                TBS_CTX_PARAMS2 p12 = {1, 0};
                rc = fnCreate(&p12, &hCtx);
            }
            tbsOk = (rc == 0 && hCtx != NULL);
            if(tbsOk) tbsPresent = TRUE;
        }

        if(!tbsOk){
            ADD(hPCR, L"(TBS context failed \u2014 is the TPM driver running?)", 2, COL_WARN);
        } else {
            BYTE  pcrData[2][24][32] = {0};
            DWORD pcrLen [2][24]     = {0};
            BOOL  pcrGot [2][24]     = {0};

            WORD algoIds[2] = {0x0004, 0x000B};
            const wchar_t *bankName[2] = {L"SHA-1", L"SHA-256"};

            for(int bank = 0; bank < 2; bank++){
                for(int chunk = 0; chunk < 3; chunk++){
                    BYTE mask[3] = {0,0,0};
                    mask[chunk] = 0xFF;
                    int startPcr = chunk * 8;

                    BYTE cmd[20];
                    cmd[0]=0x80; cmd[1]=0x01;
                    cmd[2]=0x00; cmd[3]=0x00; cmd[4]=0x00; cmd[5]=0x14;
                    cmd[6]=0x00; cmd[7]=0x00; cmd[8]=0x01; cmd[9]=0x7E;
                    cmd[10]=0x00; cmd[11]=0x00; cmd[12]=0x00; cmd[13]=0x01;
                    cmd[14]=(BYTE)(algoIds[bank]>>8);
                    cmd[15]=(BYTE)(algoIds[bank]&0xFF);
                    cmd[16]=0x03;
                    cmd[17]=mask[0]; cmd[18]=mask[1]; cmd[19]=mask[2];

                    BYTE   rsp[4096] = {0};
                    UINT32 rspSize   = sizeof(rsp);
                    UINT32 rc = fnSubmit(hCtx, 0, 0, cmd, 20, rsp, &rspSize);
                    if(rc != 0 || rspSize < 10) continue;

                    UINT32 respCode = ((UINT32)rsp[6]<<24)|((UINT32)rsp[7]<<16)|
                                     ((UINT32)rsp[8]<<8)|rsp[9];
                    if(respCode != 0) continue;

                    DWORD off = 10;
                    if(off+4 > rspSize) continue;
                    off += 4;

                    if(off+4 > rspSize) continue;
                    UINT32 selCount = ((UINT32)rsp[off]<<24)|((UINT32)rsp[off+1]<<16)|
                                     ((UINT32)rsp[off+2]<<8)|rsp[off+3];
                    off += 4;
                    for(UINT32 s=0; s<selCount; s++){
                        if(off+4 > rspSize) break;
                        BYTE szSel = rsp[off+2];
                        off += 2 + 1 + szSel;
                    }

                    if(off+4 > rspSize) continue;
                    UINT32 digestCount = ((UINT32)rsp[off]<<24)|((UINT32)rsp[off+1]<<16)|
                                        ((UINT32)rsp[off+2]<<8)|rsp[off+3];
                    off += 4;

                    for(UINT32 d=0; d<digestCount && d<8; d++){
                        if(off+2 > rspSize) break;
                        WORD sz = ((WORD)rsp[off]<<8)|rsp[off+1];
                        off += 2;
                        if(sz == 0 || off+sz > rspSize) break;
                        int pcrIdx = startPcr + (int)d;
                        if(pcrIdx < 24 && sz <= 32){
                            memcpy(pcrData[bank][pcrIdx], rsp+off, sz);
                            pcrLen[bank][pcrIdx] = sz;
                            pcrGot[bank][pcrIdx] = TRUE;
                        }
                        off += sz;
                    }
                }
            }

            BOOL anyPCR = FALSE;

            if(!g_baselineValid){
                BOOL hasRealData = FALSE;
                for(int pcr=0;pcr<PCR_COUNT;pcr++)
                    if(pcrGot[1][pcr]){ hasRealData=TRUE; break; }
                if(hasRealData){
                    BYTE autoBase[PCR_COUNT][PCR_HASH_LEN]={0};
                    for(int pcr=0;pcr<PCR_COUNT;pcr++)
                        if(pcrGot[1][pcr])
                            memcpy(autoBase[pcr],pcrData[1][pcr],PCR_HASH_LEN);
                    SaveBaseline(autoBase);
                    g_baselineDirty=FALSE;
                    SetStatusMsg(L"Baseline auto-saved on first run  \u2714");
                }
            }

            for(int pcr = 0; pcr < 24; pcr++){
                BOOL hasSHA1   = pcrGot[0][pcr];
                BOOL hasSHA256 = pcrGot[1][pcr];
                if(!hasSHA1 && !hasSHA256) continue;

                BOOL allZero = TRUE;
                BOOL allFF   = TRUE;
                if(hasSHA256){
                    for(int b=0;b<32;b++){
                        if(pcrData[1][pcr][b] != 0x00) allZero=FALSE;
                        if(pcrData[1][pcr][b] != 0xFF) allFF=FALSE;
                    }
                } else if(hasSHA1){
                    for(int b=0;b<20;b++){
                        if(pcrData[0][pcr][b] != 0x00) allZero=FALSE;
                        if(pcrData[0][pcr][b] != 0xFF) allFF=FALSE;
                    }
                }

                BOOL changed = FALSE;
                if(g_baselineValid && hasSHA256 && !allFF){
                    changed = (memcmp(pcrData[1][pcr],
                                      g_baseline[pcr],
                                      PCR_HASH_LEN) != 0);
                }

                const wchar_t *desc = pcrDesc[pcr];
                wchar_t nodeLabel[320];
                if(changed)
                    swprintf_s(nodeLabel,319,L"\u26A0  %s  \u2014 CHANGED",desc);
                else if(allFF)
                    swprintf_s(nodeLabel,319,L"%s  \u2298 disabled",desc);
                else if(allZero)
                    swprintf_s(nodeLabel,319,L"%s  (not extended)",desc);
                else
                    swprintf_s(nodeLabel,319,L"%s",desc);

                int nodeImg = changed ? 3 : (allFF ? 2 : (allZero ? 2 : 1));
                int nodeCol = changed ? COL_BAD
                            : (allFF  ? COL_DEFAULT
                            : (allZero? COL_DEFAULT : COL_HARDWARE));

                HTREEITEM hP = ADD(hPCR, nodeLabel, nodeImg, nodeCol);

                if(!allFF){
                    for(int bank=0;bank<2;bank++){
                        if(!pcrGot[bank][pcr]) continue;
                        wchar_t hex[72]={0};
                        for(DWORD b=0;b<pcrLen[bank][pcr];b++)
                            swprintf_s(hex+b*2,3,L"%02X",pcrData[bank][pcr][b]);
                        wchar_t lbl[200];
                        swprintf_s(lbl,199,L"%s: %s",bankName[bank],hex);
                        ADD(hP,lbl,2,COL_DEFAULT);
                    }

                    if(changed){
                        wchar_t oldHex[72]={0};
                        for(int b=0;b<PCR_HASH_LEN;b++)
                            swprintf_s(oldHex+b*2,3,L"%02X",g_baseline[pcr][b]);
                        wchar_t oldLbl[200];
                        swprintf_s(oldLbl,199,L"Baseline: %s",oldHex);
                        ADD(hP,oldLbl,2,COL_BAD);
                        ADD(hP,L"\u26A0  Value differs from saved baseline \u2014 possible boot tampering!",
                            3,COL_BAD);
                        SendMessage(g_hTree,TVM_EXPAND,TVE_EXPAND,(LPARAM)hP);
                    }
                }
                anyPCR = TRUE;
            }

            if(g_baselineValid){
                int nChanged=0;
                for(int pcr=0;pcr<PCR_COUNT;pcr++){
                    if(!pcrGot[1][pcr]) continue;
                    BOOL ff=TRUE;
                    for(int b=0;b<32;b++) if(pcrData[1][pcr][b]!=0xFF){ff=FALSE;break;}
                    if(ff) continue;
                    if(memcmp(pcrData[1][pcr],g_baseline[pcr],PCR_HASH_LEN)!=0)
                        nChanged++;
                }
                if(nChanged>0){
                    wchar_t warn[200];
                    swprintf_s(warn,199,
                        L"\u26A0  WARNING: %d PCR(s) changed since baseline \u2014 possible boot tampering!",
                        nChanged);
                    SetStatusMsg(warn);
                }
            }

            if(!anyPCR)
                ADD(hPCR,L"(no PCR data returned \u2014 TPM may not be active)",2,COL_WARN);
            else
                SendMessage(g_hTree,TVM_EXPAND,TVE_EXPAND,(LPARAM)hPCR);

            LoadEKCert(hTPM, hCtx, fnSubmit);

            fnClose(hCtx);
        }
        if(hTbs) FreeLibrary(hTbs);
    }

noWMI:
    if(pEnum) pEnum->lpVtbl->Release(pEnum);
    if(pSvc)  pSvc->lpVtbl->Release(pSvc);
    if(pLoc)  pLoc->lpVtbl->Release(pLoc);

    if(!wmiOk){
        ADD(hTPM,
            L"WMI query failed \u2014 try running as Administrator", 2, COL_WARN);

        HTREEITEM hReg = ADD(hTPM, L"Registry fallback info", 0, COL_HEADER);
        wchar_t val[256]={0};
        if(RegGetStr(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI",
            L"ManufacturerId", val, 255)){
            wchar_t lbl[300];
            swprintf_s(lbl,299,L"ManufacturerId: %s",val);
            ADD(hReg,lbl,2,COL_DEFAULT);
        }
        if(RegGetStr(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\TPM",
            L"WMIProviderDllName", val, 255)){
            wchar_t lbl[300];
            swprintf_s(lbl,299,L"TPM Provider DLL: %s",val);
            ADD(hReg,lbl,2,COL_DEFAULT);
        }
        SC_HANDLE hSCM = OpenSCManager(NULL,NULL,SC_MANAGER_CONNECT);
        if(hSCM){
            SC_HANDLE hSvc2 = OpenServiceW(hSCM,L"TPM",SERVICE_QUERY_STATUS);
            if(hSvc2){
                SERVICE_STATUS ss={0};
                QueryServiceStatus(hSvc2,&ss);
                ADD(hReg,
                    ss.dwCurrentState==SERVICE_RUNNING
                        ? L"TPM driver: Running  \u2714"
                        : L"TPM driver: Not running",
                    2,
                    ss.dwCurrentState==SERVICE_RUNNING?COL_GOOD:COL_WARN);
                CloseServiceHandle(hSvc2);
            } else {
                ADD(hReg,L"TPM driver: Not found",2,COL_BAD);
            }
            CloseServiceHandle(hSCM);
        }
    }

    SendMessage(g_hTree,TVM_EXPAND,TVE_EXPAND,(LPARAM)hTPM);
}

/* ═══════════════════════════════════════════════════════════
   TCG Event Log
   ══════════════════════════════════════════════════════════ */
static const wchar_t *TcgEventTypeName(UINT32 t)
{
    switch(t){
    case 0x00000000: return L"EV_PREBOOT_CERT";
    case 0x00000001: return L"EV_POST_CODE";
    case 0x00000002: return L"EV_UNUSED";
    case 0x00000003: return L"EV_NO_ACTION";
    case 0x00000004: return L"EV_SEPARATOR";
    case 0x00000005: return L"EV_ACTION";
    case 0x00000006: return L"EV_EVENT_TAG";
    case 0x00000007: return L"EV_S_CRTM_CONTENTS";
    case 0x00000008: return L"EV_S_CRTM_VERSION";
    case 0x00000009: return L"EV_CPU_MICROCODE";
    case 0x0000000A: return L"EV_PLATFORM_CONFIG_FLAGS";
    case 0x0000000B: return L"EV_TABLE_OF_DEVICES";
    case 0x0000000C: return L"EV_COMPACT_HASH";
    case 0x0000000D: return L"EV_IPL";
    case 0x0000000E: return L"EV_IPL_PARTITION_DATA";
    case 0x0000000F: return L"EV_NONHOST_CODE";
    case 0x00000010: return L"EV_NONHOST_CONFIG";
    case 0x00000011: return L"EV_NONHOST_INFO";
    case 0x00000012: return L"EV_OMIT_BOOT_DEVICE_EVENTS";
    case 0x80000001: return L"EV_EFI_VARIABLE_DRIVER_CONFIG";
    case 0x80000002: return L"EV_EFI_VARIABLE_BOOT";
    case 0x80000003: return L"EV_EFI_HANDOFF_TABLES";
    case 0x80000004: return L"EV_EFI_PLATFORM_FIRMWARE_BLOB";
    case 0x80000005: return L"EV_EFI_HANDOFF_TABLES2";
    case 0x80000006: return L"EV_EFI_PLATFORM_FIRMWARE_BLOB2";
    case 0x80000007: return L"EV_EFI_HCRTM_EVENT";
    case 0x80000010: return L"EV_EFI_VARIABLE_AUTHORITY";
    case 0x80000011: return L"EV_EFI_SPDM_FIRMWARE_BLOB";
    case 0x80000012: return L"EV_EFI_SPDM_FIRMWARE_CONFIG";
    case 0x8000000A: return L"EV_EFI_ACTION";
    case 0x8000000B: return L"EV_EFI_PCR_EVENT";
    case 0x8000000C: return L"EV_EFI_GPT_EVENT";
    case 0x8000000D: return L"EV_EFI_IMAGE_LOAD";
    case 0x8000000E: return L"EV_EFI_HANDOFF_TABLES";
    case 0x800000E0: return L"EV_EFI_HCRTM_EVENT";
    default: {
        static wchar_t unk[32];
        swprintf_s(unk,31,L"EV_UNKNOWN(0x%08X)",t);
        return unk;
    }}
}

static const wchar_t *FriendlyEfiVarGuid(const BYTE *guid16)
{
    static const struct { BYTE g[16]; const wchar_t *name; } known[] = {
        {{0x61,0xDF,0xe4,0x8b,0xCA,0x93,0xD2,0x11,0xAA,0x0D,0x00,0xE0,0x98,0x03,0x2B,0x8C}, L"EFI Global"},
        {{0xCB,0xB2,0x19,0xD7,0x3A,0x3D,0x96,0x45,0xA3,0xBC,0xDA,0xD0,0x0E,0x67,0x65,0x6F}, L"EFI Image Security DB"},
        {{0x04,0xB3,0x7F,0xE8,0xF6,0x31,0x4B,0x40,0xBC,0xA8,0x1B,0x31,0x1C,0x59,0x3F,0x4E}, L"SHIM"},
        {{0x77,0xFA,0x9A,0xBD,0x0B,0x57,0x26,0x40,0x90,0x17,0x55,0xBD,0xBE,0x49,0x37,0x85}, L"Microsoft UEFI CA"},
    };
    for(int i=0;i<4;i++)
        if(memcmp(guid16,known[i].g,16)==0) return known[i].name;
    return NULL;
}

/* ── Helpers ─────────────────────────────────────────────── */

/* Format a GUID (mixed-endian EFI style) as the standard string */
static void FmtGuid(const BYTE *g, wchar_t *out, int outLen)
{
    swprintf_s(out, outLen,
        L"{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        g[3],g[2],g[1],g[0], g[5],g[4], g[7],g[6],
        g[8],g[9], g[10],g[11],g[12],g[13],g[14],g[15]);
}

/* Attempt to render bytes as a UTF-16LE string; returns TRUE on success.
   Key insight: genuine UTF-16LE ASCII text has 0x00 as the HIGH byte of
   each character (e.g. 'E' = 0x45 0x00, not 0x45 0x46).
   If the odd bytes (high bytes) are all non-zero printable ASCII, the data
   is almost certainly just ASCII being misread as UTF-16 -- reject it. */
static BOOL TryUtf16(const BYTE *d, DWORD sz, wchar_t *out, int outChars)
{
    if(sz < 4) return FALSE;          /* need at least 2 chars to be confident */
    if((sz & 1)) return FALSE;        /* must be even */

    DWORD bytes = sz & ~1u;
    DWORD chars = bytes / 2;
    if(chars >= (DWORD)outChars) chars = outChars - 1;

    /* Count how many odd bytes (high bytes) are zero vs printable ASCII.
       Real UTF-16LE western text: high bytes are mostly 0x00.
       ASCII-misread-as-UTF16: high bytes are printable ASCII chars (0x20-0x7E). */
    DWORD checkChars = chars < 32 ? chars : 32;
    int highZero   = 0;   /* high byte == 0x00 */
    int highAscii  = 0;   /* high byte is printable ASCII (0x20-0x7E) */
    for(DWORD i = 0; i < checkChars; i++){
        BYTE lo = d[i*2];
        BYTE hi = d[i*2+1];
        if(lo == 0) break;            /* hit null terminator */
        if(hi == 0x00) highZero++;
        else if(hi >= 0x20 && hi < 0x7F) highAscii++;
    }
    /* If more high bytes are printable ASCII than zero, it's plain ASCII data */
    if(highAscii > highZero) return FALSE;
    /* Require at least some zero high bytes to be confident it is UTF-16 */
    if(highZero == 0) return FALSE;

    /* Copy into aligned buffer and validate */
    memcpy(out, d, chars * 2);
    out[chars] = 0;

    int good = 0;
    for(DWORD i = 0; i < chars; i++){
        wchar_t c = out[i];
        if(c == 0) break;
        if(c >= 0x20 && c < 0x7F){ good++; continue; }
        if(c >= 0x80){ good++; continue; }
        out[0] = 0;
        return FALSE;
    }
    if(good == 0){ out[0] = 0; return FALSE; }

    for(int i = (int)chars - 1; i >= 0 && out[i] == 0; i--) out[i] = 0;
    return out[0] != 0;
}

/* Attempt to render bytes as UTF-8/ASCII; returns TRUE on success.
   Accepts null-terminated strings -- stops at the first null. */
static BOOL TryAscii(const BYTE *d, DWORD sz, wchar_t *out, int outChars)
{
    if(sz == 0) return FALSE;
    if(d[0] < 0x20 || d[0] >= 0x7F) return FALSE;

    /* Find length up to null or limit */
    DWORD len = 0;
    DWORD limit = sz < (DWORD)(outChars - 1) ? sz : (DWORD)(outChars - 1);
    while(len < limit && d[len] != 0){
        if(d[len] < 0x20 || d[len] >= 0x7F) return FALSE;
        len++;
    }
    if(len == 0) return FALSE;

    MultiByteToWideChar(CP_UTF8, 0, (char*)d, (int)len, out, outChars - 1);
    out[outChars - 1] = 0;
    return out[0] != 0;
}

/* Emit a hex dump as child nodes under hParent, 16 bytes per row */
static void AddHexDump(HTREEITEM hParent, const BYTE *d, DWORD sz,
                        const wchar_t *prefix)
{
    DWORD show = sz < 128 ? sz : 128;
    for(DWORD row = 0; row < show; row += 16){
        DWORD rowLen = (show - row < 16) ? show - row : 16;
        wchar_t hex[56] = {0}, asc[20] = {0};
        for(DWORD b = 0; b < rowLen; b++){
            swprintf_s(hex + b*3, 4, L"%02X ", d[row+b]);
            asc[b] = (d[row+b] >= 0x20 && d[row+b] < 0x7F) ? d[row+b] : L'.';
        }
        wchar_t lbl[128];
        swprintf_s(lbl, 127, L"%s%04X:  %-48s  %s",
                   prefix ? prefix : L"", row, hex, asc);
        ADD(hParent, lbl, 2, COL_DEFAULT);
    }
    if(sz > 128){
        wchar_t lbl[64];
        swprintf_s(lbl, 63, L"  … (%u bytes total, showing first 128)", sz);
        ADD(hParent, lbl, 2, COL_DEFAULT);
    }
}

/* ── Known EFI Image Load device path node types ────────── */
static const wchar_t *DpTypeName(BYTE type, BYTE sub)
{
    if(type==2 && sub==1)  return L"PCI";
    if(type==2 && sub==3)  return L"USB";
    if(type==2 && sub==18) return L"NVMe";
    if(type==2 && sub==23) return L"UFS";
    if(type==3 && sub==1)  return L"Generic FS";
    if(type==3 && sub==4)  return L"File Path";
    if(type==4 && sub==1)  return L"ACPI";
    if(type==4 && sub==3)  return L"Expanded ACPI";
    if(type==2 && sub==26) return L"SATA";
    if(type==2 && sub==8)  return L"Infiniband";
    if(type==2 && sub==12) return L"SCSI";
    if(type==2 && sub==4)  return L"IDE";
    if(type==2 && sub==22) return L"SAS";
    if(type==5 && sub==1)  return L"BIOS Boot";
    return NULL;
}

/* ═══════════════════════════════════════════════════════════
   ParseEventData — adds rich child nodes to hEv based on evType
   ══════════════════════════════════════════════════════════ */
static void ParseEventData(HTREEITEM hEv, UINT32 evType,
                            const BYTE *d, DWORD sz)
{
    wchar_t lbl[512];

    switch(evType){

    /* ── EV_EVENT_TAG  (0x06) ─────────────────────────────
       TCG PC Client FPT §10.4.5
       Layout: taggedEventDataSize(4) + tagId(4) + tagDataSize(4) + tagData(N) */
    case 0x00000006:
        if(sz >= 12){
            DWORD tagId       = *(DWORD*)(d+4);
            DWORD tagDataSize = *(DWORD*)(d+8);
            swprintf_s(lbl,511,L"Tag ID: 0x%08X",tagId);
            ADD(hEv,lbl,2,COL_DEFAULT);
            swprintf_s(lbl,511,L"Tag data size: %u bytes",tagDataSize);
            ADD(hEv,lbl,2,COL_DEFAULT);
            if(tagDataSize > 0 && sz >= 12 + tagDataSize){
                const BYTE *td = d + 12;
                wchar_t str[256]={0};
                if(TryUtf16(td, tagDataSize, str, 255) ||
                   TryAscii(td, tagDataSize, str, 255)){
                    swprintf_s(lbl,511,L"Tag data: \"%s\"",str);
                    ADD(hEv,lbl,2,COL_HARDWARE);
                } else {
                    HTREEITEM hDump = ADD(hEv,L"Tag data (hex):",2,COL_DEFAULT);
                    AddHexDump(hDump,td,tagDataSize,L"");
                }
            }
        } else {
            AddHexDump(hEv,d,sz,L"");
        }
        break;

    /* ── EV_POST_CODE  (0x01) ─────────────────────────────
       Usually a string ("ACPI DATA", "SMBIOS", etc.) or a blob address */
    case 0x00000001:
        if(sz > 0){
            wchar_t str[256]={0};
            if(TryAscii(d,sz,str,255)){
                swprintf_s(lbl,511,L"POST code: \"%s\"",str);
                ADD(hEv,lbl,2,COL_HARDWARE);
            } else if(sz == 8){
                UINT64 addr = *(UINT64*)d;
                swprintf_s(lbl,511,L"Address: 0x%016I64X",addr);
                ADD(hEv,lbl,2,COL_DEFAULT);
            } else if(sz == 16){
                UINT64 base = *(UINT64*)d;
                UINT64 len  = *(UINT64*)(d+8);
                swprintf_s(lbl,511,L"Base: 0x%016I64X",base);
                ADD(hEv,lbl,2,COL_DEFAULT);
                swprintf_s(lbl,511,L"Length: 0x%I64X (%I64u bytes)",len,len);
                ADD(hEv,lbl,2,COL_DEFAULT);
            } else {
                AddHexDump(hEv,d,sz,L"");
            }
        }
        break;

    /* ── EV_S_CRTM_VERSION  (0x08) ───────────────────────
       Spec says UTF-16LE string, but many firmware implementations
       store a GUID (16 bytes) identifying the CRTM instead.
       Handle both. */
    case 0x00000008:{
        wchar_t str[256]={0};
        if(sz == 16){
            /* GUID form */
            FmtGuid(d, str, 255);
            swprintf_s(lbl,511,L"CRTM GUID: %s",str);
            ADD(hEv,lbl,2,COL_HARDWARE);
        } else if(TryUtf16(d,sz,str,255)){
            swprintf_s(lbl,511,L"CRTM version: \"%s\"",str);
            ADD(hEv,lbl,2,COL_HARDWARE);
        } else if(TryAscii(d,sz,str,255)){
            swprintf_s(lbl,511,L"CRTM version: \"%s\"",str);
            ADD(hEv,lbl,2,COL_HARDWARE);
        } else {
            /* Unknown format — show hex */
            AddHexDump(hEv,d,sz,L"");
        }
        break;
    }

    /* ── EV_S_CRTM_CONTENTS  (0x07) ──────────────────────
       UEFI_PLATFORM_FIRMWARE_BLOB: base(8) + length(8) */
    case 0x00000007:
        if(sz >= 16){
            UINT64 base = *(UINT64*)d;
            UINT64 len  = *(UINT64*)(d+8);
            swprintf_s(lbl,511,L"Base:   0x%016I64X",base);  ADD(hEv,lbl,2,COL_DEFAULT);
            swprintf_s(lbl,511,L"Length: 0x%I64X (%I64u KB)",len,len/1024); ADD(hEv,lbl,2,COL_DEFAULT);
        }
        break;

    /* ── EV_EFI_PLATFORM_FIRMWARE_BLOB  (0x80000004) ─────
       UEFI_PLATFORM_FIRMWARE_BLOB: base(8) + length(8) */
    case 0x80000004:
        if(sz >= 16){
            UINT64 base = *(UINT64*)d;
            UINT64 len  = *(UINT64*)(d+8);
            swprintf_s(lbl,511,L"Base:   0x%016I64X",base);  ADD(hEv,lbl,2,COL_DEFAULT);
            swprintf_s(lbl,511,L"Length: 0x%I64X (%I64u KB)",len,len/1024); ADD(hEv,lbl,2,COL_DEFAULT);
        }
        break;

    /* ── EV_EFI_PLATFORM_FIRMWARE_BLOB2  (0x80000006) ────
       UEFI_PLATFORM_FIRMWARE_BLOB2: descSize(1) + desc(N) + base(8) + len(8) */
    case 0x80000006:
        if(sz >= 1){
            BYTE descLen = d[0];
            if((DWORD)1 + descLen + 16 <= sz){
                wchar_t desc[256]={0};
                if(TryAscii(d+1, descLen, desc, 255) ||
                   TryUtf16(d+1, descLen, desc, 255)){
                    swprintf_s(lbl,511,L"Description: \"%s\"",desc);
                    ADD(hEv,lbl,2,COL_HARDWARE);
                }
                UINT64 base = *(UINT64*)(d+1+descLen);
                UINT64 len  = *(UINT64*)(d+1+descLen+8);
                swprintf_s(lbl,511,L"Base:   0x%016I64X",base); ADD(hEv,lbl,2,COL_DEFAULT);
                swprintf_s(lbl,511,L"Length: 0x%I64X (%I64u KB)",len,len/1024); ADD(hEv,lbl,2,COL_DEFAULT);
            }
        }
        break;

    /* ── EV_EFI_HANDOFF_TABLES  (0x80000003 / 0x8000000E) ─
       UEFI_HANDOFF_TABLE_POINTERS: count(8) + (guid(16)+addr(8))*N */
    case 0x80000003:
    case 0x8000000E:
        if(sz >= 8){
            UINT64 count = *(UINT64*)d;
            if(count > 16) count = 16;
            swprintf_s(lbl,511,L"Table count: %I64u",count); ADD(hEv,lbl,2,COL_DEFAULT);
            for(UINT64 i=0; i<count && 8+i*24+24<=(UINT64)sz; i++){
                const BYTE *entry = d + 8 + i*24;
                wchar_t guid[64]={0}; FmtGuid(entry,guid,63);
                UINT64 addr = *(UINT64*)(entry+16);
                /* Known table GUIDs */
                static const struct { const BYTE g[16]; const wchar_t *n; } kt[] = {
                    {{0x18,0xEB,0x4A,0xEB,0x22,0x80,0xD8,0x41,0xBE,0x68,0x28,0x2A,0x40,0xA3,0x7D,0x0B}, L"SMBIOS"},
                    {{0xEA,0xED,0x21,0xF9,0x1A,0xDE,0x74,0x4E,0xB8,0x44,0x6F,0xA0,0x48,0x25,0xE0,0x19}, L"SMBIOS3"},
                    {{0xEB,0x9D,0x2D,0x31,0x2D,0x38,0xC3,0x11,0x82,0x18,0x00,0xA0,0xC9,0x69,0x72,0x3B}, L"ACPI 1.0 RSDP"},
                    {{0x71,0xE8,0x68,0x88,0xF1,0xE4,0xD3,0x11,0xBC,0x22,0x00,0x80,0xC7,0x3C,0x88,0x81}, L"ACPI 2.0+ RSDP"},
                    {{0x8D,0x59,0xD3,0x26,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, L"SAL System Table"},
                };
                const wchar_t *name = NULL;
                for(int k=0;k<5;k++) if(memcmp(entry,kt[k].g,16)==0){ name=kt[k].n; break; }
                swprintf_s(lbl,511,L"[%I64u] %s  @ 0x%016I64X",
                    i, name?name:guid, addr);
                ADD(hEv,lbl,2,name?COL_HARDWARE:COL_DEFAULT);
            }
        }
        break;

    /* ── EV_EFI_HANDOFF_TABLES2  (0x80000005) ────────────
       UEFI_HANDOFF_TABLE_POINTERS2: descSize(1)+desc(N)+count(8)+(guid+addr)*N */
    case 0x80000005:
        if(sz >= 1){
            BYTE descLen = d[0];
            if((DWORD)1+descLen+8 <= sz){
                wchar_t desc[256]={0};
                TryAscii(d+1,descLen,desc,255);
                swprintf_s(lbl,511,L"Description: \"%s\"",desc[0]?desc:L"(none)");
                ADD(hEv,lbl,2,COL_HARDWARE);
                if((DWORD)1+descLen+8 <= sz){
                    UINT64 count = *(UINT64*)(d+1+descLen);
                    swprintf_s(lbl,511,L"Table count: %I64u",count);
                    ADD(hEv,lbl,2,COL_DEFAULT);
                }
            }
        }
        break;

    /* ── EV_EFI_VARIABLE_DRIVER_CONFIG / BOOT / AUTHORITY ─
       (0x80000001 / 0x80000002 / 0x80000010)
       UEFI_VARIABLE_DATA: guid(16)+nameLen(8)+dataLen(8)+name(nameLen*2)+data */
    case 0x80000001:
    case 0x80000002:
    case 0x80000010:
        if(sz >= 32){
            wchar_t guid[64]={0}; FmtGuid(d,guid,63);
            const wchar_t *gname = FriendlyEfiVarGuid(d);
            swprintf_s(lbl,511,L"GUID: %s%s%s",
                gname?gname:L"", gname?L"  ":L"", guid);
            ADD(hEv,lbl,2,gname?COL_HARDWARE:COL_DEFAULT);

            UINT64 nameLen = *(UINT64*)(d+16);
            UINT64 dataLen = *(UINT64*)(d+24);
            if(nameLen>0 && nameLen<128 && 32+nameLen*2 <= (UINT64)sz){
                wchar_t varName[128]={0};
                memcpy(varName, d+32, nameLen*2); varName[nameLen]=0;
                swprintf_s(lbl,511,L"Variable: %s",varName);
                ADD(hEv,lbl,2,COL_HARDWARE);
            }
            swprintf_s(lbl,511,L"Data length: %I64u bytes",dataLen);
            ADD(hEv,lbl,2,COL_DEFAULT);

            /* For authority events, try to parse as X.509 cert */
            DWORD dataOff = (DWORD)(32 + nameLen*2);
            if(evType==0x80000010 && dataLen>=8 && dataOff+dataLen<=sz){
                /* Authority data is an EFI_SIGNATURE_DATA: owner GUID(16) + cert */
                if(dataLen > 16){
                    PCCERT_CONTEXT pc = CertCreateCertificateContext(
                        X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,
                        d+dataOff+16, (DWORD)(dataLen-16));
                    if(pc){
                        wchar_t subj[256]=L"?";
                        CertGetNameStringW(pc,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,NULL,subj,255);
                        swprintf_s(lbl,511,L"Verified by: %s",subj);
                        ADD(hEv,lbl,1,COL_GOOD);
                        CertFreeCertificateContext(pc);
                    }
                }
            }
        }
        break;

    /* ── EV_EFI_IMAGE_LOAD  (0x8000000D) ─────────────────
       UEFI_IMAGE_LOAD_EVENT:
         imageLocationInMemory(8) + lengthInMemory(8) +
         lengthOfDevicePath(8) + devicePath(N) */
    case 0x8000000D:
        if(sz >= 24){
            UINT64 imgAddr = *(UINT64*)(d+0);
            UINT64 imgLen  = *(UINT64*)(d+8);
            UINT64 dpLen   = *(UINT64*)(d+16);
            swprintf_s(lbl,511,L"Image address: 0x%016I64X",imgAddr); ADD(hEv,lbl,2,COL_DEFAULT);
            swprintf_s(lbl,511,L"Image length:  0x%I64X (%I64u KB)",imgLen,imgLen/1024); ADD(hEv,lbl,2,COL_DEFAULT);
            swprintf_s(lbl,511,L"DevicePath length: %I64u bytes",dpLen); ADD(hEv,lbl,2,COL_DEFAULT);

            /* Walk device path nodes */
            if(dpLen > 0 && 24+dpLen <= (UINT64)sz){
                HTREEITEM hDP = ADD(hEv,L"Device path:",2,COL_HEADER);
                const BYTE *dp    = d + 24;
                const BYTE *dpEnd = dp + dpLen;
                int nodeIdx = 0;
                while(dp + 4 <= dpEnd && nodeIdx < 32){
                    BYTE dpType  = dp[0];
                    BYTE dpSub   = dp[1];
                    WORD dpSz    = *(WORD*)(dp+2);
                    if(dpSz < 4 || dp+dpSz > dpEnd) break;
                    if(dpType == 0x7F && dpSub == 0xFF) break; /* End of Hardware */

                    const wchar_t *dpName = DpTypeName(dpType,dpSub);
                    wchar_t dpLbl[256]={0};

                    /* File Path node (type=4 sub=4): UTF-16LE string */
                    if(dpType==4 && dpSub==4 && dpSz > 4){
                        wchar_t path[256]={0};
                        DWORD pathBytes = dpSz - 4;
                        if(pathBytes/2 < 255){
                            memcpy(path, dp+4, pathBytes);
                            path[pathBytes/2]=0;
                        }
                        swprintf_s(dpLbl,255,L"File: %s",path);
                    } else if(dpType==2 && dpSub==18 && dpSz>=28){
                        /* NVMe: namespace(4)+IEEE EUI-64(8) */
                        DWORD ns = *(DWORD*)(dp+4);
                        swprintf_s(dpLbl,255,L"NVMe namespace: 0x%08X",ns);
                    } else if(dpType==2 && dpSub==1 && dpSz>=6){
                        /* PCI: function+device */
                        swprintf_s(dpLbl,255,L"PCI %02X:%02X",dp[5],dp[4]);
                    } else if(dpName){
                        swprintf_s(dpLbl,255,L"%s",dpName);
                    } else {
                        swprintf_s(dpLbl,255,L"Type %02X/%02X (%u bytes)",
                                   dpType,dpSub,dpSz-4);
                    }
                    ADD(hDP,dpLbl,2,COL_DEFAULT);
                    dp += dpSz;
                    nodeIdx++;
                }
            }
        }
        break;

    /* ── EV_EFI_GPT_EVENT  (0x8000000C) ──────────────────
       EFI_GPT_DATA: header(92) + partCount(8) + partitions(N×128) */
    case 0x8000000C:
        if(sz >= 100){
            UINT64 partCount = *(UINT64*)(d+92);
            if(partCount > 128) partCount = 128;
            swprintf_s(lbl,511,L"GPT partition count: %I64u",partCount);
            ADD(hEv,lbl,2,COL_DEFAULT);

            /* Disk GUID is at offset 56 in the GPT header */
            wchar_t diskGuid[64]={0}; FmtGuid(d+56,diskGuid,63);
            swprintf_s(lbl,511,L"Disk GUID: %s",diskGuid);
            ADD(hEv,lbl,2,COL_DEFAULT);

            for(UINT64 i=0; i<partCount && 100+i*128+128<=(UINT64)sz; i++){
                const BYTE *pe = d + 100 + i*128;
                /* GPT partition entry: typeGuid(16)+partGuid(16)+startLBA(8)+
                   endLBA(8)+attrs(8)+name(72 UTF-16LE) */
                wchar_t typeGuid[64]={0}; FmtGuid(pe,typeGuid,63);
                UINT64 startLBA = *(UINT64*)(pe+32);
                UINT64 endLBA   = *(UINT64*)(pe+40);
                UINT64 sectors  = endLBA >= startLBA ? endLBA-startLBA+1 : 0;

                /* Friendly partition type names */
                static const struct { const BYTE g[16]; const wchar_t *n; } pt[] = {
                    {{0x28,0x73,0x2A,0xC1,0x1F,0xF8,0xD2,0x11,0xBA,0x4B,0x00,0xA0,0xC9,0x3E,0xC9,0x3B}, L"EFI System Partition"},
                    {{0x16,0xE3,0xC9,0xE3,0x5C,0x0B,0xB8,0x4D,0x81,0x7D,0xF9,0x2D,0xF0,0x02,0x15,0xAE}, L"Microsoft Reserved"},
                    {{0xA2,0xA0,0xD0,0xEB,0xE5,0xB9,0x33,0x44,0x87,0xC0,0x68,0xB6,0xB7,0x26,0x99,0xC7}, L"Basic Data"},
                    {{0xAA,0xC8,0x08,0x58,0x8F,0x7E,0xE0,0x42,0x85,0xD2,0xE1,0xE9,0x04,0x34,0xCF,0xB3}, L"LDM Metadata"},
                    {{0x26,0x58,0x44,0xA9,0x76,0x7B,0xCC,0x45,0xA4,0xBB,0xA4,0xBD,0x2D,0x79,0x06,0x6E}, L"Windows RE"},
                    {{0x0F,0x88,0x9D,0xA1,0x15,0x3B,0x43,0x40,0xB5,0x48,0x02,0x2D,0x0C,0xE4,0xF7,0x4F}, L"Linux /boot"},
                    {{0x0F,0xC6,0x3D,0xAF,0x84,0x83,0x72,0x47,0x8E,0x79,0x3D,0x69,0xD8,0x47,0x7D,0xE4}, L"Linux Data"},
                    {{0x6D,0xFD,0x57,0x06,0xAB,0xA4,0xC4,0x43,0x84,0xE5,0x09,0x33,0xC8,0x4B,0x4F,0x4F}, L"Linux swap"},
                };
                const wchar_t *ptName = NULL;
                for(int k=0;k<8;k++) if(memcmp(pe,pt[k].g,16)==0){ ptName=pt[k].n; break; }

                wchar_t partName[37]={0};
                memcpy(partName, pe+56, 36*2); partName[36]=0;
                /* Trim null */
                for(int t=35;t>=0&&partName[t]==0;t--) partName[t]=0;

                swprintf_s(lbl,511,L"[%I64u] %s  \u2014  %s  (%I64u MB)",
                    i,
                    partName[0]?partName:L"(unnamed)",
                    ptName?ptName:typeGuid,
                    sectors/2048);
                ADD(hEv,lbl,2,ptName?COL_HARDWARE:COL_DEFAULT);
            }
        }
        break;

    /* ── EV_EFI_ACTION / EV_ACTION  (0x8000000A / 0x05) ──
       Actual format on this firmware:
         byte[0]  = string length (char count, not including null)
         byte[1..len] = ASCII string
         byte[len+1]  = 0x00 null terminator
         byte[len+2..] = optional binary tail (address/size)
       Some firmware instead just stores a plain null-terminated ASCII
       string with no length prefix. Handle both. */
    case 0x8000000A:
    case 0x00000005:{
        if(sz == 0) break;
        wchar_t str[512]={0};
        DWORD strEnd = 0;  /* first byte past the string+null */

        /* Try length-prefixed form: byte[0] = len, then ascii, then null */
        BYTE prefixLen = d[0];
        if(prefixLen > 0 && prefixLen < sz && (DWORD)prefixLen+1 < sz
           && d[prefixLen+1] == 0x00){
            /* Validate the chars */
            BOOL ok = TRUE;
            for(BYTE i = 1; i <= prefixLen; i++)
                if(d[i] < 0x20 || d[i] >= 0x7F){ ok=FALSE; break; }
            if(ok){
                MultiByteToWideChar(CP_UTF8,0,(char*)(d+1),(int)prefixLen,str,511);
                str[prefixLen]=0;
                strEnd = prefixLen + 2;
            }
        }

        /* Fall back to plain null-terminated ASCII */
        if(str[0]==0 && TryAscii(d,sz,str,511)){
            /* find the null */
            strEnd = 0;
            for(DWORD i=0;i<sz;i++) if(d[i]==0){strEnd=i+1;break;}
        }

        if(str[0]){
            swprintf_s(lbl,511,L"\"%s\"",str);
            ADD(hEv,lbl,2,COL_HARDWARE);
            /* If there's a binary tail, show base+size */
            DWORD tail = sz - strEnd;
            if(strEnd > 0 && tail == 8){
                UINT64 addr = *(UINT64*)(d+strEnd);
                swprintf_s(lbl,511,L"Address: 0x%016I64X",addr);
                ADD(hEv,lbl,2,COL_DEFAULT);
            } else if(strEnd > 0 && tail == 16){
                UINT64 base = *(UINT64*)(d+strEnd);
                UINT64 len2 = *(UINT64*)(d+strEnd+8);
                swprintf_s(lbl,511,L"Base:   0x%016I64X",base); ADD(hEv,lbl,2,COL_DEFAULT);
                swprintf_s(lbl,511,L"Length: 0x%I64X (%I64u KB)",len2,len2/1024); ADD(hEv,lbl,2,COL_DEFAULT);
            } else if(strEnd > 0 && tail > 0){
                AddHexDump(hEv,d+strEnd,tail,L"tail: ");
            }
        } else {
            /* Truly unknown — show hex */
            AddHexDump(hEv,d,sz,L"");
        }
        break;
    }

    /* ── EV_SEPARATOR  (0x04) ────────────────────────────
       A 4-byte value; 0x00000000 means no error */
    case 0x00000004:
        if(sz >= 4){
            DWORD val = *(DWORD*)d;
            swprintf_s(lbl,511,L"Value: 0x%08X%s",val,
                val==0?L"  (success)":val==0xFFFFFFFF?L"  (error)":L"");
            ADD(hEv,lbl,2,val==0?COL_GOOD:(val==0xFFFFFFFF?COL_BAD:COL_DEFAULT));
        }
        break;

    /* ── EV_NO_ACTION  (0x03) ────────────────────────────
       Variable; may contain a "Spec ID Event" header or StartupLocality */
    case 0x00000003:
        if(sz >= 16){
            /* Check for "Spec ID Event03" or "StartupLocality" */
            if(sz >= 15 && memcmp(d,"Spec ID Event03",15)==0){
                /* specVersion at offset 24+: major(1)+minor(1)+errata(1) */
                if(sz >= 28){
                    swprintf_s(lbl,511,L"Spec: TCG2 v%u.%u errata %u",d[24],d[25],d[26]);
                    ADD(hEv,lbl,2,COL_HARDWARE);
                    /* Hash algorithm list follows */
                    DWORD numAlg = *(DWORD*)(d+24+4);
                    DWORD off2 = 24+8;
                    for(DWORD i=0;i<numAlg&&off2+4<=sz;i++){
                        WORD alg  = *(WORD*)(d+off2);
                        WORD hlen = *(WORD*)(d+off2+2);
                        const wchar_t *an =
                            alg==0x0004?L"SHA-1":
                            alg==0x000B?L"SHA-256":
                            alg==0x000C?L"SHA-384":
                            alg==0x000D?L"SHA-512":L"?";
                        swprintf_s(lbl,511,L"Hash alg: %s (%u bytes)",an,hlen);
                        ADD(hEv,lbl,2,COL_DEFAULT);
                        off2+=4;
                    }
                }
            } else if(sz >= 17 && memcmp(d,"StartupLocality",15)==0){
                BYTE loc = d[16];
                swprintf_s(lbl,511,L"Startup locality: %u%s",loc,
                    loc==0?L" (BIOS/firmware)":loc==3?L" (OS/pre-OS)":L"");
                ADD(hEv,lbl,2,COL_DEFAULT);
            }
        }
        break;

    /* ── EV_CPU_MICROCODE  (0x09) ────────────────────────
       UEFI_PLATFORM_FIRMWARE_BLOB: base(8) + length(8) */
    case 0x00000009:
        if(sz >= 16){
            UINT64 base = *(UINT64*)d;
            UINT64 len  = *(UINT64*)(d+8);
            swprintf_s(lbl,511,L"Microcode base:   0x%016I64X",base); ADD(hEv,lbl,2,COL_DEFAULT);
            swprintf_s(lbl,511,L"Microcode length: 0x%I64X (%I64u bytes)",len,len); ADD(hEv,lbl,2,COL_DEFAULT);
        }
        break;

    /* ── EV_COMPACT_HASH  (0x0C) ─────────────────────────
       Raw hash (often all-FF when PCR not used) — just show hex cleanly */
    case 0x0000000C:
        if(sz > 0){
            wchar_t hex[128]={0};
            DWORD show = sz < 48 ? sz : 48;
            for(DWORD b=0;b<show;b++) swprintf_s(hex+b*2,3,L"%02X",d[b]);
            if(sz > 48) wcscat(hex,L"\u2026");
            swprintf_s(lbl,511,L"Hash: %s",hex);
            ADD(hEv,lbl,2,COL_DEFAULT);
        }
        break;

    /* ── EV_TABLE_OF_DEVICES  (0x0B) ─────────────────────
       ACPI-style 8-byte base+length records */
    case 0x0000000B:
        if(sz >= 8){
            DWORD nEntries = sz / 8;
            for(DWORD i=0;i<nEntries&&i<8;i++){
                UINT64 val = *(UINT64*)(d+i*8);
                swprintf_s(lbl,511,L"Entry[%u]: 0x%016I64X",i,val);
                ADD(hEv,lbl,2,COL_DEFAULT);
            }
        }
        break;

    default:
        /* For any unhandled type with small data, try string then hex */
        if(sz > 0 && sz <= 512){
            wchar_t str[512]={0};
            if(TryUtf16(d,sz,str,511)){
                swprintf_s(lbl,511,L"Data: \"%s\"",str);
                ADD(hEv,lbl,2,COL_DEFAULT);
            } else if(TryAscii(d,sz,str,511)){
                swprintf_s(lbl,511,L"Data: \"%s\"",str);
                ADD(hEv,lbl,2,COL_DEFAULT);
            } else if(sz <= 64){
                AddHexDump(hEv,d,sz,L"");
            }
        }
        break;
    }
}

static void LoadTCGLog(HTREEITEM hRoot)
{
    HTREEITEM hLog = ADD(hRoot, L"TCG Boot Event Log", 0, COL_HEADER);

    typedef UINT32 (WINAPI *PFN_GetLog)(void*, BYTE*, UINT32*);
    typedef struct { UINT32 version; UINT32 grbitConn; } TBS_CP2;
    typedef UINT32 (WINAPI *PFN_CC)(TBS_CP2*,void**);
    typedef UINT32 (WINAPI *PFN_CL)(void*);

    HMODULE hTbs = LoadLibraryW(L"tbs.dll");
    if(!hTbs){ ADD(hLog,L"(tbs.dll not found)",2,COL_WARN); return; }

    PFN_CC     fnCreate  = (PFN_CC)    GetProcAddress(hTbs,"Tbsi_Context_Create");
    PFN_CL     fnClose   = (PFN_CL)    GetProcAddress(hTbs,"Tbsip_Context_Close");
    PFN_GetLog fnGetLog  = (PFN_GetLog)GetProcAddress(hTbs,"Tbsi_Get_TCG_Log");

    if(!fnCreate||!fnClose||!fnGetLog){
        ADD(hLog,L"(Tbsi_Get_TCG_Log not available on this Windows version)",2,COL_WARN);
        FreeLibrary(hTbs); return;
    }

    void *hCtx = NULL;
    TBS_CP2 p={2,4};
    if(fnCreate(&p,&hCtx)!=0||!hCtx){
        TBS_CP2 p2={1,0}; fnCreate(&p2,&hCtx);
    }
    if(!hCtx){
        ADD(hLog,L"(could not open TBS context \u2014 run as Administrator)",2,COL_WARN);
        FreeLibrary(hTbs); return;
    }

    UINT32 logSize = 0;
    fnGetLog(hCtx, NULL, &logSize);
    if(logSize == 0){
        ADD(hLog,L"(TCG log is empty or unavailable)",2,COL_WARN);
        fnClose(hCtx); FreeLibrary(hTbs); return;
    }

    BYTE *log = (BYTE*)malloc(logSize);
    if(!log){ fnClose(hCtx); FreeLibrary(hTbs); return; }

    UINT32 rc = fnGetLog(hCtx, log, &logSize);
    fnClose(hCtx);
    FreeLibrary(hTbs);

    if(rc != 0){
        wchar_t err[128]; swprintf_s(err,127,L"(Tbsi_Get_TCG_Log failed: 0x%08X)",rc);
        ADD(hLog,err,2,COL_WARN); free(log); return;
    }

    HTREEITEM hPCRNodes[24] = {0};
    int       pcrEvCount[24] = {0};

    BYTE *p2   = log;
    BYTE *end  = log + logSize;
    BOOL crypto = FALSE;
    int  totalEvents = 0;

    wchar_t szTotal[64];

    while(p2 + 8 <= end){
        UINT32 pcrIdx   = *(UINT32*)p2;
        UINT32 evType   = *(UINT32*)(p2+4);
        p2 += 8;

        if(!crypto){
            if(p2 + 20 + 4 > end) break;
            BYTE *sha1 = p2; p2 += 20;
            UINT32 evSize = *(UINT32*)p2; p2 += 4;
            if(p2 + evSize > end) break;
            BYTE *evData = p2; p2 += evSize;

            if(evType == 0x00000003 && evSize >= 24 &&
               memcmp(evData,"Spec ID Event03",15)==0){
                crypto = TRUE;
                continue;
            }

            if(pcrIdx >= 24) continue;
            if(!hPCRNodes[pcrIdx]){
                wchar_t lbl[64];
                swprintf_s(lbl,63,L"PCR %u",pcrIdx);
                hPCRNodes[pcrIdx] = ADD(hLog,lbl,0,COL_HEADER);
            }

            const wchar_t *typeName = TcgEventTypeName(evType);
            wchar_t evLbl[256];
            swprintf_s(evLbl,255,L"[%s]",typeName);
            HTREEITEM hEv = ADD(hPCRNodes[pcrIdx],evLbl,2,COL_DEFAULT);

            wchar_t hexd[48]={0};
            for(int i=0;i<20;i++) swprintf_s(hexd+i*2,3,L"%02X",sha1[i]);
            wchar_t digestLbl[64]; swprintf_s(digestLbl,63,L"SHA-1: %s",hexd);
            ADD(hEv,digestLbl,2,COL_DEFAULT);

            /* Rich structured data */
            if(evSize > 0) ParseEventData(hEv, evType, evData, evSize);

            pcrEvCount[pcrIdx]++;
            totalEvents++;

        } else {
            if(p2 + 4 > end) break;
            UINT32 digestCount = *(UINT32*)p2; p2 += 4;
            if(digestCount > 10) break;

            struct { WORD algo; BYTE data[64]; DWORD len; } digests[5];
            DWORD nDigests = 0;
            BOOL parseOk = TRUE;

            for(UINT32 d=0; d<digestCount; d++){
                if(p2+2 > end){parseOk=FALSE;break;}
                WORD algo = *(WORD*)p2; p2+=2;
                DWORD hlen = (algo==0x0004)?20:(algo==0x000B)?32:
                             (algo==0x000C)?48:(algo==0x000D)?64:0;
                if(hlen==0||p2+hlen>end){
                    parseOk=FALSE; break;
                }
                if(nDigests<5){
                    digests[nDigests].algo=algo;
                    digests[nDigests].len=hlen;
                    memcpy(digests[nDigests].data,p2,hlen);
                    nDigests++;
                }
                p2 += hlen;
            }
            if(!parseOk) break;

            if(p2+4 > end) break;
            UINT32 evSize = *(UINT32*)p2; p2+=4;
            if(p2+evSize > end) break;
            BYTE *evData = p2; p2 += evSize;

            if(pcrIdx >= 24) continue;
            if(!hPCRNodes[pcrIdx]){
                wchar_t lbl[64]; swprintf_s(lbl,63,L"PCR %u",pcrIdx);
                hPCRNodes[pcrIdx]=ADD(hLog,lbl,0,COL_HEADER);
            }

            const wchar_t *typeName=TcgEventTypeName(evType);
            wchar_t evLbl[512];
            swprintf_s(evLbl,511,L"[%s]",typeName);
            HTREEITEM hEv=ADD(hPCRNodes[pcrIdx],evLbl,2,COL_DEFAULT);

            for(DWORD d=0;d<nDigests;d++){
                const wchar_t *aname=
                    digests[d].algo==0x0004?L"SHA-1":
                    digests[d].algo==0x000B?L"SHA-256":
                    digests[d].algo==0x000C?L"SHA-384":
                    digests[d].algo==0x000D?L"SHA-512":L"?";
                wchar_t hex[132]={0};
                for(DWORD b=0;b<digests[d].len;b++)
                    swprintf_s(hex+b*2,3,L"%02X",digests[d].data[b]);
                wchar_t dl[200];
                swprintf_s(dl,199,L"%s: %s",aname,hex);
                ADD(hEv,dl,2,COL_DEFAULT);
            }

            /* Rich structured data */
            if(evSize > 0) ParseEventData(hEv, evType, evData, evSize);

            pcrEvCount[pcrIdx]++;
            totalEvents++;
        }

        if(totalEvents > 5000) break;
    }

    free(log);

    for(int i=0;i<24;i++){
        if(!hPCRNodes[i]) continue;
        wchar_t lbl[128];
        swprintf_s(lbl,127,L"PCR %d  (%d events)",i,pcrEvCount[i]);
        TVITEMW it={0}; it.hItem=hPCRNodes[i];
        it.mask=TVIF_TEXT; it.pszText=lbl;
        SendMessage(g_hTree,TVM_SETITEMW,0,(LPARAM)&it);
    }

    if(totalEvents==0)
        ADD(hLog,L"(no events parsed \u2014 log may be in an unsupported format)",2,COL_WARN);
    else {
        swprintf_s(szTotal,63,L"Total: %d events across %d PCRs",
            totalEvents,
            (int)(sizeof(hPCRNodes)/sizeof(hPCRNodes[0])));
        TVINSERTSTRUCTW tvi={0};
        tvi.hParent=hLog; tvi.hInsertAfter=TVI_FIRST;
        tvi.item.mask=TVIF_TEXT|TVIF_IMAGE|TVIF_SELECTEDIMAGE|TVIF_PARAM;
        tvi.item.pszText=szTotal; tvi.item.lParam=COL_DEFAULT;
        SendMessage(g_hTree,TVM_INSERTITEMW,0,(LPARAM)&tvi);
    }
}

static const wchar_t *FriendlyAlgo(const wchar_t *a){
    if(!a) return L"?";
    if(wcsstr(a,L"RSA"))    return L"RSA";
    if(wcsstr(a,L"ECDSA"))  return L"ECDSA";
    if(wcsstr(a,L"ECDH"))   return L"ECDH";
    if(wcsstr(a,L"DSA"))    return L"DSA";
    if(wcsstr(a,L"Ed25519"))return L"Ed25519";
    return a;
}
static void ExportPolicyStr(DWORD p,wchar_t *out,int n){
    *out=0;
    if(p&NCRYPT_ALLOW_EXPORT_FLAG)          wcscat(out,L"Exportable ");
    if(p&NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG)wcscat(out,L"PlaintextExport ");
    if(p&NCRYPT_ALLOW_ARCHIVING_FLAG)       wcscat(out,L"Archivable ");
    if(!*out) wcscpy(out,L"Not exportable");
}
static DWORD NcryptDW(NCRYPT_KEY_HANDLE h,const wchar_t *p){
    DWORD v=0,cb=0;
    NCryptGetProperty(h,p,(PBYTE)&v,sizeof(v),&cb,0);
    return v;
}
static BOOL NcryptStr(NCRYPT_KEY_HANDLE h,const wchar_t *p,
                       wchar_t *out,DWORD oc){
    DWORD cb=0;
    if(NCryptGetProperty(h,p,NULL,0,&cb,0)!=ERROR_SUCCESS
       &&NCryptGetProperty(h,p,NULL,0,&cb,0)!=(SECURITY_STATUS)ERROR_MORE_DATA)
        return FALSE;
    if(!cb||cb>oc*2) return FALSE;
    return NCryptGetProperty(h,p,(PBYTE)out,oc*2,&cb,0)==ERROR_SUCCESS;
}
static DWORD GetKeyBits(NCRYPT_KEY_HANDLE h){
    DWORD b=NcryptDW(h,NCRYPT_LENGTH_PROPERTY);
    if(b) return b;
    DWORD cb=0;
    if(NCryptExportKey(h,0,BCRYPT_RSAPUBLIC_BLOB,NULL,NULL,0,&cb,0)==ERROR_SUCCESS&&cb){
        BYTE *bl=(BYTE*)malloc(cb);
        if(bl){
            if(NCryptExportKey(h,0,BCRYPT_RSAPUBLIC_BLOB,NULL,bl,cb,&cb,0)==ERROR_SUCCESS&&cb>=8)
                b=((DWORD*)bl)[1];
            free(bl);
        }
    }
    return b;
}

static void LoadNCrypt(HTREEITEM hRoot)
{
    HTREEITEM hNC = ADD(hRoot, L"NCrypt  /  Key Storage Providers", 0, COL_HEADER);

    DWORD kspCnt=0; NCryptProviderName *pProvs=NULL;
    if(NCryptEnumStorageProviders(&kspCnt,&pProvs,0)!=ERROR_SUCCESS||!kspCnt){
        ADD(hNC,L"(NCryptEnumStorageProviders failed)",2,COL_WARN);
        return;
    }
    for(DWORD p=0;p<kspCnt;p++){
        const wchar_t *kn=pProvs[p].pszName;
        NCRYPT_PROV_HANDLE hProv=0;
        if(NCryptOpenStorageProvider(&hProv,kn,0)!=ERROR_SUCCESS) continue;

        wchar_t pl[512]; swprintf_s(pl,511,L"Provider: %s",kn);
        HTREEITEM hP=ADD(hNC,pl,0,COL_HEADER);

        DWORD scopes[]={0,NCRYPT_MACHINE_KEY_FLAG};
        const wchar_t *snames[]={L"Current User",L"Local Machine"};
        for(int sc=0;sc<2;sc++){
            NCryptKeyName *pKeys=NULL; PVOID pEnum=NULL;
            HTREEITEM hScope=NULL;
            while(NCryptEnumKeys(hProv,NULL,&pKeys,&pEnum,scopes[sc])==ERROR_SUCCESS){
                if(!hScope) hScope=ADD(hP,snames[sc],0,COL_DEFAULT);

                NCRYPT_KEY_HANDLE hKey=0;
                int col=COL_DEFAULT;
                NCryptOpenKey(hProv,&hKey,pKeys->pszName,
                               pKeys->dwLegacyKeySpec,scopes[sc]);
                if(hKey){
                    DWORD hw=NcryptDW(hKey,NCRYPT_IMPL_TYPE_PROPERTY);
                    if(hw&NCRYPT_IMPL_HARDWARE_FLAG) col=COL_HARDWARE;
                    DWORD ep=NcryptDW(hKey,NCRYPT_EXPORT_POLICY_PROPERTY);
                    if(ep&NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG) col=COL_WARN;
                }

                HTREEITEM hK=ADD(hScope,pKeys->pszName,1,col);

                wchar_t lbl[512];
                swprintf_s(lbl,511,L"Algorithm: %s",FriendlyAlgo(pKeys->pszAlgid));
                ADD(hK,lbl,2,COL_DEFAULT);

                if(hKey){
                    DWORD bits=GetKeyBits(hKey);
                    if(bits){swprintf_s(lbl,511,L"Key length: %u bits",bits);ADD(hK,lbl,2,COL_DEFAULT);}

                    DWORD ep=NcryptDW(hKey,NCRYPT_EXPORT_POLICY_PROPERTY);
                    wchar_t es[256]; ExportPolicyStr(ep,es,255);
                    swprintf_s(lbl,511,L"Export policy: %s",es);
                    ADD(hK,lbl,2,(ep&NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG)?COL_WARN:COL_GOOD);

                    DWORD hw=NcryptDW(hKey,NCRYPT_IMPL_TYPE_PROPERTY);
                    swprintf_s(lbl,511,L"Implementation: %s%s%s",
                        (hw&NCRYPT_IMPL_HARDWARE_FLAG)?L"Hardware ":L"",
                        (hw&NCRYPT_IMPL_SOFTWARE_FLAG)?L"Software ":L"",
                        (hw&NCRYPT_IMPL_REMOVABLE_FLAG)?L"Removable":L"");
                    ADD(hK,lbl,2,(hw&NCRYPT_IMPL_HARDWARE_FLAG)?COL_HARDWARE:COL_DEFAULT);

                    wchar_t uname[512]={0};
                    if(NcryptStr(hKey,NCRYPT_UNIQUE_NAME_PROPERTY,uname,511)){
                        swprintf_s(lbl,511,L"Container: %s",uname);
                        ADD(hK,lbl,2,COL_DEFAULT);
                    }

                    DWORD cbC=0;
                    if(NCryptGetProperty(hKey,NCRYPT_CERTIFICATE_PROPERTY,
                                          NULL,0,&cbC,0)==ERROR_SUCCESS&&cbC){
                        BYTE *cb2=(BYTE*)malloc(cbC);
                        if(cb2){
                            if(NCryptGetProperty(hKey,NCRYPT_CERTIFICATE_PROPERTY,
                                                  cb2,cbC,&cbC,0)==ERROR_SUCCESS){
                                PCCERT_CONTEXT pc=CertCreateCertificateContext(
                                    X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,cb2,cbC);
                                if(pc){
                                    wchar_t sj[256]=L"?";
                                    CertGetNameStringW(pc,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,NULL,sj,255);
                                    swprintf_s(lbl,511,L"Linked cert: %s",sj);
                                    ADD(hK,lbl,2,COL_DEFAULT);
                                    CertFreeCertificateContext(pc);
                                }
                            }
                            free(cb2);
                        }
                    }
                    NCryptFreeObject(hKey);
                }
                NCryptFreeBuffer(pKeys); pKeys=NULL;
            }
            if(pEnum) NCryptFreeBuffer(pEnum);
            if(hScope) SendMessage(g_hTree,TVM_EXPAND,TVE_EXPAND,(LPARAM)hScope);
        }
        NCryptFreeObject(hProv);
        SendMessage(g_hTree,TVM_EXPAND,TVE_EXPAND,(LPARAM)hP);
    }
    NCryptFreeBuffer(pProvs);
    SendMessage(g_hTree,TVM_EXPAND,TVE_EXPAND,(LPARAM)hNC);
}

/* ═══════════════════════════════════════════════════════════
   GPG
   ══════════════════════════════════════════════════════════ */
static void LoadGPG(HTREEITEM hRoot)
{
    HTREEITEM hGPG=ADD(hRoot,L"GPG / PGP Keys",0,COL_HEADER);
    char raw[16384]={0};
    BOOL ok=RunCmd(L"gpg --list-secret-keys --with-colons 2>nul",raw,sizeof(raw));
    if(!ok||strlen(raw)<5)
        ok=RunCmd(L"gpg2 --list-secret-keys --with-colons 2>nul",raw,sizeof(raw));
    if(!ok||strlen(raw)<5){ADD(hGPG,L"(gpg not found or no secret keys)",2,COL_WARN);return;}

    wchar_t wide[16384];
    MultiByteToWideChar(CP_UTF8,0,raw,-1,wide,16383);
    static const wchar_t *am[]={
        L"?",L"RSA",L"?",L"?",L"?",L"?",L"?",L"?",L"?",L"?",
        L"?",L"?",L"?",L"?",L"?",L"?",L"?",L"DSA",L"?",L"?",
        L"?",L"?",L"ECDH",L"ECDSA",L"?",L"EdDSA"};
    wchar_t *ctx=NULL,*line=wcstok_s(wide,L"\n",&ctx);
    HTREEITEM hKey=NULL; wchar_t lbl[512];
    while(line){
        size_t n=wcslen(line); if(n&&line[n-1]==L'\r') line[n-1]=0;
        if(wcsncmp(line,L"sec",3)==0){
            wchar_t f[10][128]={0}; int fi=0; wchar_t *p=line;
            while(*p&&fi<10){wchar_t *c=wcschr(p,L':');
                if(!c){wcsncpy_s(f[fi++],128,p,127);break;}
                int sl=(int)(c-p);if(sl>127)sl=127;
                wcsncpy_s(f[fi++],128,p,sl);p=c+1;}
            int an=_wtoi(f[3]);
            const wchar_t *an2=(an>=0&&an<26)?am[an]:L"?";
            swprintf_s(lbl,511,L"Key ID: %s  [%s  %s-bit]",f[4][0]?f[4]:L"?",an2,f[2]);
            hKey=ADD(hGPG,lbl,1,COL_DEFAULT);
        } else if(wcsncmp(line,L"fpr",3)==0&&hKey){
            int c2=0;wchar_t *p2=line;while(*p2&&c2<9)if(*p2++==L':')c2++;
            if(*p2){swprintf_s(lbl,511,L"Fingerprint: %s",p2);ADD(hKey,lbl,2,COL_DEFAULT);}
        } else if(wcsncmp(line,L"uid",3)==0&&hKey){
            int c2=0;wchar_t *p2=line;while(*p2&&c2<9)if(*p2++==L':')c2++;
            if(*p2){swprintf_s(lbl,511,L"UID: %s",p2);ADD(hKey,lbl,2,COL_DEFAULT);}
        } else if(wcsncmp(line,L"ssb",3)==0&&hKey){
            ADD(hKey,L"\u21B3 Signing subkey",2,COL_DEFAULT);
        }
        line=wcstok_s(NULL,L"\n",&ctx);
    }
    SendMessage(g_hTree,TVM_EXPAND,TVE_EXPAND,(LPARAM)hGPG);
}

/* ═══════════════════════════════════════════════════════════
   SSH
   ══════════════════════════════════════════════════════════ */
static void LoadSSH(HTREEITEM hRoot)
{
    HTREEITEM hSSH=ADD(hRoot,L"SSH Keys  (~/.ssh)",0,COL_HEADER);
    wchar_t prof[MAX_PATH]={0};
    SHGetFolderPathW(NULL,CSIDL_PROFILE,NULL,0,prof);
    wchar_t pat[MAX_PATH],base[MAX_PATH];
    swprintf_s(pat,MAX_PATH,L"%s\\.ssh\\*.pub",prof);
    swprintf_s(base,MAX_PATH,L"%s\\.ssh\\",prof);
    WIN32_FIND_DATAW fd;
    HANDLE hF=FindFirstFileW(pat,&fd);
    if(hF==INVALID_HANDLE_VALUE){ADD(hSSH,L"(no .pub files in ~/.ssh)",2,COL_WARN);return;}
    do{
        wchar_t full[MAX_PATH]; swprintf_s(full,MAX_PATH,L"%s%s",base,fd.cFileName);
        HTREEITEM hK=ADD(hSSH,fd.cFileName,1,COL_DEFAULT);
        HANDLE hFile=CreateFileW(full,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
        if(hFile!=INVALID_HANDLE_VALUE){
            char buf[2048]={0};DWORD nr=0;
            ReadFile(hFile,buf,sizeof(buf)-1,&nr,NULL);CloseHandle(hFile);
            char *sp1=strchr(buf,' ');
            if(sp1){*sp1=0;wchar_t wt[64];wchar_t lbl[256];
                MultiByteToWideChar(CP_UTF8,0,buf,-1,wt,63);
                swprintf_s(lbl,255,L"Type: %s",wt);ADD(hK,lbl,2,COL_DEFAULT);
                char *sp2=strchr(sp1+1,' ');
                if(sp2){char *nl=strchr(sp2+1,'\n');if(nl)*nl=0;
                    char *cr=strchr(sp2+1,'\r');if(cr)*cr=0;
                    wchar_t wc[256];MultiByteToWideChar(CP_UTF8,0,sp2+1,-1,wc,255);
                    swprintf_s(lbl,255,L"Comment: %s",wc);ADD(hK,lbl,2,COL_DEFAULT);}
            }
        }
    }while(FindNextFileW(hF,&fd));
    FindClose(hF);
    SendMessage(g_hTree,TVM_EXPAND,TVE_EXPAND,(LPARAM)hSSH);
}

/* ═══════════════════════════════════════════════════════════
   Cert Store
   ══════════════════════════════════════════════════════════ */
/* ── Expiry colour: red if expired, orange if within 60 days ── */
static int CertExpiryColor(const FILETIME *notAfter)
{
    FILETIME now; GetSystemTimeAsFileTime(&now);
    ULONGLONG nowU  = ((ULONGLONG)now.dwHighDateTime     <<32)|now.dwLowDateTime;
    ULONGLONG expU  = ((ULONGLONG)notAfter->dwHighDateTime<<32)|notAfter->dwLowDateTime;
    if(nowU >= expU) return COL_BAD;
    /* 60 days in 100-ns units */
    if(expU - nowU < (ULONGLONG)60*24*3600*10000000ULL) return COL_WARN;
    return COL_GOOD;
}

/* ── Decode a single OID to a friendly name ─────────────── */
static void OidFriendly(LPCSTR oid, wchar_t *out, int outChars)
{
    /* Try Windows built-in name first */
    PCCRYPT_OID_INFO info = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY,
                                              (void*)oid, 0);
    if(info && info->pwszName){
        wcsncpy(out, info->pwszName, outChars-1);
        return;
    }
    /* Fall back to raw OID string */
    MultiByteToWideChar(CP_ACP, 0, oid, -1, out, outChars-1);
}

/* ── Parse Subject Alternative Names extension ──────────── */
static void AddSANs(HTREEITEM hParent, PCCERT_CONTEXT px)
{
    PCERT_EXTENSION ext = CertFindExtension(
        szOID_SUBJECT_ALT_NAME2,
        px->pCertInfo->cExtension,
        px->pCertInfo->rgExtension);
    if(!ext) ext = CertFindExtension(
        szOID_SUBJECT_ALT_NAME,
        px->pCertInfo->cExtension,
        px->pCertInfo->rgExtension);
    if(!ext) return;

    DWORD cb = 0;
    CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME,
                        ext->Value.pbData, ext->Value.cbData,
                        CRYPT_DECODE_ALLOC_FLAG, NULL, NULL, &cb);
    if(!cb) return;

    CERT_ALT_NAME_INFO *san = NULL;
    if(!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME,
                             ext->Value.pbData, ext->Value.cbData,
                             CRYPT_DECODE_ALLOC_FLAG, NULL, &san, &cb))
        return;

    HTREEITEM hSAN = ADD(hParent, L"Subject Alternative Names:", 2, COL_DEFAULT);
    for(DWORD i = 0; i < san->cAltEntry; i++){
        CERT_ALT_NAME_ENTRY *e = &san->rgAltEntry[i];
        wchar_t lbl[512];
        switch(e->dwAltNameChoice){
        case CERT_ALT_NAME_DNS_NAME:
            swprintf_s(lbl,511,L"DNS: %s", e->pwszDNSName);
            ADD(hSAN,lbl,2,COL_DEFAULT); break;
        case CERT_ALT_NAME_RFC822_NAME:
            swprintf_s(lbl,511,L"Email: %s", e->pwszRfc822Name);
            ADD(hSAN,lbl,2,COL_DEFAULT); break;
        case CERT_ALT_NAME_URL:
            swprintf_s(lbl,511,L"URL: %s", e->pwszURL);
            ADD(hSAN,lbl,2,COL_DEFAULT); break;
        case CERT_ALT_NAME_IP_ADDRESS:
            if(e->IPAddress.cbData==4){
                BYTE *ip=e->IPAddress.pbData;
                swprintf_s(lbl,511,L"IP: %u.%u.%u.%u",ip[0],ip[1],ip[2],ip[3]);
            } else if(e->IPAddress.cbData==16){
                BYTE *ip=e->IPAddress.pbData;
                swprintf_s(lbl,511,
                    L"IPv6: %02X%02X:%02X%02X:%02X%02X:%02X%02X:"
                    L"%02X%02X:%02X%02X:%02X%02X:%02X%02X",
                    ip[0],ip[1],ip[2],ip[3],ip[4],ip[5],ip[6],ip[7],
                    ip[8],ip[9],ip[10],ip[11],ip[12],ip[13],ip[14],ip[15]);
            } else { wcscpy(lbl,L"IP: (unknown format)"); }
            ADD(hSAN,lbl,2,COL_DEFAULT); break;
        default:
            swprintf_s(lbl,511,L"(type %u)",e->dwAltNameChoice);
            ADD(hSAN,lbl,2,COL_DEFAULT); break;
        }
    }
    LocalFree(san);
}

/* ── Parse Extended Key Usage extension ─────────────────── */
static void AddEKUs(HTREEITEM hParent, PCCERT_CONTEXT px)
{
    DWORD cb = 0;
    if(!CertGetEnhancedKeyUsage(px, 0, NULL, &cb) || cb == 0) return;
    CERT_ENHKEY_USAGE *eku = (CERT_ENHKEY_USAGE*)malloc(cb);
    if(!eku) return;
    if(!CertGetEnhancedKeyUsage(px, 0, eku, &cb) || eku->cUsageIdentifier == 0){
        free(eku); return;
    }
    HTREEITEM hEKU = ADD(hParent, L"Extended Key Usage:", 2, COL_DEFAULT);
    for(DWORD i = 0; i < eku->cUsageIdentifier; i++){
        wchar_t name[256]={0};
        OidFriendly(eku->rgpszUsageIdentifier[i], name, 255);
        wchar_t lbl[384];
        swprintf_s(lbl,383,L"%s",name);
        ADD(hEKU,lbl,2,COL_DEFAULT);
    }
    free(eku);
}

/* ── Parse CRL Distribution Points ──────────────────────── */
static void AddCDPs(HTREEITEM hParent, PCCERT_CONTEXT px)
{
    PCERT_EXTENSION ext = CertFindExtension(
        szOID_CRL_DIST_POINTS,
        px->pCertInfo->cExtension,
        px->pCertInfo->rgExtension);
    if(!ext) return;

    DWORD cb = 0;
    CRL_DIST_POINTS_INFO *cdp = NULL;
    if(!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_CRL_DIST_POINTS,
                             ext->Value.pbData, ext->Value.cbData,
                             CRYPT_DECODE_ALLOC_FLAG, NULL, &cdp, &cb))
        return;

    HTREEITEM hCDP = ADD(hParent, L"CRL Distribution Points:", 2, COL_DEFAULT);
    for(DWORD i = 0; i < cdp->cDistPoint && i < 4; i++){
        CRL_DIST_POINT *dp = &cdp->rgDistPoint[i];
        if(dp->DistPointName.dwDistPointNameChoice == CRL_DIST_POINT_FULL_NAME){
            for(DWORD j = 0; j < dp->DistPointName.FullName.cAltEntry; j++){
                CERT_ALT_NAME_ENTRY *e = &dp->DistPointName.FullName.rgAltEntry[j];
                if(e->dwAltNameChoice == CERT_ALT_NAME_URL){
                    ADD(hCDP, e->pwszURL, 2, COL_DEFAULT);
                }
            }
        }
    }
    LocalFree(cdp);
}

/* ── Parse Authority Information Access (OCSP / CA Issuer) ─ */
static void AddAIA(HTREEITEM hParent, PCCERT_CONTEXT px)
{
    PCERT_EXTENSION ext = CertFindExtension(
        szOID_AUTHORITY_INFO_ACCESS,
        px->pCertInfo->cExtension,
        px->pCertInfo->rgExtension);
    if(!ext) return;

    DWORD cb = 0;
    CERT_AUTHORITY_INFO_ACCESS *aia = NULL;
    if(!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_AUTHORITY_INFO_ACCESS,
                             ext->Value.pbData, ext->Value.cbData,
                             CRYPT_DECODE_ALLOC_FLAG, NULL, &aia, &cb))
        return;

    for(DWORD i = 0; i < aia->cAccDescr; i++){
        CERT_ACCESS_DESCRIPTION *ad = &aia->rgAccDescr[i];
        if(ad->AccessLocation.dwAltNameChoice != CERT_ALT_NAME_URL) continue;
        wchar_t lbl[512];
        if(strcmp(ad->pszAccessMethod, szOID_PKIX_OCSP) == 0)
            swprintf_s(lbl,511,L"OCSP: %s", ad->AccessLocation.pwszURL);
        else if(strcmp(ad->pszAccessMethod, szOID_PKIX_CA_ISSUERS) == 0)
            swprintf_s(lbl,511,L"CA Issuers: %s", ad->AccessLocation.pwszURL);
        else
            swprintf_s(lbl,511,L"AIA: %s", ad->AccessLocation.pwszURL);
        ADD(hParent, lbl, 2, COL_DEFAULT);
    }
    LocalFree(aia);
}

/* ── Full certificate detail node ───────────────────────── */
static void AddCertDetail(HTREEITEM hParent, PCCERT_CONTEXT px)
{
    wchar_t lbl[512];

    /* ── SHA-1 thumbprint (with expiry colour) ── */
    BYTE th[20]; DWORD tsz=20;
    int expiryCol = CertExpiryColor(&px->pCertInfo->NotAfter);
    if(CryptHashCertificate(0,CALG_SHA1,0,
                             px->pbCertEncoded,px->cbCertEncoded,th,&tsz)){
        wchar_t hex[48]={0};
        for(DWORD i=0;i<tsz;i++) swprintf_s(hex+i*2,3,L"%02X",th[i]);
        swprintf_s(lbl,511,L"SHA-1: %s",hex);
        ADD(hParent,lbl,2,COL_DEFAULT);
    }

    /* ── SHA-256 thumbprint ── */
    {
        HCRYPTPROV hProv=0; HCRYPTHASH hHash=0;
        if(CryptAcquireContextW(&hProv,NULL,NULL,PROV_RSA_AES,CRYPT_VERIFYCONTEXT)){
            if(CryptCreateHash(hProv,CALG_SHA_256,0,0,&hHash)){
                CryptHashData(hHash,px->pbCertEncoded,px->cbCertEncoded,0);
                BYTE d[32]; DWORD dl=32;
                if(CryptGetHashParam(hHash,HP_HASHVAL,d,&dl,0)){
                    wchar_t hex[68]={0};
                    for(DWORD i=0;i<dl;i++) swprintf_s(hex+i*2,3,L"%02X",d[i]);
                    swprintf_s(lbl,511,L"SHA-256: %s",hex);
                    ADD(hParent,lbl,2,COL_DEFAULT);
                }
                CryptDestroyHash(hHash);
            }
            CryptReleaseContext(hProv,0);
        }
    }

    /* ── Full subject DN ── */
    wchar_t dn[512]=L"";
    CertGetNameStringW(px,CERT_NAME_RDN_TYPE,0,NULL,dn,511);
    if(dn[0]){ swprintf_s(lbl,511,L"Subject DN: %s",dn); ADD(hParent,lbl,2,COL_DEFAULT); }

    /* ── Full issuer DN ── */
    wchar_t idn[512]=L"";
    CertGetNameStringW(px,CERT_NAME_RDN_TYPE,CERT_NAME_ISSUER_FLAG,NULL,idn,511);
    if(idn[0]){ swprintf_s(lbl,511,L"Issuer DN: %s",idn); ADD(hParent,lbl,2,COL_DEFAULT); }

    /* ── Serial number ── */
    {
        DWORD snLen=px->pCertInfo->SerialNumber.cbData;
        if(snLen>0&&snLen<=32){
            wchar_t snHex[72]={0};
            for(DWORD b=0;b<snLen;b++)
                swprintf_s(snHex+b*2,3,L"%02X",
                    px->pCertInfo->SerialNumber.pbData[snLen-1-b]);
            swprintf_s(lbl,511,L"Serial: %s",snHex);
            ADD(hParent,lbl,2,COL_DEFAULT);
        }
    }

    /* ── Validity with expiry colour ── */
    {
        SYSTEMTIME nb,na;
        FileTimeToSystemTime(&px->pCertInfo->NotBefore,&nb);
        FileTimeToSystemTime(&px->pCertInfo->NotAfter,&na);
        swprintf_s(lbl,511,L"Valid: %04d-%02d-%02d \u2192 %04d-%02d-%02d",
            nb.wYear,nb.wMonth,nb.wDay,na.wYear,na.wMonth,na.wDay);
        /* Append expiry status */
        FILETIME now; GetSystemTimeAsFileTime(&now);
        ULONGLONG nowU=((ULONGLONG)now.dwHighDateTime<<32)|now.dwLowDateTime;
        ULONGLONG expU=((ULONGLONG)px->pCertInfo->NotAfter.dwHighDateTime<<32)
                        |px->pCertInfo->NotAfter.dwLowDateTime;
        if(nowU>=expU)
            wcscat(lbl,L"  \u274C EXPIRED");
        else {
            ULONGLONG days=(expU-nowU)/(10000000ULL*86400ULL);
            if(days<=60){
                wchar_t warn[32]; swprintf_s(warn,31,L"  \u26A0 expires in %I64u days",(ULONGLONG)days);
                wcscat(lbl,warn);
            } else {
                wchar_t ok[32]; swprintf_s(ok,31,L"  \u2714 (%I64u days left)",(ULONGLONG)days);
                wcscat(lbl,ok);
            }
        }
        ADD(hParent,lbl,2,expiryCol);
    }

    /* ── Public key algorithm + size ── */
    {
        wchar_t pkAlg[128]=L"";
        if(px->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId){
            OidFriendly(px->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
                        pkAlg,127);
        }
        DWORD keyBits=0;
        DWORD cbPub=0;
        /* Try RSA first */
        if(CryptDecodeObject(X509_ASN_ENCODING,RSA_CSP_PUBLICKEYBLOB,
            px->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
            px->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData,
            0,NULL,&cbPub)&&cbPub>=16){
            BYTE *blob=(BYTE*)malloc(cbPub);
            if(blob){
                if(CryptDecodeObject(X509_ASN_ENCODING,RSA_CSP_PUBLICKEYBLOB,
                    px->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
                    px->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData,
                    0,blob,&cbPub))
                    keyBits=*(DWORD*)(blob+12);
                free(blob);
            }
        }
        if(keyBits)
            swprintf_s(lbl,511,L"Public key: %s  %u bits",pkAlg[0]?pkAlg:L"?",keyBits);
        else
            swprintf_s(lbl,511,L"Public key: %s",pkAlg[0]?pkAlg:L"?");
        ADD(hParent,lbl,1,COL_HARDWARE);
    }

    /* ── Key usage ── */
    {
        BYTE ku=0;
        if(CertGetIntendedKeyUsage(X509_ASN_ENCODING,px->pCertInfo,&ku,1)&&ku){
            wchar_t kuStr[256]=L"Key usage:";
            if(ku&CERT_DIGITAL_SIGNATURE_KEY_USAGE) wcscat(kuStr,L" DigitalSignature");
            if(ku&CERT_NON_REPUDIATION_KEY_USAGE)   wcscat(kuStr,L" NonRepudiation");
            if(ku&CERT_KEY_ENCIPHERMENT_KEY_USAGE)  wcscat(kuStr,L" KeyEncipherment");
            if(ku&CERT_DATA_ENCIPHERMENT_KEY_USAGE) wcscat(kuStr,L" DataEncipherment");
            if(ku&CERT_KEY_AGREEMENT_KEY_USAGE)     wcscat(kuStr,L" KeyAgreement");
            if(ku&CERT_KEY_CERT_SIGN_KEY_USAGE)     wcscat(kuStr,L" CertSign");
            if(ku&CERT_CRL_SIGN_KEY_USAGE)          wcscat(kuStr,L" CRLSign");
            ADD(hParent,kuStr,2,COL_DEFAULT);
        }
    }

    /* ── Extended Key Usage ── */
    AddEKUs(hParent, px);

    /* ── Subject Alternative Names ── */
    AddSANs(hParent, px);

    /* ── Basic Constraints ── */
    {
        PCERT_EXTENSION ext = CertFindExtension(
            szOID_BASIC_CONSTRAINTS2,
            px->pCertInfo->cExtension,
            px->pCertInfo->rgExtension);
        if(!ext) ext = CertFindExtension(
            szOID_BASIC_CONSTRAINTS,
            px->pCertInfo->cExtension,
            px->pCertInfo->rgExtension);
        if(ext){
            DWORD cb=0; CERT_BASIC_CONSTRAINTS2_INFO *bc=NULL;
            if(CryptDecodeObjectEx(X509_ASN_ENCODING,X509_BASIC_CONSTRAINTS2,
                                    ext->Value.pbData,ext->Value.cbData,
                                    CRYPT_DECODE_ALLOC_FLAG,NULL,&bc,&cb)){
                if(bc->fCA){
                    if(bc->fPathLenConstraint)
                        swprintf_s(lbl,511,L"CA: YES  (path length \u2264 %u)",
                                   bc->dwPathLenConstraint);
                    else
                        wcscpy(lbl,L"CA: YES  (no path length constraint)");
                    ADD(hParent,lbl,3,COL_HARDWARE);
                } else {
                    ADD(hParent,L"CA: NO  (end-entity certificate)",2,COL_DEFAULT);
                }
                LocalFree(bc);
            }
        }
    }

    /* ── OCSP / CA Issuers ── */
    AddAIA(hParent, px);

    /* ── CRL Distribution Points ── */
    AddCDPs(hParent, px);

    /* ── Subject Key Identifier ── */
    {
        PCERT_EXTENSION ext = CertFindExtension(
            szOID_SUBJECT_KEY_IDENTIFIER,
            px->pCertInfo->cExtension,
            px->pCertInfo->rgExtension);
        if(ext){
            DWORD cb=0; CRYPT_DATA_BLOB *ski=NULL;
            if(CryptDecodeObjectEx(X509_ASN_ENCODING,szOID_SUBJECT_KEY_IDENTIFIER,
                                    ext->Value.pbData,ext->Value.cbData,
                                    CRYPT_DECODE_ALLOC_FLAG,NULL,&ski,&cb)){
                wchar_t hex[64]={0};
                DWORD show=ski->cbData<20?ski->cbData:20;
                for(DWORD i=0;i<show;i++) swprintf_s(hex+i*2,3,L"%02X",ski->pbData[i]);
                swprintf_s(lbl,511,L"Subject Key ID: %s",hex);
                ADD(hParent,lbl,2,COL_DEFAULT);
                LocalFree(ski);
            }
        }
    }

    /* ── Signature algorithm ── */
    {
        wchar_t sigAlg[128]=L"";
        if(px->pCertInfo->SignatureAlgorithm.pszObjId)
            OidFriendly(px->pCertInfo->SignatureAlgorithm.pszObjId,sigAlg,127);
        if(sigAlg[0]){
            swprintf_s(lbl,511,L"Signature alg: %s",sigAlg);
            ADD(hParent,lbl,2,COL_DEFAULT);
        }
    }

    /* ── Has private key? ── */
    {
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey=0; DWORD keySpec=0; BOOL fFree=FALSE;
        if(CryptAcquireCertificatePrivateKey(px,
                CRYPT_ACQUIRE_SILENT_FLAG|CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
                NULL,&hKey,&keySpec,&fFree)){
            ADD(hParent,L"Private key: YES  \u2714  (key pair present in this store)",
                3,COL_GOOD);
            if(fFree){
                if(keySpec==CERT_NCRYPT_KEY_SPEC) NCryptFreeObject(hKey);
                else CryptReleaseContext(hKey,0);
            }
        }
    }
}

static void LoadCerts(HTREEITEM hRoot)
{
    struct{const wchar_t *id,*lbl;}st[]={
        {L"MY",L"Personal  (MY)"},{L"CA",L"Intermediate CA"},{L"ROOT",L"Trusted Root CA"}};
    HTREEITEM hC=ADD(hRoot,L"Windows Certificate Store",0,COL_HEADER);
    for(int s=0;s<3;s++){
        HCERTSTORE hSt=CertOpenSystemStoreW(0,st[s].id);
        if(!hSt) continue;
        HTREEITEM hSN=ADD(hC,st[s].lbl,0,COL_DEFAULT);
        PCCERT_CONTEXT px=NULL; int cnt=0;
        while((px=CertEnumCertificatesInStore(hSt,px))){
            BYTE ku=0;
            BOOL hku=CertGetIntendedKeyUsage(X509_ASN_ENCODING,px->pCertInfo,&ku,1);
            if(hku&&!(ku&(CERT_DIGITAL_SIGNATURE_KEY_USAGE|
                           CERT_KEY_CERT_SIGN_KEY_USAGE|CERT_CRL_SIGN_KEY_USAGE))) continue;

            /* Subject name as node label */
            wchar_t sj[256]=L"?";
            CertGetNameStringW(px,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,NULL,sj,255);

            /* Expiry colour for the node itself */
            int col = CertExpiryColor(&px->pCertInfo->NotAfter);
            HTREEITEM hCC = ADD(hSN,sj,1,col);

            /* Issuer name directly under node (quick glance) */
            wchar_t iss[256]=L"?";
            CertGetNameStringW(px,CERT_NAME_SIMPLE_DISPLAY_TYPE,
                               CERT_NAME_ISSUER_FLAG,NULL,iss,255);
            wchar_t issLbl[280];
            swprintf_s(issLbl,279,L"Issuer: %s",iss);
            ADD(hCC,issLbl,2,COL_DEFAULT);

            /* All the rich detail */
            AddCertDetail(hCC, px);

            cnt++;
        }
        CertCloseStore(hSt,0);
        if(!cnt) ADD(hSN,L"(no signing certs)",2,COL_WARN);
        else SendMessage(g_hTree,TVM_EXPAND,TVE_EXPAND,(LPARAM)hSN);
    }
    SendMessage(g_hTree,TVM_EXPAND,TVE_EXPAND,(LPARAM)hC);
}

/* ── Save baseline command ──────────────────────────────── */
static void SaveBaselineCmd(void)
{
    typedef struct { UINT32 version; UINT32 grbitConn; } TBS_CP;
    typedef UINT32 (WINAPI *PFN_CC)(TBS_CP*,void**);
    typedef UINT32 (WINAPI *PFN_CL)(void*);
    typedef UINT32 (WINAPI *PFN_SC)(void*,UINT32,UINT32,const BYTE*,UINT32,BYTE*,UINT32*);

    HMODULE hTbs = LoadLibraryW(L"tbs.dll");
    if(!hTbs){ MessageBoxW(g_hWnd,L"tbs.dll not found",L"Error",MB_ICONERROR); return; }
    PFN_CC fnCreate = (PFN_CC)GetProcAddress(hTbs,"Tbsi_Context_Create");
    PFN_CL fnClose  = (PFN_CL)GetProcAddress(hTbs,"Tbsip_Context_Close");
    PFN_SC fnSubmit = (PFN_SC)GetProcAddress(hTbs,"Tbsip_Submit_Command");
    if(!fnCreate||!fnClose||!fnSubmit){
        FreeLibrary(hTbs);
        MessageBoxW(g_hWnd,L"TBS functions not available",L"Error",MB_ICONERROR);
        return;
    }
    void *hCtx=NULL;
    TBS_CP p={2,4}; if(fnCreate(&p,&hCtx)!=0||!hCtx){ TBS_CP p2={1,0}; fnCreate(&p2,&hCtx); }
    if(!hCtx){ FreeLibrary(hTbs); MessageBoxW(g_hWnd,L"Could not open TBS context",L"Error",MB_ICONERROR); return; }

    BYTE newBase[PCR_COUNT][PCR_HASH_LEN]={0};
    BOOL gotAny=FALSE;

    for(int chunk=0;chunk<3;chunk++){
        BYTE mask[3]={0,0,0}; mask[chunk]=0xFF;
        BYTE cmd[20];
        cmd[0]=0x80;cmd[1]=0x01; cmd[2]=0x00;cmd[3]=0x00;cmd[4]=0x00;cmd[5]=0x14;
        cmd[6]=0x00;cmd[7]=0x00;cmd[8]=0x01;cmd[9]=0x7E;
        cmd[10]=0x00;cmd[11]=0x00;cmd[12]=0x00;cmd[13]=0x01;
        cmd[14]=0x00;cmd[15]=0x0B;
        cmd[16]=0x03; cmd[17]=mask[0];cmd[18]=mask[1];cmd[19]=mask[2];

        BYTE rsp[4096]={0}; UINT32 rspSz=sizeof(rsp);
        if(fnSubmit(hCtx,0,0,cmd,20,rsp,&rspSz)!=0||rspSz<10) continue;
        UINT32 rc=((UINT32)rsp[6]<<24)|((UINT32)rsp[7]<<16)|((UINT32)rsp[8]<<8)|rsp[9];
        if(rc!=0) continue;

        DWORD off=10+4;
        if(off+4>rspSz) continue;
        UINT32 selCount=((UINT32)rsp[off]<<24)|((UINT32)rsp[off+1]<<16)|((UINT32)rsp[off+2]<<8)|rsp[off+3]; off+=4;
        for(UINT32 s=0;s<selCount;s++){ if(off+4>rspSz)break; BYTE szS=rsp[off+2]; off+=2+1+szS; }
        if(off+4>rspSz) continue;
        UINT32 dc=((UINT32)rsp[off]<<24)|((UINT32)rsp[off+1]<<16)|((UINT32)rsp[off+2]<<8)|rsp[off+3]; off+=4;
        for(UINT32 d=0;d<dc&&d<8;d++){
            if(off+2>rspSz) break;
            WORD sz=((WORD)rsp[off]<<8)|rsp[off+1]; off+=2;
            if(sz==0||off+sz>rspSz) break;
            int idx=chunk*8+(int)d;
            if(idx<PCR_COUNT&&sz<=PCR_HASH_LEN){ memcpy(newBase[idx],rsp+off,sz); gotAny=TRUE; }
            off+=sz;
        }
    }
    fnClose(hCtx); FreeLibrary(hTbs);

    if(!gotAny){ MessageBoxW(g_hWnd,L"Could not read PCR values",L"Error",MB_ICONERROR); return; }

    SaveBaseline(newBase);
    g_baselineDirty=FALSE;

    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t msg[200];
    swprintf_s(msg,199,
        L"Baseline saved  \u2714  (%04d-%02d-%02d %02d:%02d:%02d)  \u2014 refresh to compare",
        st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond);
    SetStatusMsg(msg);
}

static void SnapshotTree(void); /* forward decl */

static void Populate(void)
{
    /* Disable refresh button while loading */
    EnableWindow(GetDlgItem(g_hWnd, ID_REFRESH), FALSE);
    SetStatusMsg(L"Loading\u2026");

    SendMessage(g_hTree,WM_SETREDRAW,FALSE,0);
    TreeView_DeleteAllItems(g_hTree);
    HTREEITEM hR=AddItem(g_hTree,TVI_ROOT,L"Signing Keys & Trust Anchors",0,COL_HEADER);
    LoadGPG(hR);
    LoadSSH(hR);
    LoadCerts(hR);
    LoadNCrypt(hR);
    LoadTPM(hR);
    LoadSecureBoot(hR);
    LoadTCGLog(hR);
    SendMessage(g_hTree,TVM_EXPAND,TVE_EXPAND,(LPARAM)hR);
    SendMessage(g_hTree,WM_SETREDRAW,TRUE,0);
    InvalidateRect(g_hTree,NULL,TRUE);

    SnapshotTree();

    /* Update all three status panels */
    int count = CountTreeItems();
    SetStatusCount(count);
    SetStatusTime();

    /* Only set default message if no warning was already posted */
    wchar_t cur[256]={0};
    SendMessage(g_hStatus, SB_GETTEXT, SB_PANEL_MSG, (LPARAM)cur);
    if(cur[0]==0 || wcscmp(cur,L"Loading\u2026")==0)
        SetStatusMsg(L"Ready  \u2502  F5=Refresh  Ctrl+F=Search  Ctrl+E=Expand  Ctrl+W=Collapse");

    EnableWindow(GetDlgItem(g_hWnd, ID_REFRESH), TRUE);
}

/* ── Tree snapshot / search ─────────────────────────────── */
#define MAX_NODES 4096

typedef struct {
    wchar_t  text[512];
    int      img;
    int      col;
    int      depth;
} NodeSnapshot;

static NodeSnapshot g_snap[MAX_NODES];
static int          g_snapCount = 0;

static void SnapshotTree(void)
{
    g_snapCount = 0;
    typedef struct { HTREEITEM h; int depth; } Frame;
    Frame stack[256]; int top = 0;

    HTREEITEM root = TreeView_GetRoot(g_hTree);
    if(root){ stack[top].h=root; stack[top].depth=0; top++; }

    while(top > 0 && g_snapCount < MAX_NODES){
        Frame f = stack[--top];
        wchar_t buf[512]={0};
        TVITEMW it={0}; it.hItem=f.h; it.mask=TVIF_TEXT|TVIF_IMAGE|TVIF_PARAM;
        it.pszText=buf; it.cchTextMax=511;
        SendMessage(g_hTree,TVM_GETITEMW,0,(LPARAM)&it);

        NodeSnapshot *sn = &g_snap[g_snapCount++];
        wcsncpy(sn->text, buf, 511);
        sn->img   = it.iImage;
        sn->col   = (int)it.lParam;
        sn->depth = f.depth;

        HTREEITEM sib = TreeView_GetNextSibling(g_hTree, f.h);
        if(sib){ stack[top].h=sib; stack[top].depth=f.depth; top++; }
        HTREEITEM ch = TreeView_GetChild(g_hTree, f.h);
        if(ch){ stack[top].h=ch; stack[top].depth=f.depth+1; top++; }
    }
}

static void RebuildFromSnapshot(const wchar_t *needle)
{
    wchar_t lneedle[512]={0};
    wcsncpy(lneedle, needle, 511);
    for(wchar_t *c=lneedle;*c;c++) *c=towlower(*c);
    BOOL filtering = (lneedle[0] != 0);

    BOOL matches[MAX_NODES]={0};
    for(int i=0; i<g_snapCount; i++){
        wchar_t lo[512]={0}; wcsncpy(lo,g_snap[i].text,511);
        for(wchar_t *c=lo;*c;c++) *c=towlower(*c);
        matches[i] = !filtering || (wcsstr(lo,lneedle)!=NULL);
    }
    for(int i=g_snapCount-1; i>=0; i--){
        if(matches[i] && g_snap[i].depth > 0){
            for(int j=i-1; j>=0; j--){
                if(g_snap[j].depth == g_snap[i].depth-1){
                    matches[j]=TRUE; break;
                }
            }
        }
    }

    SendMessage(g_hTree,WM_SETREDRAW,FALSE,0);
    TreeView_DeleteAllItems(g_hTree);

    HTREEITEM parentStack[16];
    memset(parentStack,0,sizeof(parentStack));
    parentStack[0] = TVI_ROOT;

    for(int i=0; i<g_snapCount; i++){
        if(!matches[i]) continue;
        int d = g_snap[i].depth;
        HTREEITEM parent = (d>0) ? parentStack[d-1] : TVI_ROOT;
        if(!parent) parent = TVI_ROOT;
        HTREEITEM h = AddItem(g_hTree, parent,
                              g_snap[i].text, g_snap[i].img, g_snap[i].col);
        parentStack[d] = h;
        if(filtering && d < 3)
            SendMessage(g_hTree,TVM_EXPAND,TVE_EXPAND,(LPARAM)h);
    }

    SendMessage(g_hTree,WM_SETREDRAW,TRUE,0);
    InvalidateRect(g_hTree,NULL,TRUE);
}

static void DoSearch(void)
{
    wchar_t needle[256]={0};
    GetWindowTextW(g_hSearch,needle,255);
    if(g_snapCount == 0) return;
    RebuildFromSnapshot(needle);

    wchar_t status[300];
    if(needle[0]){
        swprintf_s(status,299,L"Filter: \"%s\"  \u2014  Esc to clear",needle);
        /* Highlight search box background when filtering */
    } else {
        wcscpy(status,L"Ready  \u2502  F5=Refresh  Ctrl+F=Search  Ctrl+E=Expand  Ctrl+W=Collapse");
    }
    SetStatusMsg(status);
}

static void ClearSearch(void)
{
    SetWindowTextW(g_hSearch, L"");
    DoSearch();
    SetFocus(g_hTree);
}

static void CopySelected(void)
{
    HTREEITEM hSel=TreeView_GetSelection(g_hTree);
    if(!hSel) return;
    wchar_t buf[512]={0};
    TVITEMW it={0};it.hItem=hSel;it.mask=TVIF_TEXT;
    it.pszText=buf;it.cchTextMax=511;
    SendMessage(g_hTree,TVM_GETITEMW,0,(LPARAM)&it);
    if(!OpenClipboard(g_hWnd)) return;
    EmptyClipboard();
    size_t bytes=(wcslen(buf)+1)*sizeof(wchar_t);
    HGLOBAL hM=GlobalAlloc(GMEM_MOVEABLE,bytes);
    if(hM){memcpy(GlobalLock(hM),buf,bytes);GlobalUnlock(hM);SetClipboardData(CF_UNICODETEXT,hM);}
    CloseClipboard();
    SetStatusMsg(L"Copied to clipboard  \u2714");
}

/* ── Custom draw (colors + splitter hover highlight) ──── */
static LRESULT HandleCustomDraw(NMTVCUSTOMDRAW *cd)
{
    switch(cd->nmcd.dwDrawStage){
    case CDDS_PREPAINT:  return CDRF_NOTIFYITEMDRAW;
    case CDDS_ITEMPREPAINT:{
        int col=(int)cd->nmcd.lItemlParam;
        if(col>=0&&col<(int)(sizeof(g_colors)/sizeof(g_colors[0])))
            cd->clrText=g_colors[col];
        /* Slightly tint selected items */
        if(cd->nmcd.uItemState & CDIS_SELECTED)
            cd->clrTextBk = RGB(220, 235, 255);
        return CDRF_DODEFAULT;
    }}
    return CDRF_DODEFAULT;
}

/* ── Image list ─────────────────────────────────────────── */
static HIMAGELIST MakeIL(void)
{
    HIMAGELIST h=ImageList_Create(16,16,ILC_COLOR32|ILC_MASK,4,0);
    COLORREF c[]={RGB(70,130,180),RGB(255,185,0),RGB(80,180,80),RGB(200,60,60)};
    HDC hDC=GetDC(NULL);
    for(int i=0;i<4;i++){
        HDC m=CreateCompatibleDC(hDC);
        HBITMAP b=CreateCompatibleBitmap(hDC,16,16);
        HGDIOBJ o=SelectObject(m,b);
        HBRUSH br=CreateSolidBrush(c[i]);
        RECT r={2,2,14,14};FillRect(m,&r,br);DeleteObject(br);
        SelectObject(m,o);ImageList_Add(h,b,NULL);
        DeleteObject(b);DeleteDC(m);
    }
    ReleaseDC(NULL,hDC);
    return h;
}

/* ── Layout ─────────────────────────────────────────────── */
static void DoLayout(int W,int H)
{
    if(g_splitX<=0) g_splitX=DETAIL_DEF;
    if(g_splitX>W-100) g_splitX=W-100;

    int treeW=W-g_splitX-SPLITTER_W;
    int detW=g_splitX;

    /* Status bar height */
    RECT sr; GetWindowRect(g_hStatus,&sr);
    int sbH=sr.bottom-sr.top;
    int contentH=H-TOOLBAR_H-sbH;

    SetWindowPos(g_hTree,NULL,0,TOOLBAR_H,treeW,contentH,SWP_NOZORDER);
    SetWindowPos(g_hSplitter,NULL,treeW,TOOLBAR_H,SPLITTER_W,contentH,SWP_NOZORDER);
    SetWindowPos(g_hDetail,NULL,treeW+SPLITTER_W,TOOLBAR_H,detW,contentH,SWP_NOZORDER);
    SendMessage(g_hStatus,WM_SIZE,0,0);

    /* Resize status bar panels: message takes majority, count=120, time=160 */
    int parts[3];
    parts[2] = W;
    parts[1] = W - 160;
    parts[0] = W - 160 - 120;
    SendMessage(g_hStatus, SB_SETPARTS, 3, (LPARAM)parts);
}

/* ── Detail pane update ─────────────────────────────────── */
static void UpdateDetail(HTREEITEM hSel)
{
    if(!hSel){SetWindowTextW(g_hDetail,L"");return;}

    DWORD cap  = 32768;
    DWORD used = 0;
    wchar_t *buf = (wchar_t*)malloc(cap * sizeof(wchar_t));
    if(!buf) return;
    buf[0] = L'\0';

    wchar_t tmp[512] = {0};
    TVITEMW it = {0};
    it.mask       = TVIF_TEXT;
    it.pszText    = tmp;
    it.cchTextMax = 511;

#define DETAPPEND(prefix, str) do { \
    DWORD need = used + (DWORD)wcslen(prefix) + (DWORD)wcslen(str) + 3; \
    if(need >= cap) { \
        cap = need * 2 + 4096; \
        wchar_t *nb = (wchar_t*)realloc(buf, cap*sizeof(wchar_t)); \
        if(!nb){free(buf);return;} buf=nb; \
    } \
    wcscat(buf, prefix); wcscat(buf, str); wcscat(buf, L"\r\n"); \
    used = (DWORD)wcslen(buf); \
} while(0)

    tmp[0]=0; it.hItem=hSel;
    SendMessage(g_hTree,TVM_GETITEMW,0,(LPARAM)&it);
    DETAPPEND(L"\u25B6 ", tmp);
    DETAPPEND(L"", L"\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500");

    int total = 0;
    HTREEITEM ch = TreeView_GetChild(g_hTree, hSel);
    while(ch && total < 500){
        tmp[0]=0; it.hItem=ch;
        SendMessage(g_hTree,TVM_GETITEMW,0,(LPARAM)&it);
        DETAPPEND(L"  ", tmp);
        total++;

        HTREEITEM gc = TreeView_GetChild(g_hTree, ch);
        while(gc && total < 500){
            tmp[0]=0; it.hItem=gc;
            SendMessage(g_hTree,TVM_GETITEMW,0,(LPARAM)&it);
            DETAPPEND(L"    ", tmp);
            total++;
            gc = TreeView_GetNextSibling(g_hTree, gc);
        }
        ch = TreeView_GetNextSibling(g_hTree, ch);
    }
    if(total >= 500)
        DETAPPEND(L"  ", L"\u2026 (truncated \u2014 click individual entries to see more)");

#undef DETAPPEND

    SetWindowTextW(g_hDetail, buf);
    free(buf);
}

/* ── Splitter custom paint (hover highlight) ─────────────── */
static LRESULT CALLBACK SplitterProc(HWND hWnd, UINT msg, WPARAM wP, LPARAM lP)
{
    switch(msg){
    case WM_PAINT:{
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        RECT rc; GetClientRect(hWnd, &rc);
        COLORREF col = g_dragging ? RGB(0,120,215)
                     : g_splitterHot ? RGB(100,180,240)
                     : RGB(210,210,210);
        HBRUSH br = CreateSolidBrush(col);
        FillRect(hdc, &rc, br);
        DeleteObject(br);
        EndPaint(hWnd, &ps);
        return 0;
    }
    case WM_MOUSEMOVE:{
        if(!g_splitterHot){
            g_splitterHot = TRUE;
            InvalidateRect(hWnd, NULL, TRUE);
            TRACKMOUSEEVENT tme={sizeof(tme),TME_LEAVE,hWnd,0};
            TrackMouseEvent(&tme);
        }
        return 0;
    }
    case WM_MOUSELEAVE:
        g_splitterHot = FALSE;
        InvalidateRect(hWnd, NULL, TRUE);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wP, lP);
}

/* ── Main window procedure ──────────────────────────────── */
static LRESULT CALLBACK WndProc(HWND hWnd,UINT msg,WPARAM wP,LPARAM lP)
{
    switch(msg){
    case WM_CREATE:{
        g_hWnd=hWnd;

        /* ── Toolbar buttons ── */
        int x = 4;

        CreateWindowW(L"BUTTON",L"\u21BA Refresh",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            x,BTN_Y,90,BTN_H,hWnd,(HMENU)ID_REFRESH,NULL,NULL);
        x += 94;

        CreateWindowW(L"BUTTON",L"Copy",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            x,BTN_Y,60,BTN_H,hWnd,(HMENU)ID_COPYKEY,NULL,NULL);
        x += 64;

        CreateWindowW(L"BUTTON",L"Save Baseline",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            x,BTN_Y,110,BTN_H,hWnd,(HMENU)ID_BASELINE,NULL,NULL);
        x += 118;

        /* Visual separator */
        CreateWindowW(L"STATIC",L"",WS_CHILD|WS_VISIBLE|SS_ETCHEDVERT,
            x,BTN_Y+2,2,BTN_H-4,hWnd,(HMENU)-1,NULL,NULL);
        x += 10;

        CreateWindowW(L"BUTTON",L"+ All",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            x,BTN_Y,55,BTN_H,hWnd,(HMENU)ID_EXPANDALL,NULL,NULL);
        x += 59;

        CreateWindowW(L"BUTTON",L"\u2212 All",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            x,BTN_Y,55,BTN_H,hWnd,(HMENU)ID_COLLAPSEALL,NULL,NULL);
        x += 63;

        /* Visual separator */
        CreateWindowW(L"STATIC",L"",WS_CHILD|WS_VISIBLE|SS_ETCHEDVERT,
            x,BTN_Y+2,2,BTN_H-4,hWnd,(HMENU)-1,NULL,NULL);
        x += 10;

        CreateWindowW(L"BUTTON",L"Wrap",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            x,BTN_Y,50,BTN_H,hWnd,(HMENU)ID_WORDWRAP,NULL,NULL);
        x += 54;

        CreateWindowW(L"BUTTON",L"A+",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            x,BTN_Y,36,BTN_H,hWnd,(HMENU)ID_FONTPLUS,NULL,NULL);
        x += 38;

        CreateWindowW(L"BUTTON",L"A-",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            x,BTN_Y,36,BTN_H,hWnd,(HMENU)ID_FONTMINUS,NULL,NULL);
        x += 44;

        /* Visual separator */
        CreateWindowW(L"STATIC",L"",WS_CHILD|WS_VISIBLE|SS_ETCHEDVERT,
            x,BTN_Y+2,2,BTN_H-4,hWnd,(HMENU)-1,NULL,NULL);
        x += 8;

        CreateWindowW(L"STATIC",L"\U0001F50D",WS_CHILD|WS_VISIBLE|SS_CENTERIMAGE,
            x,BTN_Y,20,BTN_H,hWnd,(HMENU)-1,NULL,NULL);
        x += 20;

        g_hSearch=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",
            WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,
            x,BTN_Y+2,180,BTN_H-4,hWnd,(HMENU)ID_SEARCH,NULL,NULL);
        /* Cue banner — "Search keys…" placeholder text */
        SendMessage(g_hSearch, EM_SETCUEBANNER, TRUE,
                    (LPARAM)L"Search keys\u2026");

        /* Custom splitter window for hover effects */
        WNDCLASSEXW sc={0};
        sc.cbSize=sizeof(sc); sc.lpfnWndProc=SplitterProc;
        sc.hInstance=GetModuleHandleW(NULL);
        sc.hCursor=LoadCursor(NULL,IDC_SIZEWE);
        sc.hbrBackground=NULL;
        sc.lpszClassName=L"KVSplitter";
        RegisterClassExW(&sc);

        g_hSplitter=CreateWindowW(L"KVSplitter",L"",
            WS_CHILD|WS_VISIBLE,
            0,0,SPLITTER_W,100,hWnd,(HMENU)ID_SPLITTER,
            GetModuleHandleW(NULL),NULL);

        g_hTree=CreateWindowExW(WS_EX_CLIENTEDGE,WC_TREEVIEWW,L"",
            WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_HSCROLL|
            TVS_HASLINES|TVS_LINESATROOT|TVS_HASBUTTONS|
            TVS_SHOWSELALWAYS|TVS_FULLROWSELECT,
            0,TOOLBAR_H,600,500,hWnd,(HMENU)ID_TREEVIEW,NULL,NULL);
        TreeView_SetImageList(g_hTree,MakeIL(),TVSIL_NORMAL);

        /* Increase tree item row height slightly for readability */
        SendMessage(g_hTree, TVM_SETITEMHEIGHT, 20, 0);

        g_hDetail=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",
            WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_HSCROLL|
            ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|ES_AUTOHSCROLL,
            0,TOOLBAR_H,300,500,hWnd,(HMENU)ID_DETAIL,NULL,NULL);

        RebuildDetailFont();

        /* 3-panel status bar */
        g_hStatus=CreateWindowExW(0,STATUSCLASSNAMEW,NULL,
            WS_CHILD|WS_VISIBLE|SBARS_SIZEGRIP,
            0,0,0,0,hWnd,(HMENU)ID_STATUSBAR,NULL,NULL);

        g_splitX=DETAIL_DEF;
        UpdateWindowTitle();
        Populate();
        return 0;
    }

    case WM_SIZE:
        DoLayout(LOWORD(lP),HIWORD(lP));
        return 0;

    case WM_COMMAND:
        if(LOWORD(wP)==ID_REFRESH)      Populate();
        else if(LOWORD(wP)==ID_COPYKEY) CopySelected();
        else if(LOWORD(wP)==ID_BASELINE)SaveBaselineCmd();
        else if(LOWORD(wP)==ID_EXPANDALL)   DoExpandAll();
        else if(LOWORD(wP)==ID_COLLAPSEALL) DoCollapseAll();
        else if(LOWORD(wP)==ID_WORDWRAP)    ToggleWordWrap();
        else if(LOWORD(wP)==ID_FONTPLUS){
            if(g_detailFontSize < 24){ g_detailFontSize++; RebuildDetailFont(); }
        }
        else if(LOWORD(wP)==ID_FONTMINUS){
            if(g_detailFontSize > 8){ g_detailFontSize--; RebuildDetailFont(); }
        }
        else if(LOWORD(wP)==ID_SEARCH&&HIWORD(wP)==EN_CHANGE) DoSearch();
        return 0;

    case WM_KEYDOWN:{
        /* Global keyboard shortcuts */
        BOOL ctrl  = (GetKeyState(VK_CONTROL)&0x8000) != 0;
        BOOL shift = (GetKeyState(VK_SHIFT)   &0x8000) != 0;

        if(wP==VK_F5)                        { Populate(); return 0; }
        if(ctrl && wP=='C' && !shift)        { CopySelected(); return 0; }
        if(ctrl && wP=='F')                  { SetFocus(g_hSearch); return 0; }
        if(ctrl && wP=='E')                  { DoExpandAll(); return 0; }
        if(ctrl && wP=='W')                  { DoCollapseAll(); return 0; }
        if(ctrl && wP=='S')                  { SaveBaselineCmd(); return 0; }
        if(wP==VK_ESCAPE && GetFocus()==g_hSearch) { ClearSearch(); return 0; }
        break;
    }

    case WM_NOTIFY:{
        NMHDR *nm=(NMHDR*)lP;
        if(nm->idFrom==ID_TREEVIEW){
            if(nm->code==NM_DBLCLK) CopySelected();
            if(nm->code==NM_CUSTOMDRAW)
                return HandleCustomDraw((NMTVCUSTOMDRAW*)lP);
            if(nm->code==TVN_SELCHANGEDW){
                NMTREEVIEWW *ntv=(NMTREEVIEWW*)lP;
                UpdateDetail(ntv->itemNew.hItem);
            }
        }
        return 0;
    }

    case WM_LBUTTONDOWN:{
        POINT pt={LOWORD(lP),HIWORD(lP)};
        RECT r; GetWindowRect(g_hSplitter,&r);
        POINT tl={r.left,r.top}; ScreenToClient(hWnd,&tl);
        if(pt.x>=tl.x-4&&pt.x<=tl.x+SPLITTER_W+4){
            g_dragging=TRUE; SetCapture(hWnd);
            SetCursor(LoadCursor(NULL,IDC_SIZEWE));
            InvalidateRect(g_hSplitter, NULL, TRUE);
        }
        return 0;
    }
    case WM_MOUSEMOVE:
        if(g_dragging){
            RECT rc; GetClientRect(hWnd,&rc);
            int mx=LOWORD(lP);
            g_splitX=rc.right-mx-SPLITTER_W/2;
            if(g_splitX<DETAIL_MIN) g_splitX=DETAIL_MIN;
            DoLayout(rc.right,rc.bottom);
        }
        return 0;
    case WM_LBUTTONUP:
        if(g_dragging){
            g_dragging=FALSE;
            ReleaseCapture();
            InvalidateRect(g_hSplitter, NULL, TRUE);
        }
        return 0;

    case WM_SETCURSOR:{
        POINT pt; GetCursorPos(&pt); ScreenToClient(hWnd,&pt);
        RECT r; GetWindowRect(g_hSplitter,&r);
        POINT tl={r.left,r.top}; ScreenToClient(hWnd,&tl);
        if(pt.x>=tl.x-2&&pt.x<=tl.x+SPLITTER_W+2){
            SetCursor(LoadCursor(NULL,IDC_SIZEWE));return TRUE;}
        break;
    }

    case WM_DESTROY:
        if(g_detailFont) DeleteObject(g_detailFont);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd,msg,wP,lP);
}

int WINAPI WinMain(HINSTANCE hI,HINSTANCE hP,LPSTR lC,int nS)
{
    INITCOMMONCONTROLSEX icc={sizeof(icc),ICC_TREEVIEW_CLASSES|ICC_BAR_CLASSES};
    InitCommonControlsEx(&icc);
    CoInitializeEx(NULL,COINIT_APARTMENTTHREADED);
    LoadBaseline();

    WNDCLASSEXW wc={0};
    wc.cbSize=sizeof(wc); wc.lpfnWndProc=WndProc;
    wc.hInstance=hI;
    wc.hCursor=LoadCursor(NULL,IDC_ARROW);
    wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
    wc.lpszClassName=L"KeyViewerWnd2";
    wc.hIcon=LoadIcon(NULL,IDI_APPLICATION);
    RegisterClassExW(&wc);

    HWND hWnd=CreateWindowExW(0,L"KeyViewerWnd2",
        L"Key Viewer",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,CW_USEDEFAULT,1200,750,
        NULL,NULL,hI,NULL);
    ShowWindow(hWnd,nS); UpdateWindow(hWnd);

    MSG m;
    while(GetMessage(&m,NULL,0,0)){
        /* Route keyboard shortcuts through the main window */
        if(m.message==WM_KEYDOWN){
            BOOL ctrl  = (GetKeyState(VK_CONTROL)&0x8000) != 0;
            BOOL shift = (GetKeyState(VK_SHIFT)   &0x8000) != 0;

            if(m.wParam==VK_F5){
                Populate(); continue;
            }
            if(ctrl && m.wParam=='F'){
                SetFocus(g_hSearch); continue;
            }
            if(ctrl && m.wParam=='C' && !shift && GetFocus()!=g_hSearch){
                CopySelected(); continue;
            }
            if(ctrl && m.wParam=='E'){
                DoExpandAll(); continue;
            }
            if(ctrl && m.wParam=='W'){
                DoCollapseAll(); continue;
            }
            if(ctrl && m.wParam=='S'){
                SaveBaselineCmd(); continue;
            }
            if(m.wParam==VK_ESCAPE && GetFocus()==g_hSearch){
                ClearSearch(); continue;
            }
        }
        TranslateMessage(&m);
        DispatchMessage(&m);
    }
    CoUninitialize();
    return (int)m.wParam;
}