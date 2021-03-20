#ifndef UNICODE
#define UNICODE
#endif
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")

#include <codecvt>

#include <windows.h>
#include <lm.h>
#include <sddl.h>

#include <napi.h>

#pragma region helper
std::wstring s2ws(const std::string &s)
{
    /* int len;
    int slength = (int)s.length() + 1;
    len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
    wchar_t *buf = new wchar_t[len];
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
    std::wstring r(buf);
    delete[] buf;
    return r; */
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.from_bytes(s);
}
std::string ws2s(const std::wstring &s)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(s);
}
void parseFlags(const DWORD flags, Napi::Array &flagsArray)
{
    int FA_POS = 0;
    if ((flags & UF_SCRIPT) == UF_SCRIPT)
    {
        flagsArray.Set(FA_POS, "UF_SCRIPT");
        FA_POS++;
    }
    else if ((flags & UF_ACCOUNTDISABLE) == UF_ACCOUNTDISABLE)
    {
        flagsArray.Set(FA_POS, "UF_ACCOUNTDISABLE");
        FA_POS++;
    }
    else if ((flags & UF_HOMEDIR_REQUIRED) == UF_HOMEDIR_REQUIRED)
    {
        flagsArray.Set(FA_POS, "UF_HOMEDIR_REQUIRED");
        FA_POS++;
    }

    if ((flags & UF_PASSWD_NOTREQD) == UF_PASSWD_NOTREQD)
    {
        flagsArray.Set(FA_POS, "UF_PASSWD_NOTREQD");
        FA_POS++;
    }
    else if ((flags & UF_PASSWD_CANT_CHANGE) == UF_PASSWD_CANT_CHANGE)
    {
        flagsArray.Set(FA_POS, "UF_PASSWD_CANT_CHANGE");
        FA_POS++;
    }
    else if ((flags & UF_LOCKOUT) == UF_LOCKOUT)
    {
        flagsArray.Set(FA_POS, "UF_LOCKOUT");
        FA_POS++;
    }

    if ((flags & UF_DONT_EXPIRE_PASSWD) == UF_DONT_EXPIRE_PASSWD)
    {
        flagsArray.Set(FA_POS, "UF_LOCKOUT");
        FA_POS++;
    }
    if ((flags & UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED) == UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED)
    {
        flagsArray.Set(FA_POS, "UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED");
        FA_POS++;
    }
    if ((flags & UF_NOT_DELEGATED) == UF_NOT_DELEGATED)
    {
        flagsArray.Set(FA_POS, "UF_NOT_DELEGATED");
        FA_POS++;
    }
    if ((flags & UF_SMARTCARD_REQUIRED) == UF_SMARTCARD_REQUIRED)
    {
        flagsArray.Set(FA_POS, "UF_SMARTCARD_REQUIRED");
        FA_POS++;
    }
    if ((flags & UF_USE_DES_KEY_ONLY) == UF_USE_DES_KEY_ONLY)
    {
        flagsArray.Set(FA_POS, "UF_USE_DES_KEY_ONLY");
        FA_POS++;
    }
    if ((flags & UF_DONT_REQUIRE_PREAUTH) == UF_DONT_REQUIRE_PREAUTH)
    {
        flagsArray.Set(FA_POS, "UF_DONT_REQUIRE_PREAUTH");
        FA_POS++;
    }
    if ((flags & UF_TRUSTED_FOR_DELEGATION) == UF_TRUSTED_FOR_DELEGATION)
    {
        flagsArray.Set(FA_POS, "UF_TRUSTED_FOR_DELEGATION");
        FA_POS++;
    }
    if ((flags & UF_PASSWORD_EXPIRED) == UF_PASSWORD_EXPIRED)
    {
        flagsArray.Set(FA_POS, "UF_PASSWORD_EXPIRED");
        FA_POS++;
    }
    if ((flags & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION) == UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION)
    {
        flagsArray.Set(FA_POS, "UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION");
        FA_POS++;
    }

    if ((flags & UF_NORMAL_ACCOUNT) == UF_NORMAL_ACCOUNT)
    {
        flagsArray.Set(FA_POS, "UF_NORMAL_ACCOUNT");
        FA_POS++;
    }
    else if ((flags & UF_TEMP_DUPLICATE_ACCOUNT) == UF_TEMP_DUPLICATE_ACCOUNT)
    {
        flagsArray.Set(FA_POS, "UF_TEMP_DUPLICATE_ACCOUNT");
        FA_POS++;
    }
    else if ((flags & UF_WORKSTATION_TRUST_ACCOUNT) == UF_WORKSTATION_TRUST_ACCOUNT)
    {
        flagsArray.Set(FA_POS, "UF_WORKSTATION_TRUST_ACCOUNT");
        FA_POS++;
    }
    else if ((flags & UF_SERVER_TRUST_ACCOUNT) == UF_SERVER_TRUST_ACCOUNT)
    {
        flagsArray.Set(FA_POS, "UF_SERVER_TRUST_ACCOUNT");
        FA_POS++;
    }
    else if ((flags & UF_INTERDOMAIN_TRUST_ACCOUNT) == UF_INTERDOMAIN_TRUST_ACCOUNT)
    {
        flagsArray.Set(FA_POS, "UF_INTERDOMAIN_TRUST_ACCOUNT");
        FA_POS++;
    }
}
#pragma endregion
Napi::Object GetUserInfo(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    std::wstring servername;
    std::wstring username;
    DWORD level = 0;
    NET_API_STATUS nStatus;
    LPBYTE pBuf = NULL;
    Napi::Value _servername = info[0];
    Napi::Value _username = info[1];
    Napi::Value _level = info[2];

    /** arg[0] servername
    */
    if (_servername.IsString())
    {
        servername = s2ws(_servername.As<Napi::String>().Utf8Value());
    }
    else
    {
        if (!_servername.IsUndefined())
        {
            Napi::TypeError::New(env, "servername must be string or undefined.").ThrowAsJavaScriptException();
        }
    }
    /** arg[1] username
    */
    if (_username.IsString())
    {
        username = s2ws(_username.As<Napi::String>().Utf8Value());
    }
    else
    {
        Napi::TypeError::New(env, "username must be string.").ThrowAsJavaScriptException();
    }
    /** arg[2] level
    */
    if (_level.IsNumber())
    {
        level = _level.As<Napi::Number>().Uint32Value();
    }
    else
    {
        Napi::TypeError::New(env, "level must be int.").ThrowAsJavaScriptException();
    }

    nStatus = NetUserGetInfo(servername.c_str(), username.c_str(), level, &pBuf);
    Napi::Object error = Napi::Object::New(env);
    Napi::Object result = Napi::Object::New(env);
    bool hasError = false;
    LPTSTR sStringSid = NULL;
    if (nStatus == NERR_Success)
    {

        switch (level)
        {
        case 0:
        {
            LPUSER_INFO_0 pBuf0 = (LPUSER_INFO_0)pBuf;
            result.Set("name", ws2s(pBuf0->usri0_name));
        }
        break;
        case 1:
        {
            LPUSER_INFO_1 pBuf1 = (LPUSER_INFO_1)pBuf;
            result.Set("name", ws2s(pBuf1->usri1_name));
            result.Set("password", ws2s(pBuf1->usri1_password));
            result.Set("password_age", pBuf1->usri1_password_age);
            result.Set("priviilege_level", pBuf1->usri1_priv);
            result.Set("home_dir", ws2s(pBuf1->usri1_home_dir));
            result.Set("comment", ws2s(pBuf1->usri1_comment));
            result.Set("flags", pBuf1->usri1_flags);
            result.Set("script_path", ws2s(pBuf1->usri1_script_path));
        }
        break;
        case 2:
        {
            LPUSER_INFO_2 pBuf2 = (LPUSER_INFO_2)pBuf;
            result.Set("name", ws2s(pBuf2->usri2_name));
            result.Set("password", ws2s(pBuf2->usri2_password));
            result.Set("password_age", pBuf2->usri2_password_age);
            result.Set("priviilege_level", pBuf2->usri2_priv);
            result.Set("home_dir", ws2s(pBuf2->usri2_home_dir));
            result.Set("comment", ws2s(pBuf2->usri2_comment));
            result.Set("flags", pBuf2->usri2_flags);
            result.Set("script_path", ws2s(pBuf2->usri2_script_path));
            result.Set("auth_flags", pBuf2->usri2_auth_flags);

            result.Set("full_name", ws2s(pBuf2->usri2_full_name));
            result.Set("usr_comment", ws2s(pBuf2->usri2_usr_comment));
            result.Set("parms", ws2s(pBuf2->usri2_parms));
            result.Set("workstations", ws2s(pBuf2->usri2_workstations));

            result.Set("last_logon", pBuf2->usri2_last_logon);
            result.Set("last_logoff", pBuf2->usri2_last_logoff);
            result.Set("acct_expires", pBuf2->usri2_acct_expires);

            result.Set("max_storage", pBuf2->usri2_max_storage);
            result.Set("units_per_week", pBuf2->usri2_units_per_week);

            /**parse Logon Hours*/
            Napi::Array logon_hours = Napi::Array::New(env, 21);

            for (int j = 0; j < 21; j++)
            {
                logon_hours[j] = (BYTE)pBuf2->usri2_logon_hours[j];
            }
            result.Set("logon_hours", logon_hours);
            /***/
            result.Set("bad_pw_count", pBuf2->usri2_bad_pw_count);

            result.Set("num_logons", pBuf2->usri2_num_logons);

            result.Set("logon_server", ws2s(pBuf2->usri2_logon_server));

            result.Set("country_code", pBuf2->usri2_country_code);
            result.Set("code_page", pBuf2->usri2_code_page);
        }
        break;
        case 4:
        {
            /* LPUSER_INFO_4 pBuf4 = (LPUSER_INFO_4)pBuf;
            wprintf(L"\tUser account name: %s\n", pBuf4->usri4_name);
            wprintf(L"\tPassword: %s\n", pBuf4->usri4_password);
            wprintf(L"\tPassword age (seconds): %d\n",
                    pBuf4->usri4_password_age);
            wprintf(L"\tPrivilege level: %d\n", pBuf4->usri4_priv);
            wprintf(L"\tHome directory: %s\n", pBuf4->usri4_home_dir);
            wprintf(L"\tComment: %s\n", pBuf4->usri4_comment);
            wprintf(L"\tFlags (in hex): %x\n", pBuf4->usri4_flags);
            wprintf(L"\tScript path: %s\n", pBuf4->usri4_script_path);
            wprintf(L"\tAuth flags (in hex): %x\n",
                    pBuf4->usri4_auth_flags);
            wprintf(L"\tFull name: %s\n", pBuf4->usri4_full_name);
            wprintf(L"\tUser comment: %s\n", pBuf4->usri4_usr_comment);
            wprintf(L"\tParameters: %s\n", pBuf4->usri4_parms);
            wprintf(L"\tWorkstations: %s\n", pBuf4->usri4_workstations);
            wprintf(L"\tLast logon (seconds since January 1, 1970 GMT): %d\n",
                    pBuf4->usri4_last_logon);
            wprintf(L"\tLast logoff (seconds since January 1, 1970 GMT): %d\n",
                    pBuf4->usri4_last_logoff);
            wprintf(L"\tAccount expires (seconds since January 1, 1970 GMT): %d\n",
                    pBuf4->usri4_acct_expires);
            wprintf(L"\tMax storage: %d\n", pBuf4->usri4_max_storage);
            wprintf(L"\tUnits per week: %d\n",
                    pBuf4->usri4_units_per_week);
            wprintf(L"\tLogon hours:");
            for (int j = 0; j < 21; j++)
            {
                printf(" %x", (BYTE)pBuf4->usri4_logon_hours[j]);
            }
            wprintf(L"\n");
            wprintf(L"\tBad password count: %d\n",
                    pBuf4->usri4_bad_pw_count);
            wprintf(L"\tNumber of logons: %d\n",
                    pBuf4->usri4_num_logons);
            wprintf(L"\tLogon server: %s\n", pBuf4->usri4_logon_server);
            wprintf(L"\tCountry code: %d\n", pBuf4->usri4_country_code);
            wprintf(L"\tCode page: %d\n", pBuf4->usri4_code_page);
            if (ConvertSidToStringSid(pBuf4->usri4_user_sid, &sStringSid))
            {
                wprintf(L"\tUser SID: %s\n", sStringSid);
                LocalFree(sStringSid);
            }
            else
                wprintf(L"ConvertSidToSTringSid failed with error %d\n",
                        GetLastError());
            wprintf(L"\tPrimary group ID: %d\n",
                    pBuf4->usri4_primary_group_id);
            wprintf(L"\tProfile: %s\n", pBuf4->usri4_profile);
            wprintf(L"\tHome directory drive letter: %s\n",
                    pBuf4->usri4_home_dir_drive);
            wprintf(L"\tPassword expired information: %d\n",
                    pBuf4->usri4_password_expired); */
        }
        break;
        case 10:
        {
           /*  LPUSER_INFO_10 pBuf10 = (LPUSER_INFO_10)pBuf;
            wprintf(L"\tUser account name: %s\n", pBuf10->usri10_name);
            wprintf(L"\tComment: %s\n", pBuf10->usri10_comment);
            wprintf(L"\tUser comment: %s\n",
                    pBuf10->usri10_usr_comment);
            wprintf(L"\tFull name: %s\n", pBuf10->usri10_full_name); */
        }
        break;

        case 11:
        {

            LPUSER_INFO_11 pBuf11 = (LPUSER_INFO_11)pBuf;
            result.Set("name", ws2s(pBuf11->usri11_name));
            result.Set("comment", ws2s(pBuf11->usri11_comment));
            result.Set("usr_comment", ws2s(pBuf11->usri11_usr_comment));
            result.Set("full_name", ws2s(pBuf11->usri11_full_name));

            result.Set("priv", pBuf11->usri11_priv); //TODO:
            result.Set("auth_flags", pBuf11->usri11_auth_flags);

            result.Set("password_age", pBuf11->usri11_password_age);

            result.Set("home_dir", ws2s(pBuf11->usri11_home_dir));
            result.Set("parms", ws2s(pBuf11->usri11_parms));

            result.Set("last_logon", pBuf11->usri11_last_logon);
            result.Set("last_logoff", pBuf11->usri11_last_logoff);
            result.Set("bad_pw_count", pBuf11->usri11_bad_pw_count);
            result.Set("num_logons", pBuf11->usri11_num_logons);

            result.Set("logon_server", ws2s(pBuf11->usri11_logon_server));

            result.Set("country_code", pBuf11->usri11_country_code);

            result.Set("workstations", ws2s(pBuf11->usri11_workstations));

            result.Set("max_storage", pBuf11->usri11_max_storage);
            result.Set("units_per_week", pBuf11->usri11_units_per_week);
            /**parse Logon Hours*/
            Napi::Array logon_hours = Napi::Array::New(env, 21);

            for (int j = 0; j < 21; j++)
            {
                logon_hours[j] = (BYTE)pBuf11->usri11_logon_hours[j];
            }
            result.Set("logon_hours", logon_hours);
            /***/
            result.Set("code_page", pBuf11->usri11_code_page);
        }
        break;

        case 20:
        {
            LPUSER_INFO_20 pBuf20 = (LPUSER_INFO_20)pBuf;
            result.Set("name", ws2s(pBuf20->usri20_name));
            result.Set("full_name", ws2s(pBuf20->usri20_full_name));
            result.Set("comment", ws2s(pBuf20->usri20_comment));
            /**parse flags*/
            Napi::Array flagsArray = Napi::Array::New(env);
            parseFlags(pBuf20->usri20_flags, flagsArray);
            result.Set("flags", flagsArray);
            result.Set("user_id", pBuf20->usri20_user_id);
        }
        break;
        case 23:
        {

            LPUSER_INFO_23 pBuf23 = (LPUSER_INFO_23)pBuf;
            result.Set("name", ws2s(pBuf23->usri23_name));
            result.Set("full_name", ws2s(pBuf23->usri23_full_name));
            result.Set("comment", ws2s(pBuf23->usri23_comment));
            /**parse flags*/
            Napi::Array flagsArray = Napi::Array::New(env);
            parseFlags(pBuf23->usri23_flags, flagsArray);
            result.Set("flags", flagsArray);
            if (ConvertSidToStringSid(pBuf23->usri23_user_sid, &sStringSid))
            {
                result.Set("user_sid", ws2s(sStringSid));
                LocalFree(sStringSid);
            }
            else
            {
                hasError = true;
                error.Set("ConvertSidToStringSid", GetLastError());
            }
        }
        break;
        case 24:
        {
            LPUSER_INFO_24 pBuf24 = (LPUSER_INFO_24)pBuf;
            result.Set("is_internet_identity", pBuf24->usri24_internet_identity);
            result.Set("flags", pBuf24->usri24_flags);
            result.Set("internet_provider_name", ws2s(pBuf24->usri24_internet_provider_name));
            result.Set("internet_principal_name", ws2s(pBuf24->usri24_internet_principal_name));

            if (ConvertSidToStringSid(pBuf24->usri24_user_sid, &sStringSid))
            {
                result.Set("user_sid", ws2s(sStringSid));
                LocalFree(sStringSid);
            }
            else
            {
                error.Set("ConvertSidToStringSid", GetLastError());
            }
        }
        break;
        default:
            break;
        }
    }
    else
    {
        Napi::Object result = Napi::Object::New(env);
        result.Set("code", nStatus);
        std::string descr;
        switch (nStatus)
        {
        case ERROR_ACCESS_DENIED:
            descr = "ERROR_ACCESS_DENIED";
            break;
        case ERROR_BAD_NETPATH:
            descr = "ERROR_BAD_NETPATH";
            break;
        case ERROR_INVALID_LEVEL:
            descr = "ERROR_INVALID_LEVEL";
            break;
        case NERR_UserNotFound:
            descr = "NERR_UserNotFound";
            break;
        case NERR_InvalidComputer:
            descr = "NERR_InvalidComputer";
            break;
        }
        result.Set("descr", descr);
        error.Set("NetUserGetinfo", result);
        hasError = true;
    }
    if (hasError)
    {
        result.Set("_error", error);
    }
    if (pBuf != NULL)
        NetApiBufferFree(pBuf);
    return result;
}
Napi::Object Init(Napi::Env env, Napi::Object exports)
{
    exports.Set(Napi::String::New(env, "_f"),
                Napi::Function::New(env, GetUserInfo));
    return exports;
}

NODE_API_MODULE(addon, Init)