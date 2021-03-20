const { _f } = require('../build/Release/userinfo');
const { userInfo } = require('os')
/**
 * params for NetUserGetInfo
 * @see https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusergetinfo#parameters
 */
export interface NUGIParam {
    /**
     * String that specifies the DNS or NetBIOS name of the remote server on which the function is to execute.
     * local computer will be used if not provided.
     */
    serverName?: string,
    /**
     * String that specifies the name of the user account for which to return information.
     */
    userName: string,
    /**The information level of the data. 0 as default  */
    level?: NUGILevel,
}
export type NUGILevel = 0 | 1 | 2 | 3 | 4 | 10 | 11 | 20 | 23 | 24
export interface NUGIResult_Error {
    _error?: Record<string, string | object>
}
export interface _USER_INFO_24 {
    internet_identity: boolean;
    flags: number;
    internet_provider_name: string;
    internet_principal_name: string;
    user_sid: string;
}
export interface _USER_INFO_23 {

}
export interface _USER_INFO_23 {

}
export interface _USER_INFO_20 {

}
export interface _USER_INFO_11 {

}
export interface _USER_INFO_10 {

}
export interface _USER_INFO_4 {

}
export interface _USER_INFO_3 {

}
export interface _USER_INFO_2 {

}
export interface _USER_INFO_1 {

}
export interface _USER_INFO_0 {

}
export type NUGIReturns = NUGIResult_Error | _USER_INFO_0 | _USER_INFO_1 | _USER_INFO_2 | _USER_INFO_3 | _USER_INFO_4 | _USER_INFO_10 | _USER_INFO_11
    | _USER_INFO_20 | _USER_INFO_23 | _USER_INFO_24
export function NetUserGetInfo(param: NUGIParam): NUGIReturns {
    const { serverName, userName, level = 0 } = param
    return _f(serverName, userName, level)
}
export function NetUserGetInfoOfCurrentUser(level: NUGILevel = 0) {
    return _f(undefined, userInfo().username, level)
}
