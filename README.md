**UNDER CONSTRUCTION**
In this version, level 2,3,4,10 are not avaliable, attempts to call with these levels may return empty object. 
Also type definition for result is not done yet.
# user-info
Node.js Wrapper for Windows API NetUserGetInfo()
## Install
```npm install git+https://github.com/KotoriK/user-info.git```
## Usage
```ts
import {NetUserGetInfo} from 'user-info'
const userInfo = NetUserGetInfo({
    /**serverName:string, use local as default.*/
    userName:"Administrator",
    /**level:number, @seealso (bingding.ts)[lib\binding.ts]*/
})
/**
 * result should be :{name:"Administrator"}
*/
/**
 * This function retrieves user name of current process by executing require('os').userInfo().username
*/
const currentUserInfo = NetUserGetInfoOfCurrentUser()

```
See documents of (NetUserGetInfo)[https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusergetinfo] for more information.