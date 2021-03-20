const {NetUserGetInfo} = require("../dist/binding.js");
const assert = require("assert");

function testInternalUser(){
    const result = NetUserGetInfo({
        userName:"Administrator",level:0
    })
    if(result.name=="Administrator"){
        return true
    }else{
        throw new Error(result)
    }
}
function testTypeGuard(){
    try{
        NetUserGetInfo({userName:123})
    }catch(e){
        if(e instanceof TypeError){
            assert.ok("type guard works.")
            return
        }
    }
    assert.fail()
}
assert.doesNotThrow(testInternalUser,undefined,"testInternalUser not success")
testTypeGuard()
console.log("Tests passed- everything looks fine!");