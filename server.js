//變數區，執行前必須指向node真正的安裝目錄
var globaldir = "C:\\Users\\webadmin\\AppData\\Roaming\\npm\\node_modules\\";
var http = require("http");
var url = require('url');
var fs = require('fs');
//外掛模組區，請確認執行前都已經用NPM安裝完成
var express = require(globaldir+"express");
var moment = require(globaldir+"moment");
var Promise = require(globaldir+'bluebird');	//原生不錯，但bluebird有序列執行的功能
//var fsextra = require(globaldir+'fs-extra');
var sqlite = require(globaldir+"sqlite3").verbose();
var ldap = require(globaldir+'ldapjs');
var isReachable  = require(globaldir+'is-reachable');

const consoleDebugger = (msg) => {
    console.log("[LDAPAuth] ("+moment().format("YYYY/MM/DD HH:mm:ss")+") "+msg);
}
const ldapAuth = async(client, serverLoc, serverPort, username, usersuffix, userpass, userIP) => {
    return new Promise((resolve, reject) => {   //0: 驗證成功；1: 驗證失敗；2: 連線失敗
        try {
            isReachable('ldap://'+serverLoc+":"+serverPort)
            .then(reachable => {
                if(reachable) {
                    client.bind(username+"@"+usersuffix, userpass, (err) => {
                        client.unbind();
                        if(err) {
                            return reject({
                                username: username,
                                pass: userpass,
                                serverLoc: serverLoc,
                                status: 1,
                                msg: err
                            });
                        }
                        return resolve({
                            username: username,
                            pass: userpass,
                            serverLoc: serverLoc,
                            status: 0
                        });
                    });
                } else {
                    return resolve({
                        username: username,
                        pass: userpass,
                        serverLoc: serverLoc,
                        status: 2,
                        msg: serverLoc+"無法連線！"
                    });
                }
            })
            .catch(unreachable => {
                return resolve({
                    username: username,
                    pass: userpass,
                    serverLoc: serverLoc,
                    status: 2,
                    msg: serverLoc+"無法連線！"
                });
            });
        } catch(ex) {
            return reject({
                username: username,
                pass: userpass,
                serverLoc: serverLoc,
                status: 2,
                msg: ex
            });
        }
    });
}
const dbLogger = async(ip, userid, type,timestamp, msg) => {
    return new Promise((resolve, reject) => {
        var db = new sqlite.Database("log.sqlite",() => {
            db.run("INSERT INTO log (timestamp,userID,type,ip,msg) VALUES ( ? , ? , ?, ?, ?)",[timestamp, userid, type, ip, msg],
            function(ok){
                db.close();
                if(ok == null) {
                    return resolve(true);
                } else {
                    return reject(ok);
                }
            });
        });
    });
}

var app = express();
app.set('trust proxy', 1) // trust first proxy

var LDAPs = null;
var IPrules = null;
var server = http.Server(app);
server.listen(1234, "0.0.0.0", function() {
    fs.access(__dirname+'/ADservers.json', fs.constants.R_OK | fs.constants.W_OK, (err) => {
        if(err) {
            consoleDebugger("LDAP主機名單不存在，請自行建立ADservers.json後重新啟動node");
        } else {
            fs.readFile(__dirname+'/ADservers.json', (err, data) => {
                LDAPs = JSON.parse(data);
                consoleDebugger("LDAP主機名單已載入!(共"+LDAPs.length+"台主機)");
            });
        }
    });
    fs.access(__dirname+'/IPrules.json', fs.constants.R_OK | fs.constants.W_OK, (err) => {
        if(err) {
            consoleDebugger("IP許可名單不存在，請自行建立IPrules.json後重新啟動node");
        } else {
            fs.readFile(__dirname+'/IPrules.json', (err, data) => {
                IPrules = JSON.parse(data);
                consoleDebugger("IP許可名單已載入!(共"+IPrules.length+"條規則)");
            });
        }
    });
    consoleDebugger("服務已在port"+server.address().port+"啟動!");
});

app.get("/LDAPAuth", async (req,res) => {
    var now = moment();
    var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    var userID = req.query.hasOwnProperty("userID") ? req.query.userID : false;
    var userPass = req.query.hasOwnProperty("userPass") ? req.query.userPass : false;
	if(!(new RegExp(IPrules.join("|"), "i")).test(ip)) {
        await dbLogger(ip,"","系統訊息",now.unix(),"已攔截不許可的IP登入")
        .then(() => {
            consoleDebugger("已攔截不許可的IP："+ip+"登入");
            res.status(400).json({
                status: false,
                msg: "illegal IP!"
            });
        })
        .catch((err) => {
            consoleDebugger("已攔截不許可的IP："+ip+"登入，但寫入紀錄資料庫失敗，訊息："+err);
        });
    } else if(!userID || !userPass) {
        await dbLogger(ip,"","系統訊息",now.unix(),"嘗試輸入空白字串")
        .then(() => {
            consoleDebugger(ip+"試圖輸入空白字串被攔截");
            res.status(400).json({
                status: false,
                msg: "illegal input!"
            });
        })
        .catch((err) => {
            consoleDebugger(ip+"試圖輸入空白字串被攔截，但寫入紀錄資料庫失敗，訊息："+err);
        });
    } else {
        var serverArray = new Array();
        LDAPs.forEach((item) => {
            serverArray.push({
                client: ldap.createClient({
                    url: 'ldap://'+item.server+":"+item.port,
                    timeout: 10000,
                    connectTimeout: 10000
                }),
                suffix: item.suffix,
                serverLoc: item.server,
                serverPort: item.port
            })
        });
        Promise.mapSeries(serverArray, async item => {
            return await ldapAuth(item.client, item.serverLoc, item.serverPort, userID, item.suffix, userPass,ip)
            .then((result) => {
                now = moment();                
                return result;
            })
            .catch((err) => {
                now = moment();                
                return err;
            })
        })
        .then(async data => {
            var accepted = data.map((obj) => { return obj.status; }).indexOf(0);    //0:認證成功；1:認證失敗；2:連線失敗
            var unaccepted = 0;
            Promise.mapSeries(data, async obj => {
                if(obj.status == 2) {
                    await dbLogger(ip,obj.username,"系統訊息",now.unix(),obj.msg)
                    .then(() => {
                        consoleDebugger(obj.msg);
                    })
                    .catch((err) => {
                        consoleDebugger(obj.msg+"但記錄檔寫入資料庫時發生錯誤："+ok);
                    });
                }
                if(accepted == -1) {
                    await dbLogger(ip,obj.username,"登入失敗",now.unix(),obj.serverLoc+"驗證失敗，錯誤："+obj.msg)
                    .then(() => {
                        consoleDebugger(obj.username+"在"+obj.serverLoc+"驗證失敗（"+obj.msg+"）");
                    })
                    .catch((err) => {
                        consoleDebugger(obj.username+"在"+obj.serverLoc+"驗證失敗（"+obj.msg+"），但寫入紀錄資料庫失敗，訊息："+err);
                    });
                } else {
                    if(obj.status != 0) {
                        unaccepted++;
                    }
                }
            })
            .then(async () => {
                if(accepted > -1) {
                    var acceptedItem = data[accepted];
                    await dbLogger(ip,acceptedItem.username,"登入成功",now.unix(),"登入成功！")
                    .then(() => {
                        consoleDebugger(acceptedItem.username+"（"+ip+"）已在"+acceptedItem.serverLoc+"登入！（其餘"+unaccepted+"台主機不許可登入）");
                        res.status(200).json({
                            status: true,
                            msg: "login success"
                        });
                    })
                    .catch((err) => {
                        consoleDebugger(acceptedItem.username+"（"+ip+"）已在"+acceptedItem.serverLoc+"登入！，但寫入紀錄資料庫失敗，訊息："+err);
                    });
                } else {
                    res.status(401).json({
                        status: false,
                        msg: "login failed"
                    });
                }
            });
        })
        .catch(async (err) => { 
            await dbLogger(ip,"","系統訊息",now.unix(),"LDAP驗證程式發生錯誤："+err)
            .then(() => {
                consoleDebugger("驗證程式發生錯誤，訊息："+err);
                res.status(500).json({
                    status: false,
                    msg: "service exception"
                });
            })
            .catch((dberr) => {
                consoleDebugger("驗證程式發生錯誤（"+err+"），而且寫入紀錄資料庫失敗，訊息："+dberr);
            });
         })
    }
});