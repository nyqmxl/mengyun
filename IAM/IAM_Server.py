

from fastapi import FastAPI, Request, WebSocket, HTTPException
from fastapi.responses import JSONResponse
from pymongo import MongoClient
from mfa import totp
from time import time
from hashlib import md5
import asyncio

from psutil import virtual_memory as memory


app = FastAPI(title="IAM")

# 严格保持原始变量名
server_name = "IAM"
database = MongoClient("mongodb://localhost:27017/")
client = database[server_name]["client"]
server = database[server_name]["server"]
device = database[server_name]["device"]
log = database[server_name]["log"]


@app.get("/ip")
async def ip(request: Request):
    return JSONResponse(
        {
            "client": [request.client.host, request.client.port],
            "server": list(server.find({}, {"_id": 0}).limit(memory().free >> 16))
        }
    )


@app.post("/reg")
async def reg(request: Request):
    data = {
        "status": None,
        "rece": await request.json(),
        "send": list(client.find(
            {"ip": request.client.host},
            {"_id": 0}
        ).sort("time", -1).limit(1))
    }
    # 1740790800 -> 2025年3月1日 09:00:00
    if (data["send"] == list()):
        data["send"] = {"time": 1740790800}
    else:
        data["send"] = data["send"][0]
    if ("time" in data["send"] and int(time()) - data["send"]["time"] > 10):
        if (client.count_documents({"user": data["rece"]["user"]})):
            data["send"] = {
                "警告": F'''亲，用户'{data["rece"]["user"]}'已经存在啦！不要再尝试啦，快去登录吧！''',
                "Warning": F'''Hi there, the user '{data["rece"]["user"]}' already exists! No need to try again. Hurry up and log in!'''
            }
            data["status"] = False
        else:
            # 生产环境禁用。
            data["send"] = {
                "time": int(time()),
                "user": data["rece"]["user"],
                "passwd": md5(data["rece"]["passwd"].encode("UTF-8")).hexdigest(),
                "ip": request.client.host,
                "port": request.client.port
            }
            data["status"] = True
            client.insert_one(data["send"].copy())
            data["rece"]["passwd"] = "*" * len(data["rece"]["passwd"])
            data["send"]["passwd"] = "MD5:" + "*" * len(data["send"]["passwd"])
    else:
        data["send"] = {
            "警告": "亲，请求有点多，服务器正忙呢，稍等一下再试试哦！",
            "Warning": "Hi there, lots of requests right now, the server is busy, please try again in a moment!"
        }
        data["status"] = None
    return JSONResponse(data)


@app.post("/code")
async def code(request: Request):
    secret = {
        "status": False,
        "time": int(time()),
        "send": await request.json(),
        "rece": {}
    }
    if ("code" in secret["send"]):
        secret["rece"] = {"code": secret["send"]["code"]}
        del secret["send"]["code"]
    try:
        secret["rece"] = totp(
            secret="|".join(secret["send"].values()),
            interval=30,
            digits=6,
            algorithm="sha1",
            unix_time=int(time()),
            label=f"{list(secret["rece"].values())[0] or ""}:{int(time())}",
            issuer="MQserver",
            parameters=secret["rece"]
        )
        secret["status"] = True
    except Exception as e:
        secret["send"] = str(e)
    return JSONResponse(secret)


@app.websocket("/client")
async def ws(websocket: WebSocket):
    await websocket.accept()
    data_base = {
        "device": {
            "ip": websocket.client.host,
            "port": websocket.client.port
        },
        "time": int(time()),
        "status": None,
        "send": None,
        "rece": None
    }
    await websocket.send_json(data_base)
    data_swap = None
    try:
        data_base["send"] = await asyncio.wait_for(websocket.receive_json(), timeout=5.0)
        data_swap = data_base["send"].copy()
        if ("code" in data_base["send"]):
            data_base["status"] = {"code": data_base["send"]["code"]}
            del data_base["send"]["code"]
        data_base["send"] = client.find_one(data_base["send"], {"_id": 0})
        data_base["send"] = data_base["send"] or dict()
        data_base["send"].update(data_base["device"])
        client.update_one(
            {"user": data_base["send"]["user"]},
            {"$set": data_base["send"]},
            upsert=True
        )
        data_base["send"]["port"] = str(data_base["send"]["port"])
        if ("time" in data_base["send"]):
            del data_base["send"]["time"]
        data_base["status"] = totp(
            secret="|".join(data_base["send"].values()),
            interval=30,
            digits=6,
            algorithm="sha1",
            unix_time=int(time()),
            label=f"{data_base["send"]["user"]}:{int(time())}",
            issuer="MQserver",
            parameters=data_base["status"]
        )
        data_base["send"] = data_swap
        data_swap = data_base["status"]
        # 验证取反：data_base["status"]["verified"] or True 生产条件去掉 or True
        data_base["status"] = data_base["status"]["verified"]
        if (data_base["status"]):
            data_base["rece"] = data_swap  # 生产环境禁用。
            data_base["rece"] = {"verified": data_swap["verified"]}
            await websocket.send_json(data_base)
        while data_base["status"]:
            data_swap = {"time": int(time())}
            data_swap.update(await asyncio.wait_for(websocket.receive_json(), timeout=60.0))
            match data_swap:
                case {"query": _}:
                    data_swap["query"] = list(
                        client.find(
                            {"user": data_base["send"]["user"]},
                            {"_id": 0}
                        ).limit(memory().free >> 16)
                    )
                case {"update": _}:
                    update_data = data_swap["update"].copy()
                    update_data.update({
                        "passwd": md5(data_swap["update"]["passwd"].encode("UTF-8")).hexdigest(),
                        "time": int(time()),
                        "ip": websocket.client.host,
                        "post": websocket.client.port
                    })
                    client.update_one(
                        {"user": data_swap["update"]["user"]},
                        {"$set": update_data},
                        upsert=True
                    )
                case {"remove": _}:
                    data_swap["remove"] = bool(
                        client.delete_many(
                            {"user": data_base["send"]["user"]}
                        ).deleted_count
                    )
                    data_base["status"] = False
                case {"exit": _}:
                    data_base["status"] = False
                case {"server": _}:
                    if (type(data_swap["server"]) == dict):
                        for f1k, f1v in data_swap["server"].items():
                            if (server.count_documents({f1k: f1v})):
                                device.insert_one({f1k: f1v}).inserted_id
                                data_swap["server"][f1k] = True
                            else:
                                data_swap["server"][f1k] = False
                    else:
                        data_swap["server"] = False
                case _:
                    del data_swap["time"]
                    data_swap = {
                        "time": int(time()),
                        "message": data_swap
                    }
            await websocket.send_json(data_swap)
    except Exception as e:
        pass
    data_base["status"] = False
    data_base["rece"] = {
        "Warning": "Oops, the connection is disconnected! It might be due to a missing account, operation timeout, account deletion, unstable network, or you disconnected yourself. Please check!",
        "警告": "哎呀，连接断开啦！可能是账户不存在、操作超时、账户被删除、网络不稳定，或者您主动断开。快去检查一下吧！"
    }
    await websocket.send_json(data_base)
    await websocket.close()


@app.websocket("/server")
async def ws(websocket: WebSocket):
    if (server.count_documents({"ip": websocket.client.host})):
        await websocket.accept()
        while True:
            message = client.find_one_and_delete(
                {"ip": websocket.client.host},
                {"_id": 0}
            )
            if message:
                await websocket.send_json(message)
            else:
                try:
                    await websocket.send_text(await asyncio.wait_for(websocket.receive_text(), timeout=1))
                except:
                    await asyncio.sleep(0.1)

if __name__ == "__main__":
    # 使用 uvicorn 启动服务
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
