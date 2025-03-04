from mfa import totp
import websocket
import datetime
from datetime import datetime as date  # 用于格式化时间
from requests import post
from hashlib import md5
import time
import streamlit as st
import json
import asyncio
import websockets
import requests
from time import time, sleep, strftime
import psutil
import os

# 鉴权服务器配置
SERVER_CONFIG = {
    "api_url": "http://192.168.8.106:8000",
    "websocket_url": "ws://localhost:8000",
    "login": False
}

# 页面函数


def web_ui(ws):
    st.success("验证成功！")
    st.balloons()
    tab = st.tabs(["查询", "更新", "删除", "消息队列", "退出"])
    with tab[0]:
        ws.send(json.dumps({"query": None}, ensure_ascii=False))
        data = json.loads(ws.recv())
        if data:
            st.markdown(
                F'**请求时间**：{
                    date.fromtimestamp(
                        data.get("time")
                    ).strftime("%Y-%m-%d %H:%M:%S")
                }'
            )
            data = data.get("query")[0]
            data["time"] = date.fromtimestamp(
                data.get("time")
            ).strftime("%Y-%m-%d %H:%M:%S")
            data = {
                "时间": data["time"],
                "用户": data["user"],
                "密码": data["passwd"],
                "地址": data["ip"],
                "端口": data["port"]
            }
            st.data_editor(
                {"注册信息": list(data.keys()), "注册数据": list(data.values())},
                use_container_width=True
            )
        else:
            st.markdown("**无数据**")
    with tab[1]:
        st.warning("⚠️ 温馨提示：网页端仅用于演示，该功能仅支持客户端开发使用。")
        request_data = {
            "passwd": st.text_input("密码", type="password", key="tab_passwd")
        }
        if (st.button("确认", key="confirm1")):
            ws.send(json.dumps({"update": request_data}, ensure_ascii=False))
            data = json.loads(ws.recv())
            st.json(data)
    with tab[2]:
        st.warning("⚠️ 温馨提示：网页端仅用于演示，该功能仅支持客户端开发使用。")
        st.error("⚠️ **严重警告：删除账户后不可恢复，所有数据将被永久删除，请谨慎操作！**")
        if (st.button("确认", key="confirm2")):
            ws.send(json.dumps({"remove": None}, ensure_ascii=False))
            data = json.loads(ws.recv())
            st.json(data)
    with tab[3]:
        st.warning("⚠️ 温馨提示：网页端仅用于演示，该功能仅支持客户端开发使用。")
        request_data = {
            "ip": st.text_input("目标地址"),
            "port": st.text_input("目标端口"),
        }
        request_data = {
            "ip": "192.168.8.106",
            "port": 5000
        }
        if (st.button("确认", key="confirm3")):
            ws.send(json.dumps({"server": request_data}, ensure_ascii=False))
            data = json.loads(ws.recv())
            st.json(data)
    with tab[4]:
        st.warning("⚠️ 温馨提示：网页端仅用于演示，该功能仅支持客户端开发使用。")
        st.warning("⚠️ 温馨提醒：确认退出后，您的账号将退出登录，所有未保存的操作可能会丢失。请确认是否继续。")
        if (st.button("确认", key="confirm5")):
            ws.send(json.dumps({"exit": None}, ensure_ascii=False))
            data = json.loads(ws.recv())
            print(data)
            st.json(data)
            st.success("✅ 您已安全退出，页面将自动跳转，请稍候。")
            sleep(30)
            # st.rerun()
###############################################


def 首页():
    st.subheader("欢迎使用身份鉴权客户端！")
    st.write("此客户端主要用于与身份鉴权服务器进行交互，功能包括：")
    st.write("- **地址**：获取客户端和服务器的 IP 信息。")
    st.write("- **注册**：注册新用户，提供用户名和密码。")
    st.write("- **代码**：依据用户名和密码生成唯一的认证码。")
    st.write("- **验证**：使用认证码验证 WebSocket 连接。")


def 地址():
    st.markdown("## 客户、服务端信息")

    # 自动获取并显示 IP 信息
    api_url = f"{SERVER_CONFIG['api_url']}/ip"

    # 显示加载中提示
    with st.spinner("正在加载信息，请稍后..."):
        try:
            response = requests.get(api_url)
            response.raise_for_status()
            result = response.json()

            client_info = result.get("client")
            server_data = result.get("server")

            # 显示客户端信息
            st.markdown(f"**客户端信息：** `{client_info[0]}:{client_info[1]}`")

            # 显示服务器信息
            st.markdown("**服务器列表**")
            server_table = []
            for server_name, server_info in server_data.items():
                server_table.append({
                    "序号": len(server_table) + 1,
                    "名称": server_name,  # 修改为“名称”列
                    "地址": server_info[0],
                    "端口": server_info[1]
                })
            st.data_editor(
                server_table,
                column_config={
                    "序号": st.column_config.NumberColumn("序号", disabled=True),
                    "名称": st.column_config.TextColumn("名称", disabled=True),
                    "地址": st.column_config.TextColumn("地址", disabled=True),
                    "端口": st.column_config.TextColumn("端口", disabled=True)
                },
                use_container_width=True
            )
        except Exception as e:
            st.error("获取信息失败")


def 注册():
    st.subheader("用户注册")
    data = {
        "user": st.text_input("用户名"),
        "passwd": st.text_input("密码", type="password")
    }
    if st.button("注册"):
        api_url = SERVER_CONFIG['api_url'] + "/reg"

        try:
            response = requests.post(api_url, json=data)
            response.raise_for_status()
            result = response.json()

            if result.get("status") is True:
                st.toast("恭喜您，注册成功！", icon="✅")
                st.balloons()

                # 构造提示信息
                markdown_content = (
                    "**重要提醒**：\n\n"
                    "* **以下是您的注册信息，请妥善保管，切勿泄露给他人**：\n\n"
                    "  * 注意：以下信息仅显示一次，后续传输中将不再显示密码。\n"
                    "  * 登录时服务器仅仅使用用户名和一次性密码（TOTP）进行验证。\n"
                    "  * **警告：如果泄露，可能会导致您的账户被盗用、个人信息被滥用等严重后果。请务必保护好您的注册信息**。\n\n"
                    "**使用方式**\n\n"
                    "在登录时，您需要输入您的用户名和密码。客户端将自动为您生成一个一次性密码（TOTP），并将其与您的用户名一起发送到服务器进行验证。您无需手动输入一次性密码，客户端会自动完成整个过程。\n\n"
                    "**服务器返回的数据**\n\n"
                    f"````json\n{json.dumps(result, indent=4)}\n````\n\n"
                )
                st.markdown(markdown_content)
            else:
                rece = result.get("send", {})
                error_lines = [f"{key}: {value}" for key,
                               value in rece.items()]
                st.error(f'注册失败：\n\n{"\n\n".join(error_lines)}')
        except Exception as e:
            st.error(f"服务器请求错误：{str(e)}")


def 代码():
    st.warning("警告：使用过程中，密码密钥可能会被截取，存在严重安全风险，请谨慎操作！")
    st.subheader("TOTP 一次性代码生成器")
    # 创建列布局
    col = st.columns(5)
    request_data = {
        "user": col[0].text_input("用户名"),
        "passwd": md5(col[1].text_input("密码", type="password").encode('utf-8')).hexdigest(),
        "ip": col[2].text_input("IP 地址"),
        "port": col[3].text_input("端口号"),
        "code": col[4].text_input("验证码（选填）"),
    }

    if st.button("生成认证码"):
        api_url = SERVER_CONFIG['api_url'] + "/code"

        try:
            result = requests.post(api_url, json=request_data)
            result.raise_for_status()
            result = result.json()

            # 提取重要信息
            table_data = {
                "生成时间": datetime.datetime.fromtimestamp(result.get("time")).strftime("%Y-%m-%d %H:%M:%S"),
                "调用状态": "✅" if result.get("status") else "❌",
                "认证状态": "✅" if result["rece"].get("verified") else "❌",
                "客户端代码": f"{request_data.get('code')}",
                "服务器代码": f"{result['rece'].get('code')}",
                "原始秘钥": f"{result['rece'].get('original_secret')}",
                "TOTP秘钥": f"{result['rece'].get('secret')}",
                "更新间隔": f"{result['rece'].get('interval')} 秒",
                "输出位数": f"{result['rece'].get('digits')} 位",
                "加密算法": f"{result['rece'].get('algorithm')}",
            }

            # 显示表格
            st.data_editor(
                {
                    "名称": list(table_data.keys()),
                    "数据": list(table_data.values())
                },
                use_container_width=True
            )

            # 显示完整返回数据
            st.markdown("---")
            st.markdown("**返回数据**")
            st.json(result)
        except requests.exceptions.RequestException as e:
            st.toast(f"服务器请求异常：{str(e)}", icon="❌")
        except Exception as e:
            st.toast(f"未知错误：{str(e)}", icon="❌")


def 验证():
    st.subheader("WebSocket 验证")
    col = st.columns(2)
    verification_data = {
        "user": col[0].text_input("用户"),
        "passwd": md5(col[1].text_input("密码", type="password").encode("UTF-8")).hexdigest()
    }
    if st.button("验证"):
        try:
            ws = websocket.create_connection(
                f"{SERVER_CONFIG['websocket_url']}/client"
            )
            verification_data.update(json.loads(ws.recv())["device"])
            verification_data["port"] = str(verification_data["port"])
            verification_data.update(
                totp(
                    secret="|".join(verification_data.values()),
                    interval=30,
                    digits=6,
                    algorithm="sha1",
                    unix_time=int(time()),
                    label=f"{verification_data["user"]}:{int(time())}",
                    issuer="MQserver",
                    parameters=dict()
                )
            )
            verification_data = {
                "user": verification_data["user"],
                "code": verification_data["code"]
            }
            ws.send(json.dumps(verification_data))
            verification_data = json.loads(ws.recv())
            if verification_data.get("rece").get("verified"):
                st.markdown("---")
                web_ui(ws)
            else:
                st.error(
                    "验证失败\n\n" +
                    "\n\n".join(
                        [
                            F"{k}:{v}"
                            for k, v in verification_data.get("rece").items()
                        ]
                    )
                )

            # 关闭连接
            ws.close()
        except websocket.WebSocketException as e:
            st.error(f"WebSocket 错误：{str(e)}")
        except Exception as e:
            st.error(f"发生错误：{str(e)}")


def 任务管理器():
    if st.sidebar.button('任务管理器'):
        st.rerun()
    st.sidebar.write("---")
    cpu_usage = st.sidebar.empty()
    ram_usage = st.sidebar.empty()
    rom_usage = st.sidebar.empty()
    battery = st.sidebar.empty()

    try:
        cpu_usage.metric("CPU 使用率", f"{psutil.cpu_percent(interval=1)} %")
    except Exception as e:
        cpu_usage.metric("CPU 使用率", f"无法获取（{str(e)}）")

    try:
        ram_usage.metric("RAM 使用率", f"{psutil.virtual_memory().percent} %")
    except Exception as e:
        ram_usage.metric("RAM 使用率", f"无法获取（{str(e)}）")

    try:
        path = "/" if os.name == "posix" else "C:\\"
        rom_usage.metric("ROM 使用率", f"{psutil.disk_usage(path).percent} %")
    except Exception as e:
        rom_usage.metric("ROM 使用率", f"无法获取（{str(e)}）")

    try:
        battery_info = psutil.sensors_battery()
        battery_info_str = f"电量（{'充电中' if battery_info.power_plugged else '放电中'}）" if battery_info else "电量"
        battery.metric(
            battery_info_str, f"{battery_info.percent if battery_info else '未检测到电池'}%")
    except Exception as e:
        battery.metric("电量", f"无法获取（{str(e)}）")


def main():
    swap = "身份鉴权客户端"
    st.set_page_config(
        page_title=swap,
        layout="wide",
        initial_sidebar_state="expanded"
    )
    st.title(swap)
    swap = {f.__name__: f for f in [首页, 地址, 注册, 代码, 验证]}
    swap.get(
        st.pills(
            "导航菜单",
            list(swap.keys()),
            label_visibility="hidden"
        ),
        首页
    )()

    任务管理器()


if __name__ == "__main__":
    main()
