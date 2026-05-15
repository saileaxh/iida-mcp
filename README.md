# iida-mcp

[中文](README.md) | [English](README_EN.md)

![iida-mcp capability matrix](arts/iida-mcp-capability-matrix.svg)

`iida-mcp` 是一个 IDA Pro 插件，通过本地 HTTP MCP 服务暴露当前 IDB 的静态分析能力。

该 MCP 主要面向 x86/x86-64 架构可执行文件及对应 IDA 能力设计；如果有其他需求，请提出 issue。

- 77 个 MCP 工具
- 主要兼容 IDA 8+，包括 IDA 9.x
- 支持多 IDA 实例自动路由
- 可选 Windows 内核驱动能力
- 快捷键：`Alt+Shift+I`

## 功能

- 文件信息、原始字节、PE/ELF 解析
- 函数、反汇编、控制流图、交叉引用、调用树
- Hex-Rays 反编译、函数参数、局部变量
- 结构体、枚举、本地类型、类型化读取
- 名称、字符串、字节模式、立即数搜索
- 重命名、注释、类型、补丁、书签、批量操作
- 可选内核内存读取、内核模块枚举、IDA 地址到运行时地址映射

## 安装

把 `iida.py` 和 `iida_core/` 复制到 IDA 的 `plugins/` 目录：

```text
plugins/
  iida.py
  iida_core/
    __init__.py
    cache.py
    kdriver.py
    protocol.py
    registry.py
    router.py
    server.py
    thread_safe.py
    tools.py
    worker.py
```

## 使用

1. 在 IDA 中打开目标文件。
2. 点击 `Edit > Plugins > iida-mcp`，或按 `Alt+Shift+I` 启动。
3. 第一个启动的 IDA 实例监听 `0.0.0.0:13897`，可通过本机回环地址或主机网卡 IP 访问；后续 IDA 实例自动作为 Worker 接入。
4. 再次点击菜单项或再次按 `Alt+Shift+I`，关闭当前 IDA 实例中的 iida-mcp 服务/连接。
5. 单 IDB 时工具参数 `f` 可省略；多 IDB 时先调用 `list_files`，再用返回的 file id 指定 `f`。

## MCP 客户端配置

服务端点：

```text
http://127.0.0.1:13897/mcp
```

如果从其他机器连接，请把 `127.0.0.1` 换成运行 IDA 的主机 IP，例如：

```text
http://192.168.153.1:13897/mcp
```

对支持 HTTP/Streamable HTTP MCP server 的客户端，配置一个远程 MCP server，并把 URL 指向上面的地址即可。

通用示例：

```json
{
  "mcpServers": {
    "iida": {
      "url": "http://127.0.0.1:13897/mcp"
    }
  }
}
```

不同终端或客户端的字段名可能略有差异；核心是使用 HTTP MCP 连接到 `http://127.0.0.1:13897/mcp`。

## 依赖

插件主体只依赖 IDA 自带的 IDAPython 和 Python 标准库。

- 反编译相关工具需要 Hex-Rays Decompiler。
- `disasm_bytes` 需要在 IDA 的 Python 环境中安装 `capstone`。未安装时会返回 `capstone not installed (pip install capstone)`。
- 内核相关工具需要加载 `iida-mcp-ioctl` 驱动。

## 内核驱动

`driver/` 目录包含 `iida-mcp-ioctl` Windows 内核驱动源码，提供：

- 读取内核内存
- 获取内核模块列表
- 按名称查询模块基址

编译需要 Visual Studio Build Tools 和 WDK。`driver/build.bat` 会优先使用 `MSVC`、`WDK`、`SDK_VER` 环境变量；未设置时会尝试从标准安装路径自动探测。

预编译的 `iida-mcp-ioctl.sys` 位于 `driver/`。加载驱动需要自行处理签名和系统策略。未加载驱动时，内核工具会返回明确错误。

## 端口

| 端口 | 用途 |
|------|------|
| `13897` | MCP HTTP 服务，监听所有网卡 |
| `13898` | 内部 Worker 通信，仅本机 |
