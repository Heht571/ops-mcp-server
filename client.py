import asyncio
import json
import os
import sys
from contextlib import AsyncExitStack
from typing import Optional, List, Dict, Any
import time

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from openai import AsyncOpenAI
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text


class MCPClient:
    def __init__(self):
        # 初始化 Rich 控制台，用于更好的终端输出
        self.console = Console()
        
        # 初始化会话和客户端对象
        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        
        # 初始化 OpenAI 客户端，如使用 OpenRouter
        api_key = "your_api_key"
        base_url="https://openrouter.ai/api/v1"
        if not api_key:
            self.console.print("[bold red]错误:[/] 未设置 API_KEY 环境变量", style="bold red")
            sys.exit(1)
            
        self.client = AsyncOpenAI(
            base_url=base_url,
            api_key=api_key,
        )
        
        # 存储历史消息
        self.conversation_history = []
        
        # 存储可用工具
        self.available_tools = []
        
        # 设置 model
        self.model = "qwen/qwen-plus"

    async def connect_to_server(self, server_script_path: str):
        """连接到 MCP 服务器"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]正在连接到 MCP 服务器...[/]"),
            transient=True,
        ) as progress:
            progress.add_task("connecting", total=None)
            
            server_params = StdioServerParameters(
                command="python",
                args=[server_script_path],
                env=None
            )
            
            stdio_transport = await self.exit_stack.enter_async_context(stdio_client(server_params))
            self.stdio, self.write = stdio_transport
            self.session = await self.exit_stack.enter_async_context(ClientSession(self.stdio, self.write))
            
            await self.session.initialize()
            
            # 获取可用工具
            response = await self.session.list_tools()
            self.available_tools = [{
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.inputSchema
                }
            } for tool in response.tools]

        # 显示连接成功信息和可用工具
        self.console.print("\n[bold green]✓[/] 已成功连接到 MCP 服务器！")
        
        if self.available_tools:
            table = Table(title="可用工具", border_style="blue")
            table.add_column("工具名称", style="cyan")
            table.add_column("描述", style="green")
            
            for tool in response.tools:
                table.add_row(tool.name, tool.description or "无描述")
            
            self.console.print(table)
        else:
            self.console.print("[yellow]警告:[/] 没有可用的工具", style="yellow")

    async def process_query(self, query: str) -> str:
        """处理查询并使用工具"""
        # 添加用户消息到历史
        self.conversation_history.append({
            "role": "user",
            "content": query
        })
        
        messages = self.conversation_history.copy()
        
        final_text = []
        tool_calls_info = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]思考中...[/]"),
            transient=True,
        ) as progress:
            progress.add_task("thinking", total=None)
            
            # 初始 API 调用
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=self.available_tools
            )
        
        message = response.choices[0].message
        
        # 添加助手回复到历史
        self.conversation_history.append({
            "role": "assistant",
            "content": message.content,
            "tool_calls": message.tool_calls
        })
        
        if message.content:
            final_text.append(message.content)

        # 处理工具调用
        while message.tool_calls:
            for tool_call in message.tool_calls:
                tool_name = tool_call.function.name
                tool_args = json.loads(tool_call.function.arguments)
                
                # 显示工具调用信息
                tool_call_info = f"🔧 正在调用工具: [bold cyan]{tool_name}[/]"
                self.console.print(tool_call_info)
                
                # 显示参数
                syntax = Syntax(
                    json.dumps(tool_args, indent=2, ensure_ascii=False),
                    "json",
                    theme="monokai",
                    word_wrap=True
                )
                self.console.print(Panel(syntax, title="参数", border_style="green"))
                
                with Progress(
                    SpinnerColumn(),
                    TextColumn(f"[bold blue]工具 {tool_name} 执行中...[/]"),
                    transient=True,
                ) as progress:
                    progress.add_task("running", total=None)
                    # 执行工具调用
                    result = await self.session.call_tool(tool_name, tool_args)
                
                # 格式化工具调用信息，用于最终输出
                tool_calls_info.append({
                    "tool": tool_name,
                    "args": tool_args,
                    "result": result.content
                })
                
                # 添加工具调用和结果到消息
                messages.append({
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": tool_call.id,
                            "type": "function",
                            "function": {
                                "name": tool_name,
                                "arguments": json.dumps(tool_args)
                            }
                        }
                    ]
                })
                
                # 添加工具结果到历史
                tool_response = {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": str(result.content)
                }
                messages.append(tool_response)
                self.conversation_history.append(tool_response)
                
                # 显示工具执行结果
                result_str = str(result.content)
                if len(result_str) > 1000:
                    result_str = result_str[:997] + "..."
                
                try:
                    # 尝试作为 JSON 解析显示
                    json_data = json.loads(result_str)
                    syntax = Syntax(
                        json.dumps(json_data, indent=2, ensure_ascii=False),
                        "json",
                        theme="monokai",
                        word_wrap=True
                    )
                    self.console.print(Panel(syntax, title="工具执行结果", border_style="blue"))
                except:
                    # 普通文本显示
                    self.console.print(Panel(result_str, title="工具执行结果", border_style="blue"))

            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]分析结果中...[/]"),
                transient=True,
            ) as progress:
                progress.add_task("analyzing", total=None)
                # 获取下一个 LLM 响应
                response = await self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    tools=self.available_tools
                )
            
            message = response.choices[0].message
            
            # 添加助手回复到历史
            if message.content or message.tool_calls:
                self.conversation_history.append({
                    "role": "assistant",
                    "content": message.content,
                    "tool_calls": message.tool_calls
                })
            
            if message.content:
                final_text.append(message.content)

        # 构建漂亮的最终输出
        result = "\n\n".join(final_text)
        
        # 添加工具调用摘要（如果有）
        if tool_calls_info:
            tool_summary = "\n\n### 工具调用摘要\n"
            for i, call in enumerate(tool_calls_info):
                tool_summary += f"\n**工具 {i+1}**: `{call['tool']}`\n"
            result += tool_summary
            
        return result

    async def chat_loop(self):
        """运行交互式对话循环"""
        # 显示欢迎信息
        welcome_text = Text()
        welcome_text.append("🤖 ", style="bold blue")
        welcome_text.append("增强型 MCP 客户端", style="bold cyan")
        welcome_text.append(" 已启动！\n", style="bold green")
        welcome_text.append("输入您的问题，或输入 ", style="")
        welcome_text.append("quit", style="bold red")
        welcome_text.append(" 退出，", style="")
        welcome_text.append("help", style="bold yellow")
        welcome_text.append(" 获取帮助。", style="")
        
        self.console.print(Panel(welcome_text, border_style="green"))
        
        while True:
            try:
                # 使用 Rich 提示获取用户输入
                query = Prompt.ask("\n[bold cyan]您的问题[/]")
                
                # 处理特殊命令
                if query.lower() == 'quit':
                    self.console.print("[bold green]感谢使用！再见！[/]")
                    break
                elif query.lower() == 'help':
                    self._show_help()
                    continue
                elif query.lower() == 'clear':
                    self.conversation_history = []
                    self.console.print("[bold green]✓[/] 对话历史已清除！")
                    continue
                elif query.lower().startswith('model '):
                    new_model = query[6:].strip()
                    if new_model:
                        self.model = new_model
                        self.console.print(f"[bold green]✓[/] 模型已切换到: [bold cyan]{new_model}[/]")
                    else:
                        self.console.print(f"[bold yellow]当前模型:[/] [bold cyan]{self.model}[/]")
                    continue
                
                # 记录开始时间
                start_time = time.time()
                
                # 处理查询
                response = await self.process_query(query)
                
                # 计算耗时
                elapsed = time.time() - start_time
                
                # 显示响应
                self.console.print("\n[bold green]回答:[/]")
                self.console.print(Markdown(response))
                
                # 显示耗时
                self.console.print(f"[dim]（处理耗时: {elapsed:.2f}秒）[/]")
                
            except KeyboardInterrupt:
                self.console.print("\n[bold yellow]操作已取消[/]")
            except Exception as e:
                self.console.print(f"\n[bold red]错误:[/] {str(e)}", style="bold red")
                self.console.print_exception()
    
    def _show_help(self):
        """显示帮助信息"""
        help_table = Table(title="命令帮助", border_style="yellow")
        help_table.add_column("命令", style="cyan")
        help_table.add_column("描述", style="green")
        
        help_table.add_row("quit", "退出程序")
        help_table.add_row("help", "显示此帮助信息")
        help_table.add_row("clear", "清除对话历史")
        help_table.add_row("model <名称>", "切换模型，例如：model gpt-4")
        
        self.console.print(help_table)
    
    async def cleanup(self):
        """清理资源"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]正在清理资源...[/]"),
            transient=True,
        ) as progress:
            progress.add_task("cleaning", total=None)
            await self.exit_stack.aclose()


async def main():
    # 文件头部标题
    console = Console()
    
    title = Text()
    title.append("🚀 ", style="bold blue")
    title.append("增强型 MCP 客户端", style="bold cyan underline")
    
    console.print(Panel(title, border_style="cyan"))
    
    if len(sys.argv) < 2:
        console.print("[bold red]错误:[/] 缺少服务器脚本路径", style="bold red")
        console.print("\n使用方法: [bold]uv run client.py <服务器脚本路径>[/]")
        console.print("示例: [bold]uv run client.py ../../server/elasticsearch-mcp-server-example/server.py[/]")
        sys.exit(1)
        
    client = MCPClient()
    try:
        await client.connect_to_server(sys.argv[1])
        await client.chat_loop()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]程序被用户中断[/]")
    except Exception as e:
        console.print(f"\n[bold red]发生错误:[/] {str(e)}", style="bold red")
        console.print_exception()
    finally:
        await client.cleanup()
        console.print("[bold green]程序已退出[/]")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        Console().print("\n[bold yellow]程序被强制终止[/]")