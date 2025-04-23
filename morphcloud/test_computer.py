from morphcloud.computer import Computer

if __name__ == "__main__":
    computer = Computer.new()
    print("started")
    print(f"{computer.desktop_url()=}")
    breakpoint()
    print(computer._execute_sandbox_command("execute_code", code="1 + 5.0"))
    print(computer.start_mcp_server())
    breakpoint()
    computer.shutdown()
