def main():    
    from vulnerabilities.checkers.docker_group_check import DockerGroupCheck
    from vulnerabilities.checkers.docker_soc_poc import DockerSockPoC
    from vulnerabilities.integrity_guard_tool import IntegrityGuardTool

    from logging import basicConfig, INFO

    basicConfig(
        level=INFO,
        format='%(message)s' # Optional: keeps the output clean like print()
    )
    
    tool = IntegrityGuardTool([
        DockerGroupCheck(),
        DockerSockPoC()
    ])
    
    tool.run_analysis()

if __name__ == "__main__":
    main()