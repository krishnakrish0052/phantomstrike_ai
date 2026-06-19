# mcp_tools/web_framework/browser_agent.py

from typing import Dict, Any, Optional
import asyncio

def _available_tool_name(mcp, default_name: str, alias_name: str) -> str:
    provider = getattr(mcp, "_local_provider", None)
    components = getattr(provider, "_components", {})
    return alias_name if f"tool:{default_name}@" in components else default_name


def register_browser_agent_tool(mcp, api_client, logger, CliColors):

    @mcp.tool(name=_available_tool_name(mcp, "browser_agent_inspect", "web_framework_browser_agent_inspect"))
    async def browser_agent_inspect(url: str, headless: bool = True, wait_time: int = 5,
                             action: str = "navigate", proxy_port: Optional[int] = None, active_tests: bool = False) -> Dict[str, Any]:
        """
        AI-powered browser agent for comprehensive web application inspection and security analysis.

        Args:
            url: Target URL to inspect
            headless: Run browser in headless mode
            wait_time: Time to wait after page load
            action: Action to perform (navigate, screenshot, close, status)
            proxy_port: Optional proxy port for request interception
            active_tests: Run lightweight active reflected XSS tests (safe GET-only)

        Returns:
            Browser inspection results with security analysis
        """
        data_payload = {
            "url": url,
            "headless": headless,
            "wait_time": wait_time,
            "action": action,
            "proxy_port": proxy_port,
            "active_tests": active_tests
        }

        logger.info(f"{CliColors.CRIMSON}🌐 Starting Browser Agent {action}: {url}{CliColors.RESET}")
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None, lambda: api_client.safe_post("api/tools/browser-agent", data_payload)
        )

        if result.get("success"):
            logger.info(f"{CliColors.SUCCESS}✅ Browser Agent {action} completed for {url}{CliColors.RESET}")

            # Enhanced logging for security analysis
            if action == "navigate" and result.get("result", {}).get("security_analysis"):
                security_analysis = result["result"]["security_analysis"]
                issues_count = security_analysis.get("total_issues", 0)
                security_score = security_analysis.get("security_score", 0)

                if issues_count > 0:
                    logger.warning(f"{CliColors.HIGHLIGHT_YELLOW} Security Issues: {issues_count} | Score: {security_score}/100 {CliColors.RESET}")
                else:
                    logger.info(f"{CliColors.HIGHLIGHT_GREEN} No security issues found | Score: {security_score}/100 {CliColors.RESET}")
        else:
            logger.error(f"{CliColors.ERROR}❌ Browser Agent {action} failed for {url}{CliColors.RESET}")

        return result
