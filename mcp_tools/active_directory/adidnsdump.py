# mcp_tools/active_directory/adidnsdump.py

from typing import Dict, Any
import asyncio


def register_adidnsdump_tool(mcp, api_client, logger):
    @mcp.tool()
    async def adidnsdump(
        target: str,
        username: str = "",
        password: str = "",
        extra_args: str = "",
    ) -> Dict[str, Any]:
        """Execute adidnsdump to enumerate DNS records via LDAP.

        Args:
            target:     target DC hostname or IP
            username:   (optional) domain username
            password:   (optional) user password or NT hash
            extra_args: (optional) additional CLI arguments

        Returns:
            adidnsdump execution results
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "extra_args": extra_args,
        }
        logger.info("Starting adidnsdump on target %s", target)
        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: api_client.safe_post(
                    "api/tools/active_directory/adidnsdump", data
                ),
            )
            if result.get("success"):
                logger.info("adidnsdump completed on target %s", target)
            else:
                logger.error("adidnsdump failed on target %s", target)
            return result
        except Exception as e:
            logger.error("Error running adidnsdump: %s", str(e))
            return {"error": str(e)}
