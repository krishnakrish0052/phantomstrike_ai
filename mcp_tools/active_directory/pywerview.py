# mcp_tools/active_directory/pywerview.py

from typing import Dict, Any
import asyncio


def register_pywerview_tool(mcp, api_client, logger):
    @mcp.tool()
    async def pywerview(
        cmd: str,
        target: str,
        username: str,
        password: str,
        extra_args: str = "",
    ) -> Dict[str, Any]:
        """Execute pywerview for Active Directory enumeration (PowerView Python port).

        Args:
            cmd:        pywerview subcommand (e.g. 'get-netuser', 'get-netgroup')
            target:     target DC hostname or IP
            username:   domain username
            password:   user password or NT hash
            extra_args: (optional) additional CLI arguments

        Returns:
            pywerview execution results
        """
        data = {
            "cmd": cmd,
            "target": target,
            "username": username,
            "password": password,
            "extra_args": extra_args,
        }
        logger.info("Starting pywerview %s on target %s", cmd, target)
        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: api_client.safe_post(
                    "api/tools/active_directory/pywerview", data
                ),
            )
            if result.get("success"):
                logger.info("pywerview %s completed on target %s", cmd, target)
            else:
                logger.error("pywerview %s failed on target %s", cmd, target)
            return result
        except Exception as e:
            logger.error("Error running pywerview: %s", str(e))
            return {"error": str(e)}
