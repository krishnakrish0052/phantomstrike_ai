# mcp_tools/active_directory/certipy_ad.py

from typing import Dict, Any
import asyncio


def register_certipy_ad_tool(mcp, api_client, logger):
    @mcp.tool()
    async def certipy_ad(
        subcommand: str,
        target: str,
        username: str,
        password: str,
        dc_ip: str = "",
        extra_args: str = "",
    ) -> Dict[str, Any]:
        """Execute certipy-ad for Active Directory certificate exploitation.

        Args:
            subcommand: certipy subcommand (e.g. 'req', 'auth', 'find')
            target:     target DC or CA hostname / IP
            username:   domain username (DOMAIN\\user or user@domain)
            password:   user password or NT hash
            dc_ip:      (optional) domain controller IP
            extra_args: (optional) additional CLI arguments

        Returns:
            certipy-ad execution results
        """
        data = {
            "subcommand": subcommand,
            "target": target,
            "username": username,
            "password": password,
            "dc_ip": dc_ip,
            "extra_args": extra_args,
        }
        logger.info("Starting certipy-ad %s on %s", subcommand, target)
        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: api_client.safe_post(
                    "api/tools/active_directory/certipy_ad", data
                ),
            )
            if result.get("success"):
                logger.info("certipy-ad %s completed on %s", subcommand, target)
            else:
                logger.error("certipy-ad %s failed on %s", subcommand, target)
            return result
        except Exception as e:
            logger.error("Error running certipy-ad: %s", str(e))
            return {"error": str(e)}
