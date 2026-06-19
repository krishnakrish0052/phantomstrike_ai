# mcp_tools/active_directory/mitm6.py

from typing import Dict, Any
import asyncio


def register_mitm6_tool(mcp, api_client, logger):
    @mcp.tool()
    async def mitm6(
        domain: str,
        interface: str = "",
        extra_args: str = "",
    ) -> Dict[str, Any]:
        """Execute mitm6 for IPv6 DNS takeover / WPAD spoofing.

        Args:
            domain:    target AD domain (e.g. 'corp.local')
            interface: (optional) network interface to listen on
            extra_args: (optional) additional CLI arguments

        Returns:
            mitm6 execution results
        """
        data = {
            "domain": domain,
            "interface": interface,
            "extra_args": extra_args,
        }
        logger.info("Starting mitm6 on domain %s", domain)
        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: api_client.safe_post(
                    "api/tools/active_directory/mitm6", data
                ),
            )
            if result.get("success"):
                logger.info("mitm6 completed on domain %s", domain)
            else:
                logger.error("mitm6 failed on domain %s", domain)
            return result
        except Exception as e:
            logger.error("Error running mitm6: %s", str(e))
            return {"error": str(e)}
