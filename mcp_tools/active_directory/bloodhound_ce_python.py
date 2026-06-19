# mcp_tools/active_directory/bloodhound_ce_python.py

from typing import Dict, Any
import asyncio


def register_bloodhound_ce_python_tool(mcp, api_client, logger):
    @mcp.tool()
    async def bloodhound_ce_python(
        domain: str,
        username: str,
        password: str,
        collection_method: str = "All",
        dc_ip: str = "",
        nameserver: str = "",
        extra_args: str = "",
    ) -> Dict[str, Any]:
        """Execute bloodhound-python for Active Directory data collection.

        Args:
            domain:            target AD domain (e.g. 'corp.local')
            username:          domain username
            password:          user password or NT hash
            collection_method: data collection method (default: 'All')
            dc_ip:             (optional) domain controller IP
            nameserver:        (optional) custom DNS server
            extra_args:        (optional) additional CLI arguments

        Returns:
            bloodhound-python execution results
        """
        data = {
            "domain": domain,
            "username": username,
            "password": password,
            "collection_method": collection_method,
            "dc_ip": dc_ip,
            "nameserver": nameserver,
            "extra_args": extra_args,
        }
        logger.info("Starting bloodhound-python on domain %s", domain)
        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: api_client.safe_post(
                    "api/tools/active_directory/bloodhound_ce_python", data
                ),
            )
            if result.get("success"):
                logger.info("bloodhound-python completed on domain %s", domain)
            else:
                logger.error("bloodhound-python failed on domain %s", domain)
            return result
        except Exception as e:
            logger.error("Error running bloodhound-python: %s", str(e))
            return {"error": str(e)}
