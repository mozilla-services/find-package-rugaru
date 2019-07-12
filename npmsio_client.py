import os
import sys

import asyncio
import aiohttp
import json
import pathlib
import time


def aiohttp_session():
    return aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(limit=4),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla-Dependency-Observatory/g-k",
        },
    )


async def async_query(session, json):
    url = "https://api.npms.io/v2/package/mget"
    response = await session.post(url, json=json)
    response_json = await response.json()
    return response_json


async def async_main(package_names):
    async with aiohttp_session() as s:
        response = await async_query(s, package_names)
        return response
