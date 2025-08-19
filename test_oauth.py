#!/usr/bin/env python3
"""
Test script to verify OAuth2 client credentials flow.
"""
import asyncio
import aiohttp
import logging
import base64
import json
from urllib.parse import urlencode

# Configure logging
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('oauth_test')

async def test_oauth():
    """Test OAuth2 client credentials flow."""
    # OAuth2 Configuration
    config = {
        "url": "http://localhost:9001/token",
        "use_form_data": True,
        "credentials": {
            "grant_type": "client_credentials"
        },
        "auth": {
            "type": "basic",
            "username": "demo-client",
            "password": "demo-secret"
        },
        "token_path": ["access_token"]
    }

    # Prepare headers
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
    }

    # Add Basic Auth if configured
    if 'auth' in config and config['auth'].get('type') == 'basic':
        auth = config['auth']
        username = auth.get('username', '')
        password = auth.get('password', '')
        if username and password:
            auth_str = f"{username}:{password}"
            auth_bytes = auth_str.encode('ascii')
            base64_auth = base64.b64encode(auth_bytes).decode('ascii')
            headers['Authorization'] = f"Basic {base64_auth}"
            logger.debug("Added Basic Auth header")

    # Prepare request data
    if config.get('use_form_data', True):
        data = urlencode(config['credentials'])
        logger.debug(f"Sending form data: {data}")
    else:
        data = json.dumps(config['credentials'])
        headers['Content-Type'] = 'application/json'
        logger.debug(f"Sending JSON data: {data}")

    try:
        async with aiohttp.ClientSession() as session:
            logger.info(f"Sending token request to: {config['url']}")
            logger.debug(f"Request headers: {headers}")
            
            async with session.post(
                config['url'],
                headers=headers,
                data=data,
                ssl=False
            ) as resp:
                response_text = await resp.text()
                logger.info(f"Response status: {resp.status}")
                logger.debug(f"Response headers: {dict(resp.headers)}")
                logger.debug(f"Response body: {response_text}")
                
                if resp.status != 200:
                    logger.error(f"Token request failed with status {resp.status}")
                    return None
                
                try:
                    result = await resp.json()
                    logger.debug(f"Token response: {json.dumps(result, indent=2)}")
                except Exception as e:
                    logger.error(f"Failed to parse JSON response: {e}")
                    logger.debug(f"Raw response: {response_text}")
                    raise ValueError(f"Failed to parse token response: {str(e)}")
                
                if resp.status != 200:
                    error_msg = result.get('error_description', result.get('error', 'Unknown error'))
                    logger.error(f"Token request failed: {error_msg}")
                    raise ValueError(f"Token request failed: {error_msg}")
                
                if 'access_token' not in result:
                    logger.error("No access_token in response")
                    logger.debug(f"Full response: {result}")
                    raise ValueError("No access_token in response")
                
                access_token = result['access_token']
                logger.info("Successfully obtained access token")
                logger.debug(f"Access token: {access_token[:10]}...")
                
                # Log token info if available
                if 'expires_in' in result:
                    logger.info(f"Token expires in: {result['expires_in']} seconds")
                if 'token_type' in result:
                    logger.info(f"Token type: {result['token_type']}")
                
                return access_token
                
            except asyncio.TimeoutError:
                logger.error(f"Token request timed out after {time.time() - start_time:.2f}s")
                raise
            except aiohttp.ClientError as e:
                logger.error(f"HTTP error during token request: {e}")
                raise

async def main():
    # Configuration
    config = {
        'token_url': 'http://localhost:9001/token',
        'client_id': 'demo-client',
        'client_secret': 'demo-secret',
        'mcp_url': 'http://localhost:9000'
    }
    
    logger.info("Starting OAuth2 test with configuration:")
    for k, v in config.items():
        if k == 'client_secret' and v:
            logger.info(f"  {k}: {'*' * 8 + v[-4:] if v else 'None'}")
        else:
            logger.info(f"  {k}: {v}")
    
    async with OAuth2Tester(**config) as tester:
        try:
            # Step 1: Get OAuth2 token
            await tester.get_token()
            
            # Step 2: Test MCP endpoints
            endpoints = [
                '.well-known/mcp.json',
                'tools',
                'resources'
            ]
            
            for endpoint in endpoints:
                try:
                    logger.info(f"\n{'='*50}")
                    logger.info(f"Testing endpoint: {endpoint}")
                    logger.info(f"{'='*50}")
                    await tester.test_mcp_endpoint(endpoint)
                except Exception as e:
                    logger.error(f"Error testing endpoint {endpoint}: {e}", exc_info=True)
            
        except Exception as e:
            logger.error(f"Test failed: {e}", exc_info=True)
            return 1
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        logger.info("Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)
