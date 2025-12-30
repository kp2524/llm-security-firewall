"""Google Gemini API client for LLM interactions using the new google-genai SDK."""
import google.genai as genai
from config import settings
from typing import Optional


class LLMClient:
    """Client for interacting with Google Gemini API using the new SDK."""
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the Gemini client.
        
        Args:
            api_key: Gemini API key. Defaults to settings.gemini_api_key.
        """
        self.api_key = api_key or settings.gemini_api_key
        
        # Initialize the client with the API key
        # Note: The new SDK should handle API version automatically, but if issues persist,
        # you can try explicit http_options configuration
        try:
            self.client = genai.Client(api_key=self.api_key)
        except Exception as e:
            print(f"Error initializing Gemini Client: {e}")
            raise
        
        # Model name - use gemini-flash-latest (always points to latest available flash model)
        # This is more reliable than specific version numbers which may be deprecated
        # Alternative models: gemini-2.5-flash, gemini-flash-lite-latest (lighter/quicker)
        self.model_name = 'gemini-flash-latest'
    
    async def generate_response(self, prompt: str, max_retries: int = 3) -> str:
        """Generate a response from the LLM.
        
        Args:
            prompt: The user's prompt
            max_retries: Maximum number of retry attempts
            
        Returns:
            The generated response text
            
        Raises:
            Exception: If API call fails after retries
        """
        # Since the new SDK's generate_content is synchronous, run it in executor
        import asyncio
        loop = asyncio.get_event_loop()
        
        last_error = None
        
        # Try alternative model names if primary fails
        # Order: latest alias -> specific version -> lite version (for quota/performance)
        model_names_to_try = [
            self.model_name,  # gemini-flash-latest
            'gemini-2.5-flash',  # Latest stable version
            'gemini-flash-lite-latest',  # Lighter version if quota issues
            'gemini-2.0-flash-lite',  # Fallback lite version
        ]
        
        for model_name in model_names_to_try:
            for attempt in range(max_retries):
                try:
                    # Helper function to generate with specific model
                    def _generate(model: str):
                        return self.client.models.generate_content(
                            model=model,
                            contents=prompt
                        )
                    
                    # Run the synchronous generate_content in an executor
                    response = await loop.run_in_executor(None, _generate, model_name)
                    
                    # Extract text from response (new API has .text attribute directly)
                    if not response.text or response.text.strip() == '':
                        raise ValueError("Empty response from model")
                    
                    # If we used a different model, update the default
                    if model_name != self.model_name:
                        print(f"Using model: {model_name} (fallback from {self.model_name})")
                        self.model_name = model_name
                    
                    return response.text.strip()
                        
                except Exception as e:
                    last_error = e
                    # If it's a 404 (model not found) or 429 (quota exceeded), try next model name
                    error_str = str(e)
                    if '404' in error_str or 'not found' in error_str.lower() or '429' in error_str or 'quota' in error_str.lower() or 'RESOURCE_EXHAUSTED' in error_str:
                        break  # Try next model name
                    
                    if attempt < max_retries - 1:
                        # Wait before retry (exponential backoff)
                        await asyncio.sleep(2 ** attempt)
            
            # If we got here and last_error exists, try next model
            error_str = str(last_error) if last_error else ''
            if last_error and ('404' in error_str or 'not found' in error_str.lower() or '429' in error_str or 'quota' in error_str.lower() or 'RESOURCE_EXHAUSTED' in error_str):
                continue
        
        # If all models failed, raise the last error
        raise Exception(f"Failed to generate response after trying {len(model_names_to_try)} model(s): {str(last_error)}")
        
        raise last_error
    
    def generate_response_sync(self, prompt: str, max_retries: int = 3) -> str:
        """Generate a response synchronously (for non-async contexts).
        
        Args:
            prompt: The user's prompt
            max_retries: Maximum number of retry attempts
            
        Returns:
            The generated response text
            
        Raises:
            Exception: If API call fails after retries
        """
        last_error = None
        
        # Try alternative model names if primary fails
        # Order: latest alias -> specific version -> lite version (for quota/performance)
        model_names_to_try = [
            self.model_name,  # gemini-flash-latest
            'gemini-2.5-flash',  # Latest stable version
            'gemini-flash-lite-latest',  # Lighter version if quota issues
            'gemini-2.0-flash-lite',  # Fallback lite version
        ]
        
        for model_name in model_names_to_try:
            for attempt in range(max_retries):
                try:
                    # Generate content using the new API
                    # contents can be a string directly
                    response = self.client.models.generate_content(
                        model=model_name,
                        contents=prompt
                    )
                    
                    # Extract text from response (new API has .text attribute directly)
                    if not response.text or response.text.strip() == '':
                        raise ValueError("Empty response from model")
                    
                    # If we used a different model, update the default
                    if model_name != self.model_name:
                        print(f"Using model: {model_name} (fallback from {self.model_name})")
                        self.model_name = model_name
                    
                    return response.text.strip()
                    
                except Exception as e:
                    last_error = e
                    # If it's a 404 (model not found) or 429 (quota exceeded), try next model name
                    error_str = str(e)
                    if '404' in error_str or 'not found' in error_str.lower() or '429' in error_str or 'quota' in error_str.lower() or 'RESOURCE_EXHAUSTED' in error_str:
                        break  # Try next model name
                    
                    if attempt < max_retries - 1:
                        import time
                        time.sleep(2 ** attempt)
            
            # If we got here and last_error exists, try next model
            error_str = str(last_error) if last_error else ''
            if last_error and ('404' in error_str or 'not found' in error_str.lower() or '429' in error_str or 'quota' in error_str.lower() or 'RESOURCE_EXHAUSTED' in error_str):
                continue
        
        # If all models failed, raise the last error
        raise Exception(f"Failed to generate response after trying {len(model_names_to_try)} model(s): {str(last_error)}")
        
        raise last_error


# Global client instance (will be initialized in main.py)
llm_client: Optional[LLMClient] = None

def get_llm_client() -> LLMClient:
    """Get or create the global LLM client instance.
    
    Returns:
        LLMClient instance
    """
    global llm_client
    if llm_client is None:
        llm_client = LLMClient()
    return llm_client
