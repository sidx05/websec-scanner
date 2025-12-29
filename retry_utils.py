"""
Retry utilities with exponential backoff for network operations.
"""

import time
import functools
from typing import Callable, TypeVar, Any
import logging

logger = logging.getLogger(__name__)

T = TypeVar('T')


def retry_with_backoff(
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    backoff_factor: float = 2.0,
    max_delay: float = 60.0,
    exceptions: tuple = (Exception,)
):
    """
    Decorator for retrying functions with exponential backoff.
    
    Args:
        max_attempts: Maximum number of retry attempts
        initial_delay: Initial delay in seconds before first retry
        backoff_factor: Multiplier for delay after each retry
        max_delay: Maximum delay between retries
        exceptions: Tuple of exception types to catch and retry
        
    Example:
        @retry_with_backoff(max_attempts=3, initial_delay=1.0)
        def fetch_data():
            return requests.get('https://api.example.com')
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            delay = initial_delay
            last_exception = None
            
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    
                    if attempt == max_attempts:
                        logger.error(
                            f"{func.__name__} failed after {max_attempts} attempts: {e}"
                        )
                        raise
                    
                    logger.warning(
                        f"{func.__name__} attempt {attempt}/{max_attempts} failed: {e}. "
                        f"Retrying in {delay:.1f}s..."
                    )
                    
                    time.sleep(delay)
                    delay = min(delay * backoff_factor, max_delay)
            
            # Should never reach here, but just in case
            if last_exception:
                raise last_exception
            
        return wrapper
    return decorator


class RetryableError(Exception):
    """Exception indicating an operation should be retried."""
    pass


class NonRetryableError(Exception):
    """Exception indicating an operation should NOT be retried."""
    pass


def is_retryable_error(error: Exception) -> bool:
    """
    Determine if an error should trigger a retry.
    
    Args:
        error: Exception to check
        
    Returns:
        True if error is retryable, False otherwise
    """
    import httpx
    
    # Always retry on these
    if isinstance(error, (
        httpx.TimeoutException,
        httpx.ConnectTimeout,
        httpx.ReadTimeout,
        httpx.WriteTimeout,
        httpx.PoolTimeout,
        httpx.ConnectError,
        ConnectionError,
        TimeoutError,
    )):
        return True
    
    # Check HTTP status codes
    if isinstance(error, httpx.HTTPStatusError):
        # Retry on server errors (5xx) and specific client errors
        status_code = error.response.status_code
        if status_code >= 500:  # 500-599
            return True
        if status_code in [408, 429]:  # Request Timeout, Too Many Requests
            return True
        return False
    
    # Don't retry these
    if isinstance(error, (
        httpx.InvalidURL,
        httpx.UnsupportedProtocol,
        ValueError,
        TypeError,
    )):
        return False
    
    # Default: retry unknown errors
    return True


def retry_operation(
    operation: Callable[[], T],
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    operation_name: str = "operation"
) -> tuple[T | None, str | None]:
    """
    Execute operation with retry logic and error handling.
    
    Args:
        operation: Callable to execute
        max_attempts: Maximum retry attempts
        initial_delay: Initial delay between retries
        operation_name: Name for logging
        
    Returns:
        Tuple of (result, error_message)
    """
    delay = initial_delay
    last_error = None
    
    for attempt in range(1, max_attempts + 1):
        try:
            result = operation()
            if attempt > 1:
                logger.info(f"{operation_name} succeeded on attempt {attempt}")
            return result, None
            
        except Exception as e:
            last_error = e
            
            if not is_retryable_error(e):
                logger.error(f"{operation_name} failed with non-retryable error: {e}")
                return None, f"Failed: {str(e)}"
            
            if attempt == max_attempts:
                logger.error(f"{operation_name} failed after {max_attempts} attempts: {e}")
                return None, f"Failed after {max_attempts} attempts: {str(e)}"
            
            logger.warning(
                f"{operation_name} attempt {attempt}/{max_attempts} failed: {e}. "
                f"Retrying in {delay:.1f}s..."
            )
            
            time.sleep(delay)
            delay *= 2  # Exponential backoff
    
    return None, f"Failed: {str(last_error)}"


class CircuitBreaker:
    """
    Circuit breaker pattern to prevent cascading failures.
    
    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Failure threshold exceeded, requests fail fast
    - HALF_OPEN: Testing if service recovered
    """
    
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"
    
    def __init__(
        self,
        failure_threshold: int = 5,
        timeout: float = 60.0,
        expected_exception: type = Exception
    ):
        """
        Initialize circuit breaker.
        
        Args:
            failure_threshold: Number of failures before opening circuit
            timeout: Seconds before attempting recovery
            expected_exception: Exception type to track
        """
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = self.CLOSED
    
    def call(self, operation: Callable[[], T]) -> T:
        """
        Execute operation through circuit breaker.
        
        Args:
            operation: Callable to execute
            
        Returns:
            Operation result
            
        Raises:
            Exception if circuit is open or operation fails
        """
        if self.state == self.OPEN:
            if time.time() - self.last_failure_time >= self.timeout:
                self.state = self.HALF_OPEN
                logger.info("Circuit breaker entering HALF_OPEN state")
            else:
                raise Exception(
                    f"Circuit breaker is OPEN. Service unavailable. "
                    f"Retry after {self.timeout}s"
                )
        
        try:
            result = operation()
            self._on_success()
            return result
            
        except self.expected_exception as e:
            self._on_failure()
            raise
    
    def _on_success(self):
        """Handle successful operation."""
        self.failure_count = 0
        if self.state == self.HALF_OPEN:
            self.state = self.CLOSED
            logger.info("Circuit breaker recovered: CLOSED")
    
    def _on_failure(self):
        """Handle failed operation."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = self.OPEN
            logger.warning(
                f"Circuit breaker OPEN after {self.failure_count} failures"
            )
