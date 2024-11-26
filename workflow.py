"""
Agentic RPC Framework
====================

This module implements an "agentic RPC" framework that combines elements of remote procedure
calls (RPC), monadic composition, and agent-based execution models. The framework provides
a type-safe, composable way to define and execute instructions through agents while
maintaining execution context and state.

Background & Context
------------------
Traditional RPC frameworks focus on the mechanics of remote execution but often lack
facilities for maintaining execution context, composing operations, and handling state
in a principled way. This framework addresses these limitations by introducing the concept
of "agentic RPCs" - RPCs that are:
1. Executed by agents with explicit capabilities
2. Maintain execution context through a Runtime object
3. Support monadic composition for complex operations
4. Provide comprehensive error handling and state tracking

Design Philosophy
---------------
The design follows several key principles:
1. Explicit over implicit: Capabilities, parameters, and execution context are always explicit
2. Composition over inheritance: Operations can be composed using monadic patterns
3. Type safety: Comprehensive use of generics and type hints
4. Fail-fast: Early validation of instructions and runtime state
5. Traceable: All operations are logged and trackable
6. Extensible: Abstract base classes and interfaces for customization

Architecture Deep Dive
--------------------
The framework is built around several core abstractions:

1. Runtime
   - Serves as the execution context
   - Maintains state and metadata
   - Tracks execution history
   - Immutable by design (updates create new instances)

2. Instruction
   - Declarative specification of operations
   - Includes validation of required parameters
   - Supports timeout configuration
   - Carries metadata for execution

3. Agent
   - Executes instructions with capability checking
   - Maintains its own context and configuration
   - Abstract base class for custom implementations
   - Handles timeout and cancellation

4. AgentRPC
   - Monadic container for operations
   - Supports composition through `then` and `sequence`
   - Maintains type safety through generics
   - Handles execution flow and error propagation

5. AgentResult
   - Type-safe result container
   - Carries both success and error states
   - Maintains updated runtime
   - Tracks execution metadata

The execution flow follows these steps:
1. Instruction validation
2. Capability checking
3. Runtime preparation
4. Execution with timeout handling
5. Result wrapping
6. Runtime updating
7. Metadata logging

Tradeoffs and Considerations
--------------------------
Pros:
+ Type-safe composition of operations
+ Comprehensive error handling
+ Clear execution boundaries
+ Traceable operations
+ Immutable state management
+ Flexible extension points
+ Built-in timeout handling
+ Support for cancellation

Cons:
- Additional complexity over simple RPC
- Memory overhead from immutable state
- Learning curve for monadic patterns
- Potential performance impact from validation
- Verbose setup for simple operations

Current Limitations:
- No built-in retry mechanism
- Limited backpressure handling
- No distributed transaction support
- No built-in caching
- Limited performance optimization options

Potential Extensions
------------------
1. Retry Mechanisms:
   - Add retry policies
   - Implement exponential backoff
   - Circuit breaker pattern

2. Performance Optimizations:
   - State pooling
   - Result caching
   - Batch operations

3. Distribution Features:
   - Distributed transaction support
   - Cluster awareness
   - Load balancing

4. Monitoring & Observability:
   - Metrics collection
   - Tracing integration
   - Health checking

5. Advanced Features:
   - Workflow definitions
   - Pipeline operations
   - Streaming support
"""

import asyncio
import contextlib
import logging
import os
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, Generic, List, Optional, TypeVar

from anthropic import AsyncAnthropic

from morphcloud import Runtime

T = TypeVar("T")
S = TypeVar("S")

import asyncio
import contextlib
import io
import json
import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union


class MessageRole(Enum):
    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"


@dataclass
class ChatMessage:
    role: MessageRole
    content: Union[str, List[Dict[str, Any]]]

    def __post_init__(self):
        if isinstance(self.role, str):
            self.role = MessageRole(self.role)
        if not isinstance(self.content, (str, list)):
            raise ValueError("Content must be string or list of content blocks")
        if isinstance(self.content, list):
            for block in self.content:
                if not isinstance(block, dict) or "type" not in block:
                    raise ValueError("Invalid content block structure")


@dataclass
class ChatHistory:
    messages: List[ChatMessage] = field(default_factory=list)
    max_messages: int = 100
    max_tokens: int = 8000  # Approximate token limit

    def add(self, message: ChatMessage) -> None:
        self.messages.append(message)
        while len(self.messages) > self.max_messages:
            self.messages.pop(0)

    def to_api_messages(self) -> List[Dict[str, Any]]:
        return [
            {"role": msg.role.value, "content": msg.content} for msg in self.messages
        ]


class StreamSplitter:
    """Splits a stream of text into a buffered iterator of tuples that either contain a matched filter word or a chunk of text."""

    def __init__(self, filter_words: Iterable[str]):
        self.buffer = deque()
        self.filter_set = set(filter_words)
        self.max_filter_len = max(len(word) for word in filter_words)

    def add(self, chunk: str):
        self.buffer.extend(chunk)
        return self

    def extend(self, chunks: Iterable[str]):
        for chunk in chunks:
            self.add(chunk)
        return self

    def flush_iter(self) -> Iterable[Tuple[Optional[str], Optional[str]]]:
        while self.buffer:
            matched_filter = self._check_filter()
            if matched_filter:
                yield matched_filter, None
                for _ in range(len(matched_filter)):
                    self.buffer.popleft()
            else:
                yield None, self.buffer.popleft()

    def _check_filter(self) -> Optional[str]:
        buffer_str = "".join(self.buffer)
        for word in self.filter_set:
            if buffer_str.startswith(word):
                return word
        return None


@dataclass
class ResponseProcessor:
    """Processes streaming responses and maintains state."""

    stream_splitter: StreamSplitter
    partial_buffer: io.StringIO
    content_blocks: List[Dict[str, Any]]

    @classmethod
    def create(cls) -> "ResponseProcessor":
        return cls(
            stream_splitter=StreamSplitter(["<thinking>", "</thinking>"]),
            partial_buffer=io.StringIO(),
            content_blocks=[],
        )

    def process_chunk(
        self, chunk: Any
    ) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        """Process a single chunk from the response stream."""
        text_content = None
        tool_content = None

        match chunk.type:
            case "message_start":
                return None, None

            case "content_block_start":
                self.partial_buffer.seek(0)
                self.partial_buffer.truncate()

                if chunk.content_block.type == "text":
                    self.content_blocks.append({"type": "text"})
                elif chunk.content_block.type == "tool_use":
                    self.content_blocks.append(
                        {
                            "type": "tool_use",
                            "name": chunk.content_block.name,
                            "id": chunk.content_block.id,
                        }
                    )

            case "content_block_delta":
                if self.content_blocks[-1]["type"] == "text":
                    self.partial_buffer.write(chunk.delta.text)
                    # Process text through stream splitter
                    text_content = "".join(
                        text
                        for _, text in self.stream_splitter.add(
                            chunk.delta.text
                        ).flush_iter()
                        if text is not None
                    )
                elif self.content_blocks[-1]["type"] == "tool_use":
                    self.partial_buffer.write(chunk.delta.partial_json)

            case "content_block_stop":
                if self.content_blocks[-1]["type"] == "text":
                    self.content_blocks[-1]["text"] = self.partial_buffer.getvalue()
                    # Flush any remaining content
                    text_content = "".join(
                        text
                        for _, text in self.stream_splitter.flush_iter()
                        if text is not None
                    )
                elif self.content_blocks[-1]["type"] == "tool_use":
                    json_str = self.partial_buffer.getvalue()
                    if json_str:
                        try:
                            tool_content = json.loads(json_str)
                            self.content_blocks[-1]["input"] = tool_content
                        except json.JSONDecodeError:
                            self.logger.warning("Invalid JSON in tool use delta")

        return text_content, tool_content

    def get_final_message(self) -> ChatMessage:
        """Create the final ChatMessage from processed content."""
        return ChatMessage(role=MessageRole.ASSISTANT, content=self.content_blocks)


class ExecutionError(Exception):
    """Base class for execution errors"""

    pass


class ValidationError(ExecutionError):
    """Validation related errors"""

    pass


class TimeoutError(ExecutionError):
    """Timeout related errors"""

    pass


class ExecutionStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class RuntimeMetadata:
    """Metadata about runtime execution"""

    start_time: datetime
    last_updated: datetime
    status: ExecutionStatus
    execution_history: deque = field(default_factory=lambda: deque(maxlen=100))

    def log_operation(self, operation: str) -> None:
        self.execution_history.append((datetime.now(), operation))
        self.last_updated = datetime.now()


@dataclass
class ExecutionContext:
    """Execution context with validation and history tracking"""

    state: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    context: Dict[str, Any] = field(default_factory=dict)
    metadata: RuntimeMetadata = field(
        default_factory=lambda: RuntimeMetadata(
            start_time=datetime.now(),
            last_updated=datetime.now(),
            status=ExecutionStatus.PENDING,
        )
    )

    def __post_init__(self):
        if not isinstance(self.state, dict):
            raise ValidationError("State must be a dictionary")
        if not isinstance(self.context, dict):
            raise ValidationError("Context must be a dictionary")

    def update(self, updates: Dict[str, Any]) -> "ExecutionContext":
        new_runtime = ExecutionContext(
            state={**self.state, **updates},
            timestamp=datetime.now(),
            context=self.context,
            metadata=self.metadata,
        )
        new_runtime.metadata.log_operation(f"State updated with keys: {updates.keys()}")
        return new_runtime


@dataclass
class Instruction:
    """Validated instruction with required and optional parameters"""

    action: str
    parameters: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)
    required_params: List[str] = field(default_factory=list)
    timeout: Optional[float] = None

    def __post_init__(self):
        if not self.action:
            raise ValidationError("Action cannot be empty")
        missing_params = [
            param for param in self.required_params if param not in self.parameters
        ]
        if missing_params:
            raise ValidationError(f"Missing required parameters: {missing_params}")


@dataclass
class AgentContext:
    """Agent configuration with capability verification"""

    agent_id: str
    capabilities: List[str] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.agent_id:
            raise ValidationError("Agent ID cannot be empty")
        if not isinstance(self.capabilities, list):
            raise ValidationError("Capabilities must be a list")

    def can_execute(self, instruction: Instruction) -> bool:
        return instruction.action in self.capabilities


@dataclass
class AgentResult(Generic[T]):
    """Enhanced result container with metadata and utilities"""

    value: Optional[T]
    runtime: ExecutionContext
    error: Optional[Exception] = None
    execution_time: Optional[float] = None

    @classmethod
    def pure(cls, value: T, runtime: ExecutionContext) -> "AgentResult[T]":
        return cls(value=value, runtime=runtime)

    @classmethod
    def fail(cls, error: Exception, runtime: ExecutionContext) -> "AgentResult[Any]":
        return cls(value=None, runtime=runtime, error=error)

    def map(self, f: Callable[[T], S]) -> "AgentResult[S]":
        if self.error is not None:
            return AgentResult(None, self.runtime, self.error)
        try:
            return AgentResult(f(self.value), self.runtime)
        except Exception as e:
            return AgentResult.fail(e, self.runtime)


class Agent:
    """Enhanced agent with proper error handling and timeouts"""

    def __init__(self, context: AgentContext):
        self.context = context
        self.logger = logging.getLogger(f"Agent-{context.agent_id}")

    async def execute(
        self, instruction: Instruction, runtime: ExecutionContext
    ) -> AgentResult:
        start_time = datetime.now()
        runtime.metadata.status = ExecutionStatus.RUNNING

        try:
            if not self.context.can_execute(instruction):
                raise ValidationError(
                    f"Agent {self.context.agent_id} cannot execute {instruction.action}"
                )

            async def execute_with_timeout():
                return await self._execute_instruction(instruction, runtime)

            if instruction.timeout:
                try:
                    result = await asyncio.wait_for(
                        execute_with_timeout(), timeout=instruction.timeout
                    )
                except asyncio.TimeoutError:
                    raise TimeoutError(
                        f"Execution timeout after {instruction.timeout} seconds"
                    )
            else:
                result = await execute_with_timeout()

            runtime.metadata.status = ExecutionStatus.COMPLETED
            return result

        except Exception as e:
            runtime.metadata.status = ExecutionStatus.FAILED
            self.logger.exception(f"Error executing {instruction.action}")
            return AgentResult.fail(e, runtime)

        finally:
            execution_time = (datetime.now() - start_time).total_seconds()
            runtime.metadata.log_operation(
                f"Executed {instruction.action} in {execution_time:.2f}s"
            )

    @abstractmethod
    async def _execute_instruction(
        self, instruction: Instruction, runtime: ExecutionContext
    ) -> AgentResult:
        """Must be implemented by concrete agent classes"""
        pass


@dataclass
class AgentRPC(Generic[T]):
    """
    RPC implementation with clear monadic composition
    """

    instruction: Instruction
    agent: Agent
    _execute_fn: Callable[[ExecutionContext], AgentResult[T]]

    @classmethod
    def create(cls, instruction: Instruction, agent: Agent) -> "AgentRPC[T]":
        """Create a basic RPC"""

        async def execute_fn(runtime: ExecutionContext) -> AgentResult[T]:
            if runtime is None:
                raise ValidationError("ExecutionContext cannot be None")
            return await agent.execute(instruction, runtime)

        return cls(instruction, agent, execute_fn)

    async def execute(self, runtime: ExecutionContext) -> AgentResult[T]:
        """Execute the RPC with the given runtime"""
        if runtime is None:
            raise ValidationError("ExecutionContext cannot be None")
        try:
            return await self._execute_fn(runtime)
        except asyncio.CancelledError:
            runtime.metadata.status = ExecutionStatus.CANCELLED
            raise

    def then(self, f: Callable[[T], "AgentRPC[S]"]) -> "AgentRPC[S]":
        """Chain another RPC, passing the result of this one"""

        async def new_execute(runtime: ExecutionContext) -> AgentResult[S]:
            result = await self.execute(runtime)
            if result.error:
                return AgentResult.fail(result.error, result.runtime)
            next_rpc = f(result.value)
            return await next_rpc.execute(result.runtime)

        return AgentRPC(
            instruction=Instruction(
                action="chain",
                parameters={"operations": [self.instruction]},
                timeout=self.instruction.timeout,
            ),
            agent=self.agent,
            _execute_fn=new_execute,
        )

    def map(self, f: Callable[[T], S]) -> "AgentRPC[S]":
        """Transform the result value without creating a new RPC"""

        async def new_execute(runtime: ExecutionContext) -> AgentResult[S]:
            result = await self.execute(runtime)
            return result.map(f)

        return AgentRPC(
            instruction=self.instruction, agent=self.agent, _execute_fn=new_execute
        )

    @classmethod
    def pure(cls, value: T, agent: Agent) -> "AgentRPC[T]":
        """Create an RPC that just returns a value"""

        async def execute_fn(runtime: ExecutionContext) -> AgentResult[T]:
            return AgentResult.pure(value, runtime)

        return cls(
            instruction=Instruction(action="pure", parameters={"value": value}),
            agent=agent,
            _execute_fn=execute_fn,
        )


# Example concrete agent implementation
class SimpleAgent(Agent):
    async def _execute_instruction(
        self, instruction: Instruction, runtime: ExecutionContext
    ) -> AgentResult:
        # Simple example implementation
        if instruction.action == "echo":
            return AgentResult.pure(instruction.parameters.get("message", ""), runtime)
        raise NotImplementedError(f"Unknown action: {instruction.action}")


# Example concrete agent implementation

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from openai import AsyncOpenAI


class LLMError(ExecutionError):
    """Specific error type for LLM-related failures"""

    pass


@dataclass
class LLMAgentConfig:
    """Configuration for LLM Agent"""

    model: str = "gpt-4-turbo-preview"
    temperature: float = 0.1
    max_tokens: Optional[int] = None
    stop_sequences: Optional[List[str]] = None
    system_prompt: Optional[str] = None
    api_key: Optional[str] = None
    organization: Optional[str] = None


class LLMAgent(Agent):
    """
    Agent that executes instructions by sending them to OpenAI's chat API.

    Capabilities:
    - "chat": Send a message and get a response
    - "analyze": Structured analysis of input
    - "extract": Extract specific information
    - "transform": Transform content according to instructions
    """

    def __init__(self, context: AgentContext, config: LLMAgentConfig):
        super().__init__(context)
        self.config = config
        self.client = AsyncOpenAI(
            api_key=config.api_key, organization=config.organization
        )
        self.logger = logging.getLogger("LLMAgent")

    async def _execute_instruction(
        self, instruction: Instruction, runtime: ExecutionContext
    ) -> AgentResult:
        try:
            # Validate instruction parameters
            if "prompt" not in instruction.parameters:
                raise ValidationError("'prompt' is required in instruction parameters")

            # Prepare messages
            messages = self._prepare_messages(instruction)

            # Get response from API
            response = await self._get_completion(messages)

            # Process response based on instruction action
            result = await self._process_response(instruction, response)

            # Update runtime with relevant metadata
            new_runtime = runtime.update(
                {
                    "last_llm_call": datetime.now().isoformat(),
                    "last_prompt": instruction.parameters["prompt"],
                    "tokens_used": response.usage.total_tokens,
                }
            )

            return AgentResult.pure(result, new_runtime)

        except Exception as e:
            self.logger.exception("Error in LLM execution")
            return AgentResult.fail(LLMError(str(e)), runtime)

    def _prepare_messages(self, instruction: Instruction) -> List[Dict[str, str]]:
        """Prepare messages for the API call"""
        messages = []

        # Add system prompt if configured
        if self.config.system_prompt:
            messages.append({"role": "system", "content": self.config.system_prompt})

        # Add instruction-specific system prompt if provided
        if instruction.parameters.get("system_prompt"):
            messages.append(
                {"role": "system", "content": instruction.parameters["system_prompt"]}
            )

        # Add main prompt
        messages.append({"role": "user", "content": instruction.parameters["prompt"]})

        return messages

    async def _get_completion(self, messages: List[Dict[str, str]]) -> Any:
        """Get completion from OpenAI API"""
        try:
            response = await self.client.chat.completions.create(
                model=self.config.model,
                messages=messages,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                stop=self.config.stop_sequences,
            )
            return response
        except Exception as e:
            raise LLMError(f"API call failed: {str(e)}")

    async def _process_response(self, instruction: Instruction, response: Any) -> Any:
        """Process API response based on instruction action"""
        content = response.choices[0].message.content

        match instruction.action:
            case "chat":
                # Return raw response
                return content

            case "analyze":
                # Attempt to parse as JSON for structured analysis
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    raise LLMError("Failed to parse analysis response as JSON")

            case "extract":
                # Extract specific information based on parameters
                return self._extract_information(content, instruction.parameters)

            case "transform":
                # Apply any post-processing transformations
                return self._transform_content(content, instruction.parameters)

            case _:
                raise ValidationError(f"Unknown action: {instruction.action}")

    def _extract_information(self, content: str, parameters: Dict[str, Any]) -> Any:
        """Extract specific information from response"""
        format = parameters.get("format", "text")

        if format == "json":
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                raise LLMError("Failed to parse response as JSON")

        if format == "lines":
            return content.strip().split("\n")

        return content

    def _transform_content(self, content: str, parameters: Dict[str, Any]) -> Any:
        """Apply transformations to content"""
        transforms = parameters.get("transforms", [])

        result = content
        for transform in transforms:
            match transform:
                case "uppercase":
                    result = result.upper()
                case "lowercase":
                    result = result.lower()
                case "strip":
                    result = result.strip()
                case _:
                    raise ValidationError(f"Unknown transform: {transform}")

        return result


async def morph_agent_example():
    context = AgentContext(
        agent_id="casper", capabilities=["simple_instruction", "autonomous_instruction"]
    )

    config = MorphVMAgentConfig(max_tokens=1024, default_timeout=60.0)

    agent = MorphVMAgent(context, config)

    with Runtime.create(
        snapshot_id="snapshot_idtfj0xi", vcpus=4, memory=8192
    ) as runtime:
        execution_context = ExecutionContext(state=dict(runtime=runtime))
        rpc = AgentRPC.create(
            Instruction(
                action="simple_instruction",
                parameters={
                    "prompt": "open chromium to the wikipedia page for the CCP by invoking the chromium binary in a terminal. just directly call the `chromium` binary directly"
                },
            ),
            agent,
        )
        result = await rpc.execute(execution_context)
    return result


# Example usage
async def llm_example():
    # Setup
    context = AgentContext(
        agent_id="llm-1",
        capabilities=["chat", "analyze", "extract", "transform"],
        config={},
    )

    config = LLMAgentConfig(
        model="gpt-4-turbo-preview",
        temperature=0.3,
        system_prompt=None,
    )

    agent = LLMAgent(context, config)
    runtime = ExecutionContext(
        state={}, timestamp=datetime.now(), context={"env": "prod"}
    )

    # Example 1: Simple chat
    chat_rpc = AgentRPC.create(
        Instruction(
            action="chat", parameters={"prompt": "What is the capital of France?"}
        ),
        agent,
    )

    # Example 2: Chain of operations
    complex_rpc = chat_rpc.then(
        lambda response: AgentRPC.create(
            Instruction(
                action="transform",
                parameters={"prompt": response, "transforms": ["uppercase"]},
            ),
            agent,
        )
    )

    # Execute
    result = await complex_rpc.execute(runtime)
    return result


# Example usage showing composition patterns
async def example():
    runtime = ExecutionContext(
        state={}, timestamp=datetime.now(), context={"env": "prod"}
    )

    agent_context = AgentContext(
        agent_id="agent1", capabilities=["fetch", "process"], config={}
    )
    agent = SimpleAgent(agent_context)

    # Create RPCs
    fetch_users = AgentRPC.create(Instruction("fetch", {"resource": "users"}), agent)

    # Example 1: Simple transformation
    get_user_count = fetch_users.map(lambda users: len(users))

    # Example 2: Dependent operations
    process_users = fetch_users.then(
        lambda users: AgentRPC.create(Instruction("process", {"users": users}), agent)
    )

    # Example 3: Multiple transformations
    get_processed_user_count = fetch_users.then(
        lambda users: AgentRPC.create(Instruction("process", {"users": users}), agent)
    ).map(lambda processed: len(processed))

    # Example 4: Combining results
    def combine_results(users: List[dict]) -> AgentRPC[Dict[str, Any]]:
        return AgentRPC.create(Instruction("process", {"users": users}), agent).map(
            lambda processed: {
                "original": users,
                "processed": processed,
                "count": len(users),
            }
        )

    combined = fetch_users.then(combine_results)

    return await combined.execute(runtime)


@dataclass
class MorphVMAgentConfig:
    model: str = "claude-3-opus-20240229"
    temperature: float = 0.7
    max_tokens: int = 1000
    default_timeout: float = 30.0
    max_autonomous_iterations: int = 10
    max_autonomous_time: int = 300  # 5 minutes
    retry_attempts: int = 3
    retry_delay: float = 1.0
    system_prompt: str = (
        """You are a helpful assistant that controls a cloud based development environment. Take user requests and execute them in the cloud environment."""
    )

    def __post_init__(self):
        if not self.model:
            raise ValidationError("Model must be specified")
        if not 0 <= self.temperature <= 1:
            raise ValidationError("Temperature must be between 0 and 1")
        if not 0 < self.max_tokens <= 4096:
            raise ValidationError("Invalid max_tokens value")


class MorphVMAgent(Agent):
    def __init__(
        self,
        context: AgentContext,
        config: MorphVMAgentConfig,
    ):
        super().__init__(context)
        self.config = config
        self.client = AsyncAnthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
        self.logger = logging.getLogger(f"MorphVMAgent-{context.agent_id}")

    #     # Validate runtime capabilities
    #     self._validate_capabilities()

    # def _validate_capabilities(self, runtime: ) -> None:
    #     required_capabilities = {"execute_tool", "get_tool_definitions"}
    #     # if not all(hasattr(self.context, cap) for cap in required_capabilities):
    #     if not all(cap in self.context.capabilities for cap in required_capabilities)
    #         raise ValidationError(f"Missing required capabilities: {required_capabilities}")

    async def _execute_instruction(
        self, instruction: Instruction, runtime: ExecutionContext
    ) -> AgentResult:
        if "runtime" not in runtime.state:
            raise ValidationError("No runtime found in execution context")

        try:
            async with asyncio.timeout(
                instruction.timeout or self.config.default_timeout
            ):
                if instruction.action == "simple_instruction":
                    return await self._handle_simple_instruction(instruction, runtime)
                elif instruction.action == "autonomous_instruction":
                    return await self._handle_autonomous_instruction(
                        instruction, runtime
                    )
                else:
                    raise ValidationError(
                        f"Unknown instruction type: {instruction.action}"
                    )
        except asyncio.TimeoutError:
            raise TimeoutError(
                f"Instruction execution timeout after {self.config.default_timeout}s"
            )

    async def _handle_simple_instruction(
        self, instruction: Instruction, runtime: ExecutionContext
    ) -> AgentResult:
        # Create or validate chat history
        history = ChatHistory(messages=instruction.parameters.get("messages", []))
        prompt = instruction.parameters["prompt"]

        # Add user message
        history.add(ChatMessage(role=MessageRole.USER, content=prompt))

        async def response_thunk():
            return await self.client.messages.create(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                system=self.config.system_prompt,
                messages=history.to_api_messages(),
                tools=runtime.state["runtime"].interface.render(target="anthropic"),
                stream=True,
            )

        # Get LLM response with retries
        response_stream = await self._retry_with_backoff(response_thunk)

        # Process response
        assistant_message = await self._process_response_stream(
            response_stream, runtime
        )
        history.add(assistant_message)

        # Execute tools with parallel execution and timeout
        if tool_results := await self._execute_tool_calls(
            assistant_message, runtime, timeout=self.config.default_timeout
        ):
            history.add(ChatMessage(role=MessageRole.USER, content=tool_results))

        # Update runtime
        new_runtime = runtime.update(
            {
                "last_interaction": datetime.now().isoformat(),
                "message_history": history.messages,
            }
        )

        return AgentResult.pure(
            {"response": assistant_message, "messages": history.messages}, new_runtime
        )

    async def _handle_autonomous_instruction(
        self, instruction: Instruction, runtime: ExecutionContext
    ) -> AgentResult:
        history = ChatHistory()
        goal = instruction.parameters["goal"]
        start_time = datetime.now()
        iteration = 0

        # Add initial message
        history.add(
            ChatMessage(
                role=MessageRole.USER,
                content=f"Goal: {goal}\nExecute this task autonomously. Work on it step by step and let me know when you're done.",
            )
        )

        try:
            while iteration < self.config.max_autonomous_iterations:
                # Check time limit
                if (
                    datetime.now() - start_time
                ).total_seconds() > self.config.max_autonomous_time:
                    raise TimeoutError("Autonomous execution time limit exceeded")

                # Execute one turn
                result = await self._handle_simple_instruction(
                    Instruction(
                        action="simple_instruction",
                        parameters={
                            "messages": history.messages,
                            "prompt": "Continue working on the task.",
                        },
                    ),
                    runtime,
                )

                # Update history
                history = ChatHistory(messages=result.value["messages"])

                # check completion with timeout
                async with asyncio.timeout(10):
                    completion_status = await self._check_task_completion(
                        goal, history.messages, runtime
                    )
                # try:
                #     # Wait for the task to complete with a timeout of 10 seconds
                #     result = await asyncio.wait_for(
                #         self._check_task_completion(goal, history.messages, runtime),
                #         timeout=10
                #     )
                #     completion_status = result
                # except asyncio.TimeoutError:
                #     # Handle the timeout (e.g., log an error, retry, etc.)
                #     print("Task timed out!")
                #     completion_status = "timeout"

                if completion_status["is_complete"]:
                    new_runtime = runtime.update(
                        {
                            "task_completed": True,
                            "completion_reason": completion_status["reason"],
                            "message_history": history.messages,
                            "iterations": iteration + 1,
                            "execution_time": (
                                datetime.now() - start_time
                            ).total_seconds(),
                        }
                    )

                    return AgentResult.pure(
                        {
                            "messages": history.messages,
                            "completion_status": completion_status,
                        },
                        new_runtime,
                    )

                iteration += 1

            raise RuntimeError("Maximum iterations reached without task completion")

        except Exception as e:
            self.logger.exception("Error in autonomous instruction handling")
            return AgentResult.fail(e, runtime)

    async def _retry_with_backoff(self, operation, max_attempts=None):
        if max_attempts is None:
            max_attempts = self.config.retry_attempts

        last_error = None
        for attempt in range(max_attempts):
            try:
                return await operation()
            except Exception as e:
                last_error = e
                if attempt + 1 < max_attempts:
                    await asyncio.sleep(self.config.retry_delay * (2**attempt))

        raise last_error

    # async def _process_response_stream(
    #     self,
    #     response_stream: Any,
    #     runtime: Any,
    #     max_size: int = 1024 * 1024  # 1MB limit
    # ) -> ChatMessage:
    #     content_blocks = []
    #     total_size = 0

    #     try:
    #         async for chunk in response_stream:
    #             # Check size limit
    #             chunk_size = len(str(chunk))
    #             if total_size + chunk_size > max_size:
    #                 raise ValueError("Response size limit exceeded")
    #             total_size += chunk_size

    #             # Process chunk
    #             if chunk.type == "content_block_start":
    #                 block = {"type": chunk.content_block.type}
    #                 if chunk.content_block.type == "tool_use":
    #                     block.update({
    #                         "name": chunk.content_block.name,
    #                         "id": chunk.content_block.id,
    #                     })
    #                 content_blocks.append(block)

    #             elif chunk.type == "content_block_delta":
    #                 if not content_blocks:
    #                     raise ValueError("Received delta before block start")

    #                 if content_blocks[-1]["type"] == "text":
    #                     content_blocks[-1].setdefault("text", "")
    #                     content_blocks[-1]["text"] += chunk.delta.text
    #                 elif content_blocks[-1]["type"] == "tool_use":
    #                     content_blocks[-1].setdefault("input", {})
    #                     if chunk.delta.partial_json:
    #                         print(f"{chunk.delta.partial_json=}")
    #                         try:
    #                             content_blocks[-1]["input"].update(
    #                                 json.loads(chunk.delta.partial_json)
    #                             )
    #                         except json.JSONDecodeError:
    #                             self.logger.warning("Invalid JSON in tool use delta")

    #     except Exception as e:
    #         self.logger.exception("Error processing response stream")
    #         raise

    #     return ChatMessage(role=MessageRole.ASSISTANT, content=content_blocks)

    async def _process_response_stream(
        self,
        response_stream: Any,
        runtime: ExecutionContext,
        max_size: int = 1024 * 1024,  # 1MB limit
    ) -> ChatMessage:
        """Enhanced response stream processing with proper state management."""
        total_size = 0
        processor = ResponseProcessor.create()

        try:
            async with contextlib.AsyncExitStack() as stack:
                async for chunk in response_stream:
                    # Check size limit
                    chunk_size = len(str(chunk))
                    if total_size + chunk_size > max_size:
                        raise ValueError("Response size limit exceeded")
                    total_size += chunk_size

                    # Process chunk
                    text_content, tool_content = processor.process_chunk(chunk)

                    if text_content:
                        # Log or handle streamed text content
                        self.logger.debug(f"Processed text content: {text_content}")

                    if tool_content:
                        # Log or handle tool content
                        self.logger.debug(f"Processed tool content: {tool_content}")

            return processor.get_final_message()

        except Exception as e:
            self.logger.exception("Error processing response stream")
            raise

    async def _execute_tool_calls(
        self, message: ChatMessage, runtime: ExecutionContext, timeout: float
    ) -> Optional[List[Dict[str, Any]]]:
        if not isinstance(message.content, list):
            return None

        tool_results = []
        tool_tasks = []

        # Create tasks for each tool
        for content in message.content:
            if content["type"] == "tool_use" and "input" in content:
                tool_tasks.append(
                    {
                        "id": content["id"],
                        "task": self._execute_single_tool(
                            content["name"], content["input"], runtime
                        ),
                    }
                )

        if not tool_tasks:
            return None

        # Execute tools in parallel with timeout
        try:
            async with asyncio.timeout(timeout):
                results = await asyncio.gather(
                    *(task["task"] for task in tool_tasks), return_exceptions=True
                )

            # Process results
            for task, result in zip(tool_tasks, results):
                if isinstance(result, Exception):
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": task["id"],
                            "error": str(result),
                        }
                    )
                else:
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": task["id"],
                            "content": json.dumps(result),
                        }
                    )

            return tool_results

        except asyncio.TimeoutError:
            raise TimeoutError(f"Tool execution timeout after {timeout}s")

    async def _execute_single_tool(
        self, tool_name: str, tool_input: Dict[str, Any], runtime: ExecutionContext
    ) -> Any:
        try:
            return await runtime.state["runtime"].interface.execute(
                tool_name, **tool_input
            )
        except Exception as e:
            self.logger.exception(f"Error executing tool {tool_name}")
            raise

    async def _check_task_completion(
        self,
        goal: str,
        messages: List[ChatMessage],
        runtime: ExecutionContext,
    ) -> Dict[str, Any]:
        """Check if autonomous task is complete with proper error handling and caching"""
        cache_key = f"completion_check_{hash(str(messages))}"
        if cache_key in runtime.state:
            return runtime.state[cache_key]

        try:
            # Use focused system prompt for completion checking
            completion_prompt = f"""Evaluate if this task goal has been achieved based on the conversation history.
Goal: {goal}

Criteria:
1. Have all necessary steps been executed successfully?
2. Were there any unrecovered failures?
3. Is additional work needed?
4. Is the task blocked for any reason?

Respond with ONLY a JSON object in this format:
{{
    "is_complete": boolean,
    "reason": "detailed explanation",
    "confidence": float between 0 and 1,
    "failure_detected": boolean,
    "blocked": boolean
}}"""

            response = await self._retry_with_backoff(
                lambda: self.client.messages.create(
                    model=self.config.model,
                    temperature=0.1,  # Lower temperature for more consistent evaluation
                    max_tokens=300,
                    system=completion_prompt,
                    messages=[
                        {
                            "role": "user",
                            "content": self._format_messages_for_completion_check(
                                messages[-10:]
                            ),
                        }
                    ],
                )
            )

            try:
                completion_status = json.loads(response.content)
                # Validate response format
                required_fields = {
                    "is_complete",
                    "reason",
                    "confidence",
                    "failure_detected",
                    "blocked",
                }
                if not all(field in completion_status for field in required_fields):
                    raise ValueError("Invalid completion status format")

                # Cache the result
                new_runtime = runtime.update({cache_key: completion_status})

                return completion_status

            except json.JSONDecodeError:
                return {
                    "is_complete": False,
                    "reason": "Failed to parse completion status",
                    "confidence": 0.0,
                    "failure_detected": True,
                    "blocked": True,
                }

        except Exception as e:
            self.logger.exception("Error checking task completion")
            return {
                "is_complete": False,
                "reason": f"Error evaluating completion: {str(e)}",
                "confidence": 0.0,
                "failure_detected": True,
                "blocked": True,
            }

    def _format_messages_for_completion_check(self, messages: List[ChatMessage]) -> str:
        """Format recent messages for completion check in a clear, structured way"""
        formatted_messages = []
        for msg in messages:
            if isinstance(msg.content, str):
                formatted_messages.append(f"{msg.role.value.upper()}: {msg.content}")
            else:
                # Format content blocks
                blocks = []
                for block in msg.content:
                    if block["type"] == "text":
                        blocks.append(block.get("text", ""))
                    elif block["type"] == "tool_use":
                        blocks.append(f"[Used tool: {block['name']}]")
                formatted_messages.append(
                    f"{msg.role.value.upper()}: {' '.join(blocks)}"
                )

        return "\n".join(formatted_messages)

    async def _monitor_task_progress(
        self, start_time: datetime, iteration: int, history: ChatHistory
    ) -> None:
        """Monitor task progress and resource usage"""
        current_time = datetime.now()
        execution_time = (current_time - start_time).total_seconds()

        # Log progress metrics
        self.logger.info(
            f"Task Progress - Iteration: {iteration}, "
            f"Time: {execution_time:.2f}s, "
            f"Messages: {len(history.messages)}"
        )

        # Check resource usage
        if execution_time > self.config.max_autonomous_time:
            raise TimeoutError(
                f"Exceeded maximum execution time of {self.config.max_autonomous_time}s"
            )

        if iteration >= self.config.max_autonomous_iterations:
            raise RuntimeError(
                f"Exceeded maximum iterations of {self.config.max_autonomous_iterations}"
            )

    #     async def _handle_tool_failure(
    #         self,
    #         tool_name: str,
    #         error: Exception,
    #         runtime: ExecutionContext
    #     ) -> Optional[Dict[str, Any]]:
    #         """Handle tool execution failures with recovery options"""
    #         self.logger.error(f"Tool {tool_name} failed: {str(error)}")

    #         # Ask LLM for recovery strategy
    #         recovery_prompt = f"""Tool "{tool_name}" failed with error: {str(error)}

    # Analyze the error and suggest how to proceed:
    # 1. Can we retry the operation?
    # 2. Is there an alternative approach?
    # 3. Should we abort the current task?

    # Respond with a JSON object containing:
    # {{
    #     "action": "retry|alternate|abort",
    #     "reason": "explanation",
    #     "alternate_tool": "tool_name" if applicable,
    #     "retry_count": suggested number of retries
    # }}"""

    #         try:
    #             response = await self.client.messages.create(
    #                 model=self.config.model,
    #                 temperature=0.1,
    #                 max_tokens=200,
    #                 messages=[{"role": "user", "content": recovery_prompt}]
    #             )

    #             strategy = json.loads(response.content)

    #             match strategy["action"]:
    #                 case "retry":
    #                     if strategy["retry_count"] > 0:
    #                         return await self._retry_with_backoff(
    #                             lambda: runtime.state["runtime"].interface.execute(
    #                                 tool_name
    #                             ),
    #                             max_attempts=strategy["retry_count"]
    #                         )
    #                 case "alternate":
    #                     if alt_tool := strategy.get("alternate_tool"):
    #                         return await runtime.state["runtime"].interface.execute(
    #                             create_tool(alt_tool)
    #                         )
    #                 case "abort":
    #                     raise ExecutionError(f"Tool failure: {strategy['reason']}")

    #         except Exception as e:
    #             self.logger.exception("Error in tool failure recovery")
    #             raise ExecutionError(f"Tool recovery failed: {str(e)}")

    @contextlib.asynccontextmanager
    async def _execution_context(
        self, instruction: Instruction, runtime: ExecutionContext
    ):
        """Manage execution context with proper cleanup"""
        start_time = datetime.now()
        context_data = {
            "start_time": start_time,
            "instruction_id": id(instruction),
            "tool_executions": [],
        }

        try:
            yield context_data
        finally:
            # Cleanup and logging
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.info(
                f"Instruction {context_data['instruction_id']} completed in {execution_time:.2f}s "
                f"with {len(context_data['tool_executions'])} tool executions"
            )

            # Cleanup any resources
            for tool_execution in context_data["tool_executions"]:
                if hasattr(tool_execution.get("result"), "close"):
                    await tool_execution["result"].close()

    def _validate_message_format(self, messages: List[ChatMessage]) -> None:
        """Validate message format and content"""
        if not isinstance(messages, list):
            raise ValidationError("Messages must be a list")

        for msg in messages:
            if not isinstance(msg, ChatMessage):
                raise ValidationError(f"Invalid message type: {type(msg)}")

            if isinstance(msg.content, list):
                for block in msg.content:
                    if not isinstance(block, dict) or "type" not in block:
                        raise ValidationError("Invalid content block structure")

                    if block["type"] == "tool_use":
                        required_fields = {"name", "id", "input"}
                        if not all(field in block for field in required_fields):
                            raise ValidationError(
                                f"Missing required fields in tool_use block: {required_fields}"
                            )


class MorphVMAgentMetrics:
    """Track and expose agent metrics"""

    def __init__(self):
        self.tool_executions = 0
        self.total_execution_time = 0.0
        self.failed_executions = 0
        self.retries = 0
        self.last_updated = datetime.now()

    def update_tool_execution(
        self, success: bool, execution_time: float, retries: int = 0
    ):
        self.tool_executions += 1
        self.total_execution_time += execution_time
        if not success:
            self.failed_executions += 1
        self.retries += retries
        self.last_updated = datetime.now()

    @property
    def success_rate(self) -> float:
        if self.tool_executions == 0:
            return 0.0
        return (self.tool_executions - self.failed_executions) / self.tool_executions

    @property
    def average_execution_time(self) -> float:
        if self.tool_executions == 0:
            return 0.0
        return self.total_execution_time / self.tool_executions

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_executions": self.tool_executions,
            "total_execution_time": self.total_execution_time,
            "failed_executions": self.failed_executions,
            "retries": self.retries,
            "success_rate": self.success_rate,
            "average_execution_time": self.average_execution_time,
            "last_updated": self.last_updated.isoformat(),
        }


if __name__ == "__main__":
    # import fire
    # fire.Fire(locals())
    # print(asyncio.run(example()))
    print(asyncio.run(morph_agent_example()))
