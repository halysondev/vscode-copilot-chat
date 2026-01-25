/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import type { Anthropic } from '@anthropic-ai/sdk';
import { MessageParam } from '@anthropic-ai/sdk/resources';
import { RequestMetadata, RequestType } from '@vscode/copilot-api';
import { Raw } from '@vscode/prompt-tsx';
import * as http from 'http';
import { IChatMLFetcher, Source } from '../../../../platform/chat/common/chatMLFetcher';
import { ChatLocation, ChatResponse } from '../../../../platform/chat/common/commonTypes';
import { CustomModel, EndpointEditToolName, IEndpointProvider } from '../../../../platform/endpoint/common/endpointProvider';
import { AnthropicMessagesProcessor } from '../../../../platform/endpoint/node/messagesApi';
import { ILogService } from '../../../../platform/log/common/logService';
import { FinishedCallback, OptionalChatRequestParams } from '../../../../platform/networking/common/fetch';
import { Response } from '../../../../platform/networking/common/fetcherService';
import { IChatEndpoint, ICreateEndpointBodyOptions, IEndpointBody, IEndpointFetchOptions, IMakeChatRequestOptions } from '../../../../platform/networking/common/networking';
import { ChatCompletion } from '../../../../platform/networking/common/openai';
import { ITelemetryService } from '../../../../platform/telemetry/common/telemetry';
import { TelemetryData } from '../../../../platform/telemetry/common/telemetryData';
import { ITokenizer, TokenizerType } from '../../../../util/common/tokenizer';
import { AsyncIterableObject } from '../../../../util/vs/base/common/async';
import { CancellationToken, CancellationTokenSource } from '../../../../util/vs/base/common/cancellation';
import { Disposable, toDisposable } from '../../../../util/vs/base/common/lifecycle';
import { SSEParser } from '../../../../util/vs/base/common/sseParser';
import { generateUuid } from '../../../../util/vs/base/common/uuid';
import { IInstantiationService } from '../../../../util/vs/platform/instantiation/common/instantiation';
import { claudeCodeReasoningConfig } from './claude-code';
import { IClaudeCodeModels } from './claudeCodeModels';
import { claudeCodeOAuthManager, generateUserId } from './oauth';
import { createStreamingMessage, StreamThinkingCompleteChunk, StreamToolCallPartialChunk, ThinkingConfig } from './streaming-client';

export interface IClaudeLanguageModelServerConfig {
	readonly port: number;
	readonly nonce: string;
}

interface AnthropicMessagesRequest {
	model: string;
	messages: MessageParam[];
	system?: string | Array<{ type: 'text'; text: string }>;
	max_tokens?: number;
	stream?: boolean;
	tools?: unknown[];
	[key: string]: unknown;
}

interface AnthropicErrorResponse {
	type: 'error';
	error: {
		type: 'invalid_request_error' | 'authentication_error' | 'permission_error' | 'not_found_error' | 'rate_limit_error' | 'api_error';
		message: string;
	};
}

const DEFAULT_MAX_TOKENS = 200_000;
const DEFAULT_MAX_OUTPUT_TOKENS = 64_000;

/**
 * HTTP server that provides an Anthropic Messages API compatible endpoint.
 * Acts as a pure pass-through proxy to the underlying model endpoint.
 */
export class ClaudeLanguageModelServer extends Disposable {
	private server: http.Server;
	private config: IClaudeLanguageModelServerConfig;

	constructor(
		@ILogService private readonly logService: ILogService,
		@IEndpointProvider private readonly endpointProvider: IEndpointProvider,
		@IInstantiationService private readonly instantiationService: IInstantiationService,
		@IClaudeCodeModels private readonly claudeCodeModels: IClaudeCodeModels,
	) {
		super();
		this.config = {
			port: 0, // Will be set to random available port
			nonce: 'vscode-lm-' + generateUuid()
		};

		this.server = this.createServer();
		this._register(toDisposable(() => this.stop()));
	}

	private createServer(): http.Server {
		return http.createServer(async (req, res) => {
			this.trace(`Received request: ${req.method} ${req.url}`);

			if (req.method === 'OPTIONS') {
				res.writeHead(200);
				res.end();
				return;
			}

			// Handle /v1/messages endpoint (also //messages if base URL ends in /)
			// Use URL to properly parse and extract pathname, ignoring query string
			const pathname = new URL(req.url ?? '/', 'http://localhost').pathname;
			if (req.method === 'POST' && (pathname === '/v1/messages' || pathname === '/messages' || pathname === '//messages')) {
				await this.handleMessagesRequest(req, res);
				return;
			}

			if (req.method === 'GET' && req.url === '/') {
				res.writeHead(200);
				res.end('Hello from ClaudeLanguageModelServer');
				return;
			}

			this.sendErrorResponse(res, 404, 'not_found_error', 'Not found');
		});
	}

	private async handleMessagesRequest(req: http.IncomingMessage, res: http.ServerResponse) {
		try {
			const body = await this.readRequestBody(req);
			if (!(await this.isAuthTokenValid(req))) {
				this.error('Invalid auth key');
				this.sendErrorResponse(res, 401, 'authentication_error', 'Invalid authentication');
				return;
			}

			await this.handleAuthedMessagesRequest(body, req.headers, res);
		} catch (error) {
			const errorMessage = error instanceof Error ? error.message : String(error);
			if (res.headersSent) {
				// Headers already sent (streaming started), log error but can't send error response
				this.error(`Error after headers sent: ${errorMessage}`);
				res.end();
			} else {
				this.sendErrorResponse(res, 500, 'api_error', errorMessage);
			}
		}
		return;
	}

	/**
	 * Verify nonce
	 */
	private async isAuthTokenValid(req: http.IncomingMessage): Promise<boolean> {
		const authHeader = req.headers['x-api-key'];
		return authHeader === this.config.nonce;
	}

	private async readRequestBody(req: http.IncomingMessage): Promise<string> {
		return new Promise((resolve, reject) => {
			let body = '';
			req.on('data', chunk => {
				body += chunk.toString();
			});
			req.on('end', () => {
				resolve(body);
			});
			req.on('error', reject);
		});
	}

	private async handleAuthedMessagesRequest(bodyString: string, headers: http.IncomingHttpHeaders, res: http.ServerResponse): Promise<void> {
		const requestBody: AnthropicMessagesRequest = JSON.parse(bodyString);

		// Check if OAuth is available - use direct Anthropic API if authenticated
		const accessToken = await claudeCodeOAuthManager.getAccessToken();

		if (accessToken) {
			this.trace('Using OAuth authentication for direct Anthropic API call');
			await this.handleOAuthRequest(requestBody, accessToken, res);
		} else {
			// No OAuth token available - return error instead of falling back to Copilot API
			this.error('No Claude Code OAuth credentials available. Please sign in to Claude Code.');
			this.sendErrorResponse(
				res,
				401,
				'authentication_error',
				'Claude Code OAuth not configured. Please sign in using the "Claude Code: Sign In" command.'
			);
		}
	}

	/**
	 * Handle request via direct OAuth-authenticated Anthropic API call
	 */
	private async handleOAuthRequest(
		requestBody: AnthropicMessagesRequest,
		accessToken: string,
		res: http.ServerResponse
	): Promise<void> {
		// Set up streaming response
		res.writeHead(200, {
			'Content-Type': 'text/event-stream',
			'Cache-Control': 'no-cache',
			'Connection': 'keep-alive',
		});

		// Create abort controller for request cancellation
		const abortController = new AbortController();
		res.on('close', () => {
			abortController.abort();
		});

		try {
			await this.streamWithOAuthToken(accessToken, requestBody, res, abortController.signal);
		} catch (error) {
			const errorMessage = error instanceof Error ? error.message : String(error);

			// Check if it's an abort (client closed connection) - this is normal, just end quietly
			if (abortController.signal.aborted || errorMessage.includes('aborted') || errorMessage.includes('AbortError')) {
				this.trace(`OAuth request aborted (client closed connection)`);
				if (!res.writableEnded) {
					res.end();
				}
				return;
			}

			// Check if it's an auth error - try to refresh and retry
			if (errorMessage.includes('401') || errorMessage.includes('authentication') || errorMessage.includes('unauthorized')) {
				this.info('OAuth token may be expired, attempting refresh...');
				try {
					const newToken = await claudeCodeOAuthManager.forceRefreshAccessToken();
					if (newToken) {
						this.info('Token refreshed, retrying request...');
						await this.streamWithOAuthToken(newToken, requestBody, res, abortController.signal);
						if (!res.writableEnded) {
							res.end();
						}
						return;
					}
				} catch (refreshError) {
					this.error(`Token refresh failed: ${refreshError instanceof Error ? refreshError.message : String(refreshError)}`);
				}
			}

			// Send error as SSE event since headers are already sent
			this.error(`OAuth streaming error: ${errorMessage}`);
			if (!res.writableEnded) {
				res.write(formatSSE('error', {
					type: 'error',
					error: { type: 'api_error', message: errorMessage },
				}));
				res.end();
			}
			return;
		}

		if (!res.writableEnded) {
			res.end();
		}
	}

	/**
	 * Stream a response using the OAuth token and streaming client
	 */
	private async streamWithOAuthToken(
		accessToken: string,
		requestBody: AnthropicMessagesRequest,
		res: http.ServerResponse,
		signal: AbortSignal
	): Promise<void> {
		// Extract system prompt from request
		const systemPrompt = extractSystemPrompt(requestBody);
		this.trace(`[OAuth] System prompt length: ${systemPrompt.length}`);

		// Build thinking config based on model's reasoning effort setting
		let thinking: ThinkingConfig | undefined;
		if (requestBody.thinking) {
			const thinkingInput = requestBody.thinking as { type?: string; budget_tokens?: number };
			if (thinkingInput.type === 'enabled' && thinkingInput.budget_tokens) {
				thinking = { type: 'enabled', budget_tokens: thinkingInput.budget_tokens };
			} else if (thinkingInput.type === 'disabled') {
				thinking = { type: 'disabled' };
			}
		} else {
			// Get user's selected reasoning effort from service
			const reasoningEffort = this.claudeCodeModels.getReasoningEffort();
			if (reasoningEffort === 'disable') {
				thinking = undefined; // No thinking
			} else {
				const reasoningConfig = claudeCodeReasoningConfig[reasoningEffort];
				thinking = { type: 'enabled', budget_tokens: reasoningConfig.budgetTokens };
			}
		}
		this.info(`[OAuth] Model: ${requestBody.model}, Thinking config: ${JSON.stringify(thinking)}`);

		// Generate user_id for Claude Code API
		const email = await claudeCodeOAuthManager.getEmail();
		const userId = generateUserId(email ?? undefined);
		this.trace(`[OAuth] User ID: ${userId}, Email: ${email ?? 'none'}`);

		// Log request details
		this.info(`[OAuth] Request model: ${requestBody.model}`);
		this.info(`[OAuth] Request messages count: ${requestBody.messages?.length ?? 0}`);
		this.info(`[OAuth] Request tools count: ${requestBody.tools?.length ?? 0}`);
		this.info(`[OAuth] Request max_tokens: ${requestBody.max_tokens}`);

		// Track content block state for proper SSE formatting
		let currentBlockIndex = 0;
		let messageStartSent = false;
		// Track which block types have had their content_block_start sent
		const blockStarted: Map<number, string> = new Map(); // index -> block type

		// Use streaming client to make direct API call
		this.info('[OAuth] Starting streaming request to Anthropic API...');
		const stream = createStreamingMessage({
			accessToken,
			model: requestBody.model,
			systemPrompt,
			messages: requestBody.messages as Anthropic.Messages.MessageParam[],
			maxTokens: requestBody.max_tokens,
			thinking,
			tools: requestBody.tools as Anthropic.Messages.Tool[] | undefined,
			toolChoice: requestBody.tool_choice as Anthropic.Messages.ToolChoice | undefined,
			metadata: { user_id: userId },
			signal,
		});

		// Convert StreamChunks to Anthropic SSE events and write to response
		// Track current tool_use block index for argument deltas
		let currentToolUseIndex: number | null = null;
		// Track if we have any tool_use blocks to determine stop_reason
		let hasToolUse = false;

		for await (const chunk of stream) {
			this.trace(`[OAuth] Received chunk: ${chunk.type}${chunk.type === 'tool_call_partial' ? ` (id=${(chunk as StreamToolCallPartialChunk).id}, name=${(chunk as StreamToolCallPartialChunk).name})` : ''}`);

			// Send message_start on first chunk
			if (!messageStartSent) {
				const messageStart = formatSSE('message_start', {
					type: 'message_start',
					message: {
						id: `msg_${generateUuid()}`,
						type: 'message',
						role: 'assistant',
						content: [],
						model: requestBody.model,
						stop_reason: null,
						stop_sequence: null,
						usage: { input_tokens: 0, output_tokens: 0 },
					},
				});
				res.write(messageStart);
				messageStartSent = true;
			}

			// Handle content_block_start for new blocks
			if (chunk.type === 'text') {
				// Start text block if not already started
				if (!blockStarted.has(currentBlockIndex) || blockStarted.get(currentBlockIndex) !== 'text') {
					// Close previous block if different type
					if (blockStarted.has(currentBlockIndex)) {
						res.write(formatSSE('content_block_stop', {
							type: 'content_block_stop',
							index: currentBlockIndex,
						}));
						currentBlockIndex++;
					}
					res.write(formatSSE('content_block_start', {
						type: 'content_block_start',
						index: currentBlockIndex,
						content_block: { type: 'text', text: '' },
					}));
					blockStarted.set(currentBlockIndex, 'text');
				}
				// Send text delta
				res.write(formatSSE('content_block_delta', {
					type: 'content_block_delta',
					index: currentBlockIndex,
					delta: { type: 'text_delta', text: chunk.text },
				}));
			} else if (chunk.type === 'reasoning') {
				// Start thinking block if not already started
				if (!blockStarted.has(currentBlockIndex) || blockStarted.get(currentBlockIndex) !== 'thinking') {
					// Close previous block if different type
					if (blockStarted.has(currentBlockIndex)) {
						res.write(formatSSE('content_block_stop', {
							type: 'content_block_stop',
							index: currentBlockIndex,
						}));
						currentBlockIndex++;
					}
					res.write(formatSSE('content_block_start', {
						type: 'content_block_start',
						index: currentBlockIndex,
						content_block: { type: 'thinking', thinking: '' },
					}));
					blockStarted.set(currentBlockIndex, 'thinking');
				}
				// Send thinking delta
				res.write(formatSSE('content_block_delta', {
					type: 'content_block_delta',
					index: currentBlockIndex,
					delta: { type: 'thinking_delta', thinking: chunk.text },
				}));
			} else if (chunk.type === 'thinking_complete') {
				// Emit signature_delta before closing the thinking block
				// This is critical for interleaved thinking - the SDK needs the signature
				// to pass thinking blocks back to the API in follow-up requests
				const thinkingChunk = chunk as StreamThinkingCompleteChunk;
				if (thinkingChunk.signature) {
					res.write(formatSSE('content_block_delta', {
						type: 'content_block_delta',
						index: currentBlockIndex,
						delta: { type: 'signature_delta', signature: thinkingChunk.signature },
					}));
				}
				// Close the thinking block
				res.write(formatSSE('content_block_stop', {
					type: 'content_block_stop',
					index: currentBlockIndex,
				}));
				currentBlockIndex++;
				blockStarted.delete(currentBlockIndex - 1); // Clear the old block
			} else if (chunk.type === 'tool_call_partial') {
				const toolChunk = chunk as StreamToolCallPartialChunk;
				if (toolChunk.id && toolChunk.name) {
					// New tool_use block starting
					hasToolUse = true;
					// Close previous block if any
					if (blockStarted.has(currentBlockIndex)) {
						res.write(formatSSE('content_block_stop', {
							type: 'content_block_stop',
							index: currentBlockIndex,
						}));
						currentBlockIndex++;
					}
					// Start new tool_use block
					res.write(formatSSE('content_block_start', {
						type: 'content_block_start',
						index: currentBlockIndex,
						content_block: {
							type: 'tool_use',
							id: toolChunk.id,
							name: toolChunk.name,
							input: {},
						},
					}));
					blockStarted.set(currentBlockIndex, 'tool_use');
					currentToolUseIndex = currentBlockIndex;
				} else if (toolChunk.arguments && currentToolUseIndex !== null) {
					// Tool arguments delta - use the tool_use block index
					res.write(formatSSE('content_block_delta', {
						type: 'content_block_delta',
						index: currentToolUseIndex,
						delta: { type: 'input_json_delta', partial_json: toolChunk.arguments },
					}));
				}
			} else if (chunk.type === 'usage') {
				// Send message_delta with usage and stop_reason
				const stopReason = hasToolUse ? 'tool_use' : 'end_turn';
				res.write(formatSSE('message_delta', {
					type: 'message_delta',
					delta: { stop_reason: stopReason, stop_sequence: null },
					usage: { output_tokens: chunk.outputTokens },
				}));
			} else if (chunk.type === 'error') {
				// Send error event
				res.write(formatSSE('error', {
					type: 'error',
					error: { type: 'api_error', message: chunk.error },
				}));
			}
		}

		// Close any open blocks
		if (blockStarted.has(currentBlockIndex)) {
			res.write(formatSSE('content_block_stop', {
				type: 'content_block_stop',
				index: currentBlockIndex,
			}));
		}

		// Send message_stop
		res.write(formatSSE('message_stop', { type: 'message_stop' }));
	}

	/**
	 * Handle request via VS Code endpoint forwarding (existing behavior)
	 * @deprecated Kept for potential future use. Not called to avoid consuming GitHub/Copilot API tokens.
	 */
	// @ts-expect-error - Intentionally unused, kept for potential future use
	private async handleEndpointRequest(requestBody: AnthropicMessagesRequest, headers: http.IncomingHttpHeaders, res: http.ServerResponse): Promise<void> {
		// Create cancellation token for the request
		const tokenSource = new CancellationTokenSource();

		try {
			// Determine if this is a user-initiated message
			const lastMessage = requestBody.messages?.at(-1);
			const isUserInitiatedMessage = lastMessage?.role === 'user';

			const endpoints = await this.endpointProvider.getAllChatEndpoints();
			if (endpoints.length === 0) {
				this.error('No language models available');
				this.sendErrorResponse(res, 404, 'not_found_error', 'No language models available');
				return;
			}

			const selectedEndpoint = this.selectEndpoint(endpoints, requestBody.model);
			if (!selectedEndpoint) {
				this.error('No model found matching criteria');
				this.sendErrorResponse(res, 404, 'not_found_error', 'No model found matching criteria');
				return;
			}
			requestBody.model = selectedEndpoint.model;

			// Set up streaming response
			res.writeHead(200, {
				'Content-Type': 'text/event-stream',
				'Cache-Control': 'no-cache',
				'Connection': 'keep-alive',
			});

			// Handle client disconnect
			let requestComplete = false;
			res.on('close', () => {
				if (!requestComplete) {
					this.info('Client disconnected before request complete');
				}

				tokenSource.cancel();
			});

			const endpointRequestBody = requestBody as IEndpointBody;
			const streamingEndpoint = this.instantiationService.createInstance(
				ClaudeStreamingPassThroughEndpoint,
				selectedEndpoint,
				res,
				endpointRequestBody,
				headers,
				'vscode_claude_code',
				{
					modelMaxPromptTokens: DEFAULT_MAX_TOKENS - DEFAULT_MAX_OUTPUT_TOKENS,
					maxOutputTokens: DEFAULT_MAX_OUTPUT_TOKENS
				}
			);

			let messagesForLogging: Raw.ChatMessage[] = [];
			try {
				// Don't fail based on any assumptions about the shape of the request
				messagesForLogging = Array.isArray(requestBody.messages) ?
					messagesApiInputToRawMessagesForLogging(requestBody) :
					[];
			} catch (e) {
				this.exception(e as Error, `Failed to parse messages for logging`);
			}

			await streamingEndpoint.makeChatRequest2({
				debugName: 'claudeLMServer',
				messages: messagesForLogging,
				finishedCb: async () => undefined,
				location: ChatLocation.MessagesProxy,
				userInitiatedRequest: isUserInitiatedMessage
			}, tokenSource.token);

			requestComplete = true;

			res.end();
		} finally {
			tokenSource.dispose();
		}
	}

	private selectEndpoint(endpoints: readonly IChatEndpoint[], requestedModel?: string): IChatEndpoint | undefined {
		if (!requestedModel) {
			return undefined;
		}

		// Handle Claude model name mapping
		// e.g. claude-sonnet-4-20250514 -> claude-sonnet-4.20250514
		let mappedModel = requestedModel;
		if (requestedModel.startsWith('claude-')) {
			const parts = requestedModel.split('-');
			if (parts.length >= 4) {
				// claude-sonnet-4-20250514 -> ['claude', 'sonnet', '4', '20250514']
				const [claude, model, major, minor] = parts;
				mappedModel = `${claude}-${model}-${major}.${minor}`;
			}
		}

		// Only exact match by family or model - no fallbacks
		return endpoints.find(e => e.family === mappedModel || e.model === mappedModel);
	}

	private sendErrorResponse(
		res: http.ServerResponse,
		statusCode: number,
		errorType: AnthropicErrorResponse['error']['type'],
		message: string
	): void {
		const errorResponse: AnthropicErrorResponse = {
			type: 'error',
			error: {
				type: errorType,
				message
			}
		};
		res.writeHead(statusCode, { 'Content-Type': 'application/json' });
		res.end(JSON.stringify(errorResponse));
	}

	public async start(): Promise<void> {
		if (this.config.port !== 0) {
			// Already started
			return;
		}

		return new Promise((resolve, reject) => {
			this.server.listen(0, '127.0.0.1', () => {
				const address = this.server.address();
				if (address && typeof address === 'object') {
					this.config = {
						...this.config,
						port: address.port
					};
					this.info(`Claude Language Model Server started on http://localhost:${this.config.port}`);
					resolve();
					return;
				}

				reject(new Error('Failed to start server'));
			});
		});
	}

	public stop(): void {
		this.server.close();
	}

	public getConfig(): IClaudeLanguageModelServerConfig {
		return { ...this.config };
	}

	private info(message: string): void {
		const messageWithClassName = `[ClaudeLanguageModelServer] ${message}`;
		this.logService.info(messageWithClassName);
	}

	private error(message: string): void {
		const messageWithClassName = `[ClaudeLanguageModelServer] ${message}`;
		this.logService.error(messageWithClassName);
	}

	private exception(err: Error, message?: string): void {
		this.logService.error(err, message);
	}

	private trace(message: string): void {
		const messageWithClassName = `[ClaudeLanguageModelServer] ${message}`;
		this.logService.trace(messageWithClassName);
	}
}

/**
 * Extracts the system prompt from an Anthropic request.
 */
function extractSystemPrompt(request: AnthropicMessagesRequest): string {
	if (!request.system) {
		return '';
	}
	if (typeof request.system === 'string') {
		return request.system;
	}
	return request.system.map(block => block.text).join('\n');
}

/**
 * Formats data as an SSE event string.
 */
function formatSSE(event: string, data: unknown): string {
	return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

/**
 * Converts Anthropic Messages API input to Raw.ChatMessage[] for logging purposes.
 */
function messagesApiInputToRawMessagesForLogging(request: AnthropicMessagesRequest): Raw.ChatMessage[] {
	const messages: Raw.ChatMessage[] = [];

	// Add system message if present
	if (request.system) {
		const systemText = typeof request.system === 'string'
			? request.system
			: request.system.map(block => block.text).join('\n');
		messages.push({
			role: Raw.ChatRole.System,
			content: [{ type: Raw.ChatCompletionContentPartKind.Text, text: systemText }]
		});
	}

	// Convert each message
	for (const msg of request.messages ?? []) {
		const role = msg.role === 'user' ? Raw.ChatRole.User : Raw.ChatRole.Assistant;
		const content: Raw.ChatCompletionContentPart[] = [];

		if (typeof msg.content === 'string') {
			content.push({ type: Raw.ChatCompletionContentPartKind.Text, text: msg.content });
		} else if (Array.isArray(msg.content)) {
			for (const block of msg.content) {
				if (block.type === 'text') {
					content.push({ type: Raw.ChatCompletionContentPartKind.Text, text: block.text });
				} else if (block.type === 'image') {
					// Handle image blocks if needed for logging
					content.push({ type: Raw.ChatCompletionContentPartKind.Text, text: '[image]' });
				} else if (block.type === 'tool_use') {
					content.push({ type: Raw.ChatCompletionContentPartKind.Text, text: `[tool_use: ${block.name}]` });
				} else if (block.type === 'tool_result') {
					content.push({ type: Raw.ChatCompletionContentPartKind.Text, text: `[tool_result: ${block.tool_use_id}]` });
				}
			}
		}

		messages.push({ role, content });
	}

	return messages;
}

class ClaudeStreamingPassThroughEndpoint implements IChatEndpoint {
	constructor(
		private readonly base: IChatEndpoint,
		private readonly responseStream: http.ServerResponse,
		private readonly requestBody: IEndpointBody,
		private readonly requestHeaders: http.IncomingHttpHeaders,
		private readonly userAgentPrefix: string,
		private readonly contextWindowOverride: { modelMaxPromptTokens?: number; maxOutputTokens?: number },
		@IChatMLFetcher private readonly chatMLFetcher: IChatMLFetcher,
		@IInstantiationService private readonly instantiationService: IInstantiationService
	) { }

	public get urlOrRequestMetadata(): string | RequestMetadata {
		// Force Messages API endpoint - we need this regardless of the useMessagesApi setting
		// since we're proxying Messages API format requests from Claude Code
		const baseUrl = this.base.urlOrRequestMetadata;
		if (typeof baseUrl === 'string') {
			return baseUrl;
		}
		return { type: RequestType.ChatMessages };
	}

	public getExtraHeaders(): Record<string, string> {
		const headers = this.base.getExtraHeaders?.() ?? {};
		if (this.requestHeaders['user-agent']) {
			headers['User-Agent'] = this.getUserAgent(this.requestHeaders['user-agent']);
		}
		return headers;
	}

	getEndpointFetchOptions(): IEndpointFetchOptions {
		return {
			suppressIntegrationId: true
		};
	}

	private getUserAgent(incomingUserAgent: string): string {
		const slashIndex = incomingUserAgent.indexOf('/');
		if (slashIndex === -1) {
			return `${this.userAgentPrefix}/${incomingUserAgent}`;
		}

		return `${this.userAgentPrefix}${incomingUserAgent.substring(slashIndex)}`;
	}

	public interceptBody(body: IEndpointBody | undefined): void {
		this.base.interceptBody?.(body);
	}

	public acquireTokenizer(): ITokenizer {
		return this.base.acquireTokenizer();
	}

	public get modelMaxPromptTokens(): number {
		return this.contextWindowOverride.modelMaxPromptTokens ?? this.base.modelMaxPromptTokens;
	}

	public get maxOutputTokens(): number {
		return this.contextWindowOverride.maxOutputTokens ?? this.base.maxOutputTokens;
	}

	public get model(): string {
		return this.base.model;
	}

	public get name(): string {
		return this.base.name;
	}

	public get version(): string {
		return this.base.version;
	}

	public get family(): string {
		return this.base.family;
	}

	public get tokenizer(): TokenizerType {
		return this.base.tokenizer;
	}

	public get showInModelPicker(): boolean {
		return this.base.showInModelPicker;
	}

	public get isPremium(): boolean | undefined {
		return this.base.isPremium;
	}

	public get degradationReason(): string | undefined {
		return this.base.degradationReason;
	}

	public get multiplier(): number | undefined {
		return this.base.multiplier;
	}

	public get restrictedToSkus(): string[] | undefined {
		return this.base.restrictedToSkus;
	}

	public get isDefault(): boolean {
		return this.base.isDefault;
	}

	public get isFallback(): boolean {
		return this.base.isFallback;
	}

	public get customModel(): CustomModel | undefined {
		return this.base.customModel;
	}

	public get isExtensionContributed(): boolean | undefined {
		return this.base.isExtensionContributed;
	}

	public get apiType(): string | undefined {
		return 'messages';
	}

	public get supportsThinkingContentInHistory(): boolean | undefined {
		return this.base.supportsThinkingContentInHistory;
	}

	public get supportsToolCalls(): boolean {
		return this.base.supportsToolCalls;
	}

	public get supportsVision(): boolean {
		return this.base.supportsVision;
	}

	public get supportsPrediction(): boolean {
		return this.base.supportsPrediction;
	}

	public get supportedEditTools(): readonly EndpointEditToolName[] | undefined {
		return this.base.supportedEditTools;
	}

	public get policy(): IChatEndpoint['policy'] {
		return this.base.policy;
	}

	public async processResponseFromChatEndpoint(
		telemetryService: ITelemetryService,
		logService: ILogService,
		response: Response,
		expectedNumChoices: number,
		finishCallback: FinishedCallback,
		telemetryData: TelemetryData,
		cancellationToken?: CancellationToken
	): Promise<AsyncIterableObject<ChatCompletion>> {
		const body = response.body;
		return new AsyncIterableObject<ChatCompletion>(async feed => {
			// We parse the stream just to return a correct ChatCompletion for logging the response and token usage details.
			const requestId = response.headers.get('X-Request-ID') ?? generateUuid();
			const ghRequestId = response.headers.get('x-github-request-id') ?? '';
			const processor = this.instantiationService.createInstance(AnthropicMessagesProcessor, telemetryData, requestId, ghRequestId);
			const parser = new SSEParser((ev) => {
				try {
					const trimmed = ev.data?.trim();
					if (!trimmed || trimmed === '[DONE]') {
						return;
					}

					logService.trace(`[ClaudeStreamingPassThroughEndpoint] SSE: ${ev.data}`);
					const parsed = JSON.parse(trimmed);
					const type = parsed.type ?? ev.type;
					if (!type) {
						return;
					}
					const completion = processor.push({ ...parsed, type }, finishCallback);
					if (completion) {
						feed.emitOne(completion);
					}
				} catch (e) {
					feed.reject(e);
				}
			});

			try {
				for await (const chunk of body) {
					if (cancellationToken?.isCancellationRequested) {
						break;
					}

					this.responseStream.write(chunk);
					parser.feed(chunk);
				}
			} finally {
				await body.destroy();
			}
		});
	}

	public acceptChatPolicy(): Promise<boolean> {
		return this.base.acceptChatPolicy();
	}

	public makeChatRequest(
		debugName: string,
		messages: Raw.ChatMessage[],
		finishedCb: FinishedCallback | undefined,
		token: CancellationToken,
		location: ChatLocation,
		source?: Source,
		requestOptions?: Omit<OptionalChatRequestParams, 'n'>,
		userInitiatedRequest?: boolean
	): Promise<ChatResponse> {
		throw new Error('not implemented');
	}

	public makeChatRequest2(
		options: IMakeChatRequestOptions,
		token: CancellationToken
	): Promise<ChatResponse> {
		return this.chatMLFetcher.fetchOne({
			requestOptions: {},
			...options,
			endpoint: this,
		}, token);
	}

	public createRequestBody(
		options: ICreateEndpointBodyOptions
	): IEndpointBody {
		const base = this.base.createRequestBody(options);
		// Merge with original request body to preserve any additional properties
		// i.e. default thinking budget.
		return {
			...base,
			...this.requestBody
		};
	}

	public cloneWithTokenOverride(modelMaxPromptTokens: number): IChatEndpoint {
		throw new Error('not implemented');
	}
}
