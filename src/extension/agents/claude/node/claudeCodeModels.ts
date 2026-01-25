/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { IEndpointProvider } from '../../../../platform/endpoint/common/endpointProvider';
import { IVSCodeExtensionContext } from '../../../../platform/extContext/common/extensionContext';
import { ILogService } from '../../../../platform/log/common/logService';
import { createServiceIdentifier } from '../../../../util/common/services';
import { Lazy } from '../../../../util/vs/base/common/lazy';
import { claudeCodeModels, claudeCodeReasoningConfig, ClaudeCodeModelId, ClaudeCodeReasoningLevel } from './claude-code';
import { claudeCodeOAuthManager } from './oauth';

const CLAUDE_CODE_MODEL_MEMENTO_KEY = 'github.copilot.claudeCode.sessionModel';
const CLAUDE_CODE_REASONING_EFFORT_KEY = 'github.copilot.claudeCode.reasoningEffort';

export interface ClaudeCodeModelInfo {
	id: string;
	name: string;
	multiplier?: number;
}

export interface IClaudeCodeModels {
	readonly _serviceBrand: undefined;
	resolveModel(modelId: string): Promise<string | undefined>;
	getDefaultModel(): Promise<string | undefined>;
	setDefaultModel(modelId: string | undefined): Promise<void>;
	getModels(): Promise<ClaudeCodeModelInfo[]>;
	getReasoningEffort(): ClaudeCodeReasoningLevel;
	setReasoningEffort(level: ClaudeCodeReasoningLevel): Promise<void>;
	getReasoningEffortOptions(): { id: ClaudeCodeReasoningLevel; name: string; description: string }[];
}

export const IClaudeCodeModels = createServiceIdentifier<IClaudeCodeModels>('IClaudeCodeModels');

export class ClaudeCodeModels implements IClaudeCodeModels {
	declare _serviceBrand: undefined;
	private readonly _availableModels: Lazy<Promise<ClaudeCodeModelInfo[]>>;

	constructor(
		@IEndpointProvider private readonly endpointProvider: IEndpointProvider,
		@IVSCodeExtensionContext private readonly extensionContext: IVSCodeExtensionContext,
		@ILogService private readonly logService: ILogService,
	) {
		this._availableModels = new Lazy<Promise<ClaudeCodeModelInfo[]>>(() => this._getAvailableModels());
	}

	async resolveModel(modelId: string): Promise<string | undefined> {
		const models = await this.getModels();
		const normalizedId = modelId.trim().toLowerCase();
		return models.find(m => m.id.toLowerCase() === normalizedId || m.name.toLowerCase() === normalizedId)?.id;
	}

	public async getDefaultModel(): Promise<string | undefined> {
		const models = await this.getModels();
		if (!models.length) {
			return undefined;
		}

		// Get preferred model from stored preference
		const preferredModelId = this.extensionContext.globalState.get<string>(CLAUDE_CODE_MODEL_MEMENTO_KEY)?.trim()?.toLowerCase();

		if (preferredModelId) {
			const matchedModel = models.find(m => m.id.toLowerCase() === preferredModelId);
			if (matchedModel) {
				return matchedModel.id;
			}
		}

		// Return the latest Sonnet as the default model
		const defaultModel = models.find(m => m.id.toLowerCase().includes('sonnet') || m.name.toLowerCase().includes('sonnet'));
		return defaultModel?.id ?? models[0]?.id;
	}

	public async setDefaultModel(modelId: string | undefined): Promise<void> {
		await this.extensionContext.globalState.update(CLAUDE_CODE_MODEL_MEMENTO_KEY, modelId);
	}

	public getReasoningEffort(): ClaudeCodeReasoningLevel {
		const stored = this.extensionContext.globalState.get<string>(CLAUDE_CODE_REASONING_EFFORT_KEY);
		if (stored === 'disable' || (stored && stored in claudeCodeReasoningConfig)) {
			return stored as ClaudeCodeReasoningLevel;
		}
		return 'high'; // Default to high
	}

	public async setReasoningEffort(level: ClaudeCodeReasoningLevel): Promise<void> {
		await this.extensionContext.globalState.update(CLAUDE_CODE_REASONING_EFFORT_KEY, level);
	}

	public getReasoningEffortOptions(): { id: ClaudeCodeReasoningLevel; name: string; description: string }[] {
		return [
			{ id: 'disable', name: 'Disable', description: 'No thinking' },
			{ id: 'low', name: 'Low', description: `${claudeCodeReasoningConfig.low.budgetTokens.toLocaleString()} tokens` },
			{ id: 'medium', name: 'Medium', description: `${claudeCodeReasoningConfig.medium.budgetTokens.toLocaleString()} tokens` },
			{ id: 'high', name: 'High', description: `${claudeCodeReasoningConfig.high.budgetTokens.toLocaleString()} tokens` },
		];
	}

	public async getModels(): Promise<ClaudeCodeModelInfo[]> {
		// Check if OAuth is authenticated - if so, return Claude Code subscription models
		const isOAuthAuthenticated = await claudeCodeOAuthManager.isAuthenticated();
		if (isOAuthAuthenticated) {
			this.logService.trace('[ClaudeCodeModels] OAuth authenticated, returning Claude Code subscription models');
			return this._getClaudeCodeSubscriptionModels();
		}

		// Fall back to endpoint-provided models
		return this._availableModels.value;
	}

	/**
	 * Returns the Claude Code subscription models (Haiku, Sonnet, Opus).
	 * These are the models available with a Claude Code subscription via OAuth.
	 */
	private _getClaudeCodeSubscriptionModels(): ClaudeCodeModelInfo[] {
		const modelIds = Object.keys(claudeCodeModels) as ClaudeCodeModelId[];
		return modelIds.map(id => {
			const model = claudeCodeModels[id];
			return {
				id,
				name: model.description,
				multiplier: undefined, // Claude Code subscription has flat pricing
			};
		});
	}

	private async _getAvailableModels(): Promise<ClaudeCodeModelInfo[]> {
		try {
			const endpoints = await this.endpointProvider.getAllChatEndpoints();

			// Filter for Claude/Anthropic models that are available in the model picker
			const claudeEndpoints = endpoints.filter(e =>
				e.showInModelPicker &&
				(e.family?.toLowerCase().includes('claude') || e.model?.toLowerCase().includes('claude'))
			);

			if (claudeEndpoints.length === 0) {
				this.logService.trace('[ClaudeCodeModels] No Claude models found, returning all available models');
				// Fall back to all available models if no Claude-specific ones
				return endpoints
					.filter(e => e.showInModelPicker)
					.map(e => ({ id: e.model, name: e.name, multiplier: e.multiplier }));
			}

			// Filter to only include the latest version of each model family
			// Parse version from family string (e.g., "claude-opus-4.5" or "claude-opus-41")
			const familyMap = new Map<string, { endpoint: typeof claudeEndpoints[0]; version: number }>();

			for (const endpoint of claudeEndpoints) {
				const parsed = this._parseFamilyString(endpoint.family);
				if (!parsed) {
					// Can't parse, include as-is using full family as key
					familyMap.set(endpoint.family, { endpoint, version: 0 });
					continue;
				}

				const existing = familyMap.get(parsed.modelFamily);
				if (!existing || parsed.version > existing.version) {
					familyMap.set(parsed.modelFamily, { endpoint, version: parsed.version });
				}
			}

			return Array.from(familyMap.values()).map(v => ({ id: v.endpoint.model, name: v.endpoint.name, multiplier: v.endpoint.multiplier }));
		} catch (ex) {
			this.logService.error(`[ClaudeCodeModels] Failed to fetch models`, ex);
			return [];
		}
	}

	/**
	 * Parses a Claude family string to extract the model family and version.
	 * Examples:
	 * - "claude-haiku-4.5" -> { modelFamily: "haiku", version: 4.5 }
	 * - "claude-opus-41" -> { modelFamily: "opus", version: 4.1 }
	 * - "claude-opus-4.5" -> { modelFamily: "opus", version: 4.5 }
	 * - "claude-sonnet-35" -> { modelFamily: "sonnet", version: 3.5 }
	 */
	private _parseFamilyString(family: string): { modelFamily: string; version: number } | undefined {
		const lower = family.toLowerCase();

		// Match pattern: claude-{model}-{version} where version is digits with optional decimal
		const match = lower.match(/^claude-(\w+)-(\d+\.?\d*)$/);
		if (!match) {
			return undefined;
		}

		const modelFamily = match[1];
		let versionStr = match[2];

		// Handle versions like "41" -> 4.1, "35" -> 3.5 (two-digit without decimal)
		if (!versionStr.includes('.') && versionStr.length === 2) {
			versionStr = versionStr[0] + '.' + versionStr[1];
		}

		const version = parseFloat(versionStr) || 0;
		return { modelFamily, version };
	}
}
